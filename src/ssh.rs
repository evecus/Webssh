//! SSH 隧道层 —— 与 Go 版 `internal/ssh/ssh.go` 逻辑一一对应。
//!
//! - 目标主机白名单（逗号分隔，支持 filepath.Match 风格通配符）
//! - TOFU（Trust On First Use）主机密钥校验，指纹变化拒绝连接（防 MITM）
//! - known_hosts 读写、RemoveKnownHost
//! - 密码 / 私钥（可带口令）认证、xterm-256color PTY、交互式 shell
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use russh::client::{self, Handle, Msg};
use russh::keys::{decode_secret_key, PrivateKeyWithHashAlg, PublicKeyOrCertificate};
use russh::{ChannelReadHalf, ChannelWriteHalf, Pty};
use tokio::time::timeout;

use crate::store;

/// 对应 Go 版 `var AllowedHosts []string`，由 main 在启动时注入（空代表不限制）。
pub static ALLOWED_HOSTS: OnceLock<Vec<String>> = OnceLock::new();

/// 对应 Go 版 `const knownHostsFile = "data/known_hosts"`。
const KNOWN_HOSTS_FILE: &str = "data/known_hosts";

/// 对应 Go 版 `var khMu sync.Mutex`。
static KH_MU: Mutex<()> = Mutex::new(());

// ---- 白名单（对应 filepath.Match 语义）----

/// 对应 Go 版 `isHostAllowed()`。
fn is_host_allowed(host: &str) -> bool {
    let list = ALLOWED_HOSTS.get().cloned().unwrap_or_default();
    if list.is_empty() {
        return true;
    }
    for pattern in &list {
        if glob_match(pattern, host) || pattern == host {
            return true;
        }
    }
    false
}

/// Go 标准库 `filepath.Match` 的等价实现：`*` / `?` / `[...]` / `\` 转义，
/// 且 `*` 与 `?` 不跨越 `/`。pattern 非法时返回 false（Go 里忽略 ErrBadPattern）。
fn glob_match(pattern: &str, name: &str) -> bool {
    fn m(p: &[char], s: &[char]) -> bool {
        if p.is_empty() {
            return s.is_empty();
        }
        match p[0] {
            '*' => {
                let mut i = 0;
                loop {
                    if m(&p[1..], &s[i..]) {
                        return true;
                    }
                    if i >= s.len() || s[i] == '/' {
                        return false;
                    }
                    i += 1;
                }
            }
            '?' => !s.is_empty() && s[0] != '/' && m(&p[1..], &s[1..]),
            '[' => {
                if s.is_empty() || s[0] == '/' {
                    return false;
                }
                let mut end = 1;
                if end < p.len() && (p[end] == '!' || p[end] == '^') {
                    end += 1;
                }
                if end < p.len() && p[end] == ']' {
                    end += 1;
                }
                while end < p.len() && p[end] != ']' {
                    end += 1;
                }
                if end >= p.len() {
                    return false; // ErrBadPattern
                }
                let negate = p[1] == '!' || p[1] == '^';
                let start = if negate { 2 } else { 1 };
                let mut matched = false;
                let mut i = start;
                while i < end {
                    if i + 2 < end && p[i + 1] == '-' {
                        if p[i] <= s[0] && s[0] <= p[i + 2] {
                            matched = true;
                        }
                        i += 3;
                    } else {
                        if p[i] == s[0] {
                            matched = true;
                        }
                        i += 1;
                    }
                }
                if matched == negate {
                    return false;
                }
                m(&p[end + 1..], &s[1..])
            }
            '\\' => {
                p.len() > 1 && !s.is_empty() && p[1] == s[0] && m(&p[2..], &s[1..])
            }
            c => !s.is_empty() && c == s[0] && m(&p[1..], &s[1..]),
        }
    }
    let p: Vec<char> = pattern.chars().collect();
    let s: Vec<char> = name.chars().collect();
    m(&p, &s)
}

// ---- known_hosts / TOFU ----

/// 对应 Go 版 `ensureKnownHostsFile()`：MkdirAll(0750) + 0600 创建文件。
fn ensure_known_hosts_file() -> io::Result<()> {
    store::ensure_data_dir()?;
    OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(KNOWN_HOSTS_FILE)?;
    Ok(())
}

/// 对应 Go `knownhosts` 的 normalize：22 端口省略，其余写成 `[host]:port`。
fn normalize_host(host: &str, port: i32) -> String {
    if port == 22 {
        host.to_string()
    } else {
        format!("[{}]:{}", host, port)
    }
}

fn host_field_matches(host: &str, field: &str) -> bool {
    // 与 Go knownhosts.matchHostnames 一致：先精确相等，再通配符匹配
    //（否则 "[host]:port" 中的 '[' 会被 glob 当作字符类，导致非 22 端口永远匹配不上）
    for entry in field.split(',') {
        if entry.starts_with("|1|") {
            continue; // hashed 条目：Go 支持，此处按未知处理
        }
        if entry == host || glob_match(entry, host) {
            return true;
        }
    }
    false
}

/// hostname 形如 "host:port"（与 Go 回调参数一致），取出端口。
fn host_port(hostname: &str) -> i32 {
    match hostname.rsplit_once(':') {
        Some((_, p)) => p.parse::<i32>().unwrap_or(22),
        None => 22,
    }
}

fn host_only(hostname: &str) -> &str {
    match hostname.rsplit_once(':') {
        Some((h, _)) => h,
        None => hostname,
    }
}

/// 对应 Go 版 `tofuHostKeyCallback()`：
/// 已知且匹配 → 放行；未见过 → 追加记录（TOFU）；见过但不匹配 → 拒绝（MITM）。
fn tofu_host_key_check(
    hostname: &str,
    key: &PublicKeyOrCertificate,
) -> Result<(), String> {
    let _guard = KH_MU.lock().unwrap();
    if let Err(e) = ensure_known_hosts_file() {
        return Err(format!("failed to ensure known_hosts: {}", e));
    }

    let host = host_only(hostname);
    let port = host_port(hostname);
    let pubkey = key.public_key();
    let key_type = pubkey.algorithm().as_str().to_string();
    let blob = pubkey.to_bytes().map_err(|e| e.to_string())?;
    let b64 = B64.encode(&blob);
    let normalized = normalize_host(host, port);

    let data = fs::read_to_string(KNOWN_HOSTS_FILE)
        .map_err(|e| format!("failed to read known_hosts: {}", e))?;

    let mut found = false;
    for line in data.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let fields: Vec<&str> = trimmed.split_whitespace().collect();
        if fields.len() < 3 {
            continue;
        }
        if host_field_matches(&normalized, fields[0]) {
            found = true;
            if fields[1] == key_type && fields[2] == b64 {
                return Ok(()); // 已知且匹配
            }
        }
    }

    if !found {
        // 首次连接 —— 追加记录（对应 knownhosts.Line + Fprintln）
        let line = format!("{} {} {}\n", normalized, key_type, b64);
        let mut f = OpenOptions::new()
            .append(true)
            .open(KNOWN_HOSTS_FILE)
            .map_err(|e| format!("failed to write known_hosts: {}", e))?;
        f.write_all(line.as_bytes())
            .map_err(|e| format!("failed to append known_hosts: {}", e))?;
        return Ok(());
    }

    // 指纹不匹配 —— 拒绝（可能是 MITM）；前端依赖 "host key mismatch" 触发信任弹窗
    Err(format!(
        "SSH host key mismatch for {}: possible MITM attack. \
         If the host key legitimately changed, remove its entry from data/known_hosts",
        hostname
    ))
}

/// 对应 Go 版 `RemoveKnownHost()`：从 known_hosts 中移除指定 hostname 的所有条目。
pub fn remove_known_host(hostname: &str) -> Result<(), String> {
    let _guard = KH_MU.lock().unwrap();
    ensure_known_hosts_file().map_err(|e| format!("failed to ensure known_hosts: {}", e))?;
    let data = fs::read_to_string(KNOWN_HOSTS_FILE)
        .map_err(|e| format!("failed to read known_hosts: {}", e))?;

    let mut kept: Vec<&str> = Vec::new();
    for line in data.split('\n') {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            kept.push(line);
            continue;
        }
        let fields: Vec<&str> = trimmed.split_whitespace().collect();
        if fields.is_empty() {
            kept.push(line);
            continue;
        }
        let hosts: Vec<&str> = fields[0].split(',').collect();
        if !hosts.contains(&hostname) {
            kept.push(line);
        }
    }

    let mut new_content = kept.join("\n");
    new_content = new_content.trim_end_matches('\n').to_string() + "\n";
    let mut f = OpenOptions::new()
        .write(true)
        .truncate(true)
        .create(true)
        .mode(0o600)
        .open(KNOWN_HOSTS_FILE)
        .map_err(|e| e.to_string())?;
    f.write_all(new_content.as_bytes())
        .map_err(|e| e.to_string())?;
    Ok(())
}

// ---- SSH 连接 ----

#[derive(Clone)]
pub struct Config {
    pub host: String,
    pub port: i32,
    pub username: String,
    pub password: String,
    pub private_key: String,
    pub passphrase: String,
}

/// russh 客户端事件处理器：仅实现主机密钥校验（TOFU）。
pub struct ClientHandler {
    /// 与 Go 回调收到的 hostname 一致："host:port"
    hostname: String,
    /// 用于在握手失败时把自定义拒绝原因传回调用方
    host_key_error: Arc<Mutex<Option<String>>>,
}

impl client::Handler for ClientHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        key: &PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        match tofu_host_key_check(&self.hostname, key) {
            Ok(()) => Ok(true),
            Err(msg) => {
                *self.host_key_error.lock().unwrap() = Some(msg);
                Ok(false)
            }
        }
    }
}

/// 对应 Go 版 `Session`（client + session + stdin + stdout + stderr）。
/// 用 russh 的 ChannelReadHalf / ChannelWriteHalf 实现读写分离。
pub struct Session {
    handle: Handle<ClientHandler>,
    read: ChannelReadHalf,
    write: ChannelWriteHalf<Msg>,
}

/// 对应 Go 版 `Connect()`。
pub async fn connect(cfg: Config) -> Result<Session, String> {
    // 白名单检查（防止服务器被用作跳板/SSRF）
    if !is_host_allowed(&cfg.host) {
        return Err(format!(
            "host {:?} is not in the allowed hosts list",
            cfg.host
        ));
    }

    // 私钥优先，密码次之；与 Go 的 authMethods 顺序一致
    let private_key = if !cfg.private_key.is_empty() {
        let passphrase = if cfg.passphrase.is_empty() {
            None
        } else {
            Some(cfg.passphrase.as_str())
        };
        Some(
            decode_secret_key(&cfg.private_key, passphrase)
                .map_err(|e| format!("failed to parse private key: {}", e))?,
        )
    } else {
        None
    };

    if private_key.is_none() && cfg.password.is_empty() {
        return Err("no authentication method provided".to_string());
    }

    let host_key_error = Arc::new(Mutex::new(None::<String>));
    let handler = ClientHandler {
        hostname: format!("{}:{}", cfg.host, cfg.port),
        host_key_error: host_key_error.clone(),
    };
    let ssh_config = Arc::new(client::Config::default());
    let addr = format!("{}:{}", cfg.host, cfg.port);

    // Go: ClientConfig.Timeout = 15 * time.Second
    let mut handle = match timeout(
        Duration::from_secs(15),
        client::connect(ssh_config, addr.as_str(), handler),
    )
    .await
    {
        Ok(Ok(h)) => h,
        Ok(Err(e)) => {
            let custom = host_key_error.lock().unwrap().clone();
            return Err(custom.unwrap_or_else(|| format!("failed to connect: {}", e)));
        }
        Err(_) => return Err("failed to connect: dial tcp: i/o timeout".to_string()),
    };

    // 认证：按 Go 版 authMethods 顺序尝试，任一成功即可
    let mut authed = false;
    if let Some(key) = private_key {
        let hash_alg = handle.best_supported_rsa_hash().await.ok().flatten().flatten();
        if let Ok(res) = handle
            .authenticate_publickey(
                cfg.username.clone(),
                PrivateKeyWithHashAlg::new(Arc::new(key), hash_alg),
            )
            .await
        {
            authed = res.success();
        }
    }
    if !authed && !cfg.password.is_empty() {
        if let Ok(res) = handle
            .authenticate_password(cfg.username.clone(), cfg.password.clone())
            .await
        {
            authed = res.success();
        }
    }
    if !authed {
        return Err(
            "failed to connect: ssh: handshake failed: ssh: unable to authenticate, \
             attempted methods [none publickey password], no supported methods remain"
                .to_string(),
        );
    }

    let channel = handle
        .channel_open_session()
        .await
        .map_err(|e| format!("failed to create session: {}", e))?;

    // Go: TerminalModes{ECHO:1, TTY_OP_ISPEED:14400, TTY_OP_OSPEED:14400}
    let modes = [
        (Pty::ECHO, 1),
        (Pty::TTY_OP_ISPEED, 14400),
        (Pty::TTY_OP_OSPEED, 14400),
    ];
    // Go: RequestPty("xterm-256color", 40, 120, modes) → h=40, w=120
    channel
        .request_pty(true, "xterm-256color", 120, 40, 0, 0, &modes)
        .await
        .map_err(|e| format!("failed to request pty: {}", e))?;
    channel
        .request_shell(true)
        .await
        .map_err(|e| format!("failed to start shell: {}", e))?;

    let (read, write) = channel.split();
    Ok(Session { handle, read, write })
}

impl Session {
    /// 拆分为读端、写端与连接句柄，供 WebSocket 主循环并发读写
    /// （对应 Go 版 stdin / stdout / stderr 与 client 的分离）。
    pub fn into_parts(
        self,
    ) -> (
        ChannelReadHalf,
        ChannelWriteHalf<Msg>,
        Handle<ClientHandler>,
    ) {
        (self.read, self.write, self.handle)
    }
}

/// 对应 Go 版 `Ping()`（原版定义但未被调用，保留以保持逻辑一致）。
#[allow(dead_code)]
pub async fn ping(host: &str, port: i32) -> Result<(), String> {
    if !is_host_allowed(host) {
        return Err(format!("host {:?} is not allowed", host));
    }
    let addr = format!("{}:{}", host, port);
    match timeout(Duration::from_secs(5), tokio::net::TcpStream::connect(addr)).await {
        Ok(Ok(_conn)) => Ok(()),
        Ok(Err(e)) => Err(e.to_string()),
        Err(_) => Err("dial timeout".to_string()),
    }
}
