//! 数据持久化层 —— 与 Go 版 `internal/store/store.go` 逻辑一一对应。
//!
//! - `data/` 目录、AES-256-GCM 加密（密钥 `secret.key`，密文前缀 `enc:`）保持不变
//! - 持久化改用 redb 单文件 `data/webssh.redb`（0600）：**不再产出任何 JSON 文件**
//! - auth / settings / sessions / ssh profiles 的读写由 redb ACID 事务保护，
//!   取代 Go 版 `mu sync.RWMutex` + `os.WriteFile` 的文件级并发保护
//! - 所有落库数据均用 redb 原生类型，序列化过程不经过 JSON
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::sync::{Mutex, OnceLock, RwLock};

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use chrono::Local;
use rand::{RngCore, TryRngCore};
use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// 对应 Go 版 `const DataDir = "data"`。
pub const DATA_DIR: &str = "data";

/// 对应 Go 版 `setupMu sync.Mutex`（防止 setup 阶段并发初始化账户）。
static SETUP_LOCK: Mutex<()> = Mutex::new(());
/// 对应 Go 版包级 `var encryptionKey []byte`。
static ENCRYPTION_KEY: RwLock<Option<[u8; 32]>> = RwLock::new(None);

/// redb 数据库全局单例。文件在首次访问时创建（0600），之后一直复用。
/// 用 `Result` 作为 OnceLock 的值，使初始化失败可被后续调用感知。
static DB: OnceLock<Result<Database, String>> = OnceLock::new();

// ---- redb 表定义（全部使用原生类型，持久化过程中不出现 JSON）----

/// auth 表：单条账户，"username" / "password_hash" 两个键。
const AUTH: TableDefinition<&str, &str> = TableDefinition::new("auth");
/// settings 表：键为字段名，值统一为字符串（font_size 存十进制）。
const SETTINGS: TableDefinition<&str, &str> = TableDefinition::new("settings");
/// sessions 表：token -> (username, expires_at RFC3339)，字段与 Go 版 sessions.json 一致。
const SESSIONS: TableDefinition<&str, (&str, &str)> = TableDefinition::new("sessions");
/// profiles 表：id -> (name, host, port, username, password, private_key,
/// passphrase, auth_type, created_at)。敏感字段仍是 `enc:` 密文。
const PROFILES: TableDefinition<
    &str,
    (&str, &str, i32, &str, &str, &str, &str, &str, &str),
> = TableDefinition::new("profiles");
/// 插入顺序表：序号 -> id。redb 按 key 排序，需显式保序以对齐 Go 版 slice 顺序。
const PROFILE_ORDER: TableDefinition<u64, &str> = TableDefinition::new("profile_order");

fn file_path(name: &str) -> String {
    format!("{}/{}", DATA_DIR, name)
}

/// 对应 Go 版 `EnsureDataDir()`：`os.MkdirAll(DataDir, 0750)`。
pub fn ensure_data_dir() -> io::Result<()> {
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o750)
        .create(DATA_DIR)
}

/// 打开（或首次创建）redb 数据库。文件权限 0600，涵盖账户哈希、会话与加密凭证。
fn db() -> Result<&'static Database, String> {
    DB.get_or_init(|| {
        ensure_data_dir().map_err(|e| e.to_string())?;
        let path = file_path("webssh.redb");
        let f = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(&path)
            .map_err(|e| e.to_string())?;
        // 已存在的库若权限被改松，启动时收紧回 0600
        let _ = fs::set_permissions(&path, fs::Permissions::from_mode(0o600));
        let backend = redb::backends::FileBackend::new(f).map_err(|e| e.to_string())?;
        Database::builder()
            .create_with_backend(backend)
            .map_err(|e| e.to_string())
    })
    .as_ref()
    .map_err(|e| e.clone())
}

/// 对应 Go 版 `os.WriteFile(path, data, perm)`：仅新建文件时应用权限。
/// 现在只用于 `secret.key`（它不是 JSON，保持与 Go 版一致的独立密钥文件）。
fn write_file_mode(path: &str, data: &[u8], mode: u32) -> io::Result<()> {
    let mut f = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(mode)
        .open(path)?;
    f.write_all(data)
}

/// 对应 Go 版 `LoadOrCreateEncryptionKey()`。
pub fn load_or_create_encryption_key() -> io::Result<()> {
    let key_path = file_path("secret.key");
    if let Ok(data) = fs::read(&key_path) {
        if data.len() == 64 {
            let decoded = std::str::from_utf8(&data)
                .ok()
                .and_then(|s| hex::decode(s).ok());
            if let Some(key) = decoded.filter(|k| k.len() == 32) {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&key);
                *ENCRYPTION_KEY.write().unwrap() = Some(arr);
                return Ok(());
            }
        }
    }

    let mut key = [0u8; 32];
    rand::rng().fill_bytes(&mut key);
    let encoded = hex::encode(key);
    ensure_data_dir()?;
    write_file_mode(&key_path, encoded.as_bytes(), 0o600)?;
    *ENCRYPTION_KEY.write().unwrap() = Some(key);
    Ok(())
}

/// 对应 Go 版 `encrypt()`：随机 12 字节 nonce + AES-GCM → `enc:` + hex(nonce||ct)。
fn encrypt(plaintext: &str) -> Result<String, String> {
    if plaintext.is_empty() {
        return Ok(plaintext.to_string());
    }
    let key = match *ENCRYPTION_KEY.read().unwrap() {
        Some(k) => k,
        None => return Ok(plaintext.to_string()), // Go: encryptionKey == nil 时原文返回
    };
    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|e| e.to_string())?;
    let mut nonce_bytes = [0u8; 12];
    rand::rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_bytes())
        .map_err(|e| e.to_string())?;
    let mut out = nonce_bytes.to_vec();
    out.extend_from_slice(&ciphertext);
    Ok(format!("enc:{}", hex::encode(out)))
}

/// 对应 Go 版 `decrypt()`：无 `enc:` 前缀则原样返回。
fn decrypt(ciphertext: &str) -> Result<String, String> {
    const PREFIX: &str = "enc:";
    if !ciphertext.starts_with(PREFIX) {
        return Ok(ciphertext.to_string());
    }
    let key = match *ENCRYPTION_KEY.read().unwrap() {
        Some(k) => k,
        None => return Err("encryption key not loaded".to_string()),
    };
    let data = hex::decode(&ciphertext[PREFIX.len()..]).map_err(|e| e.to_string())?;
    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|e| e.to_string())?;
    let nonce_size = 12;
    if data.len() < nonce_size {
        return Err("ciphertext too short".to_string());
    }
    let nonce = Nonce::from_slice(&data[..nonce_size]);
    let plaintext = cipher
        .decrypt(nonce, &data[nonce_size..])
        .map_err(|e| e.to_string())?;
    Ok(String::from_utf8_lossy(&plaintext).into_owned())
}

/// 对应 Go 版 `generateID()`：时间前缀 + 8 随机字节 hex，失败时回退到 sha256(时间串)。
fn generate_id() -> String {
    let now = Local::now().format("%Y%m%d%H%M%S").to_string();
    let mut b = [0u8; 8];
    if rand::rng().try_fill_bytes(&mut b).is_ok() {
        format!("{}{}", now, hex::encode(b))
    } else {
        let h = Sha256::digest(Local::now().to_string().as_bytes());
        format!("{}{}", now, hex::encode(&h[..8]))
    }
}

// ---- 数据结构（字段名与 Go 版一致）----

pub struct AuthData {
    pub username: String,
    pub password_hash: String,
}

#[derive(Deserialize, Clone, Default)]
pub struct SSHProfile {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub host: String,
    #[serde(default)]
    pub port: i32,
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub password: String,
    #[serde(default)]
    pub private_key: String,
    #[serde(default)]
    pub passphrase: String,
    #[serde(default)]
    pub auth_type: String,
    #[serde(default)]
    pub created_at: String,
}

/// 对应 Go 版 `SSHProfileSafe`（对外 API 安全视图，不含明文凭证）。
#[derive(Serialize, Clone)]
pub struct SSHProfileSafe {
    pub id: String,
    pub name: String,
    pub host: String,
    pub port: i32,
    pub username: String,
    pub auth_type: String,
    pub has_password: bool,
    pub has_key: bool,
    pub has_passphrase: bool,
    pub created_at: String,
}

impl SSHProfile {
    /// 对应 Go 版 `ToSafe()`。
    pub fn to_safe(&self) -> SSHProfileSafe {
        SSHProfileSafe {
            id: self.id.clone(),
            name: self.name.clone(),
            host: self.host.clone(),
            port: self.port,
            username: self.username.clone(),
            auth_type: self.auth_type.clone(),
            has_password: !self.password.is_empty(),
            has_key: !self.private_key.is_empty(),
            has_passphrase: !self.passphrase.is_empty(),
            created_at: self.created_at.clone(),
        }
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Settings {
    #[serde(default)]
    pub theme: String,
    #[serde(default)]
    pub ui_font: String,
    #[serde(default)]
    pub term_font: String,
    #[serde(default)]
    pub term_bg: String,
    #[serde(default)]
    pub font_size: i32,
    #[serde(default)]
    pub lang: String,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            theme: "purple-pink".to_string(),
            ui_font: "'Outfit','Noto Sans SC',sans-serif".to_string(),
            term_font: "'JetBrains Mono',monospace".to_string(),
            term_bg: "dark".to_string(),
            font_size: 14,
            lang: "zh".to_string(),
        }
    }
}

// ---- Auth ----

pub fn load_auth() -> io::Result<AuthData> {
    let d = db().map_err(io::Error::other)?;
    let txn = d.begin_read().map_err(|e| io::Error::other(e.to_string()))?;
    let table = txn
        .open_table(AUTH)
        .map_err(|e| io::Error::other(e.to_string()))?;
    let username = table
        .get("username")
        .map_err(|e| io::Error::other(e.to_string()))?
        .ok_or_else(|| io::Error::other("auth not initialized"))?
        .value()
        .to_string();
    let password_hash = table
        .get("password_hash")
        .map_err(|e| io::Error::other(e.to_string()))?
        .ok_or_else(|| io::Error::other("auth not initialized"))?
        .value()
        .to_string();
    Ok(AuthData {
        username,
        password_hash,
    })
}

/// 对应 Go 版 `SaveAuth()`：加 setup 锁后再次检查，返回 "auth already initialized"。
/// 「检查 + 写入」在同一个 redb 写事务内完成，天然原子。
pub fn save_auth(a: &AuthData) -> Result<(), String> {
    let _guard = SETUP_LOCK.lock().unwrap();
    let d = db()?;
    let txn = d.begin_write().map_err(|e| e.to_string())?;
    {
        let mut table = txn.open_table(AUTH).map_err(|e| e.to_string())?;
        if table.get("username").map_err(|e| e.to_string())?.is_some() {
            return Err("auth already initialized".to_string());
        }
        table
            .insert("username", a.username.as_str())
            .map_err(|e| e.to_string())?;
        table
            .insert("password_hash", a.password_hash.as_str())
            .map_err(|e| e.to_string())?;
    }
    txn.commit().map_err(|e| e.to_string())?;
    Ok(())
}

pub fn auth_exists() -> bool {
    let Ok(d) = db() else { return false };
    let Ok(txn) = d.begin_read() else { return false };
    let Ok(table) = txn.open_table(AUTH) else {
        return false;
    };
    matches!(table.get("username"), Ok(Some(_)))
}

// ---- Settings ----

/// 对应 Go 版 `LoadSettings()`：读失败返回默认值，并修补两个零值字段。
pub fn load_settings() -> Settings {
    let Ok(d) = db() else {
        return Settings::default();
    };
    let Ok(txn) = d.begin_read() else {
        return Settings::default();
    };
    // 表不存在（从未写入）→ 默认值，对齐 Go 版 settings.json 缺失的情况
    let Ok(table) = txn.open_table(SETTINGS) else {
        return Settings::default();
    };
    let get = |key: &str| -> String {
        table
            .get(key)
            .ok()
            .flatten()
            .map(|v| v.value().to_string())
            .unwrap_or_default()
    };
    let mut s = Settings {
        theme: get("theme"),
        ui_font: get("ui_font"),
        term_font: get("term_font"),
        term_bg: get("term_bg"),
        font_size: get("font_size").parse::<i32>().unwrap_or(0),
        lang: get("lang"),
    };
    if s.term_bg.is_empty() {
        s.term_bg = "dark".to_string();
    }
    if s.font_size == 0 {
        s.font_size = 14;
    }
    s
}

pub fn save_settings(s: &Settings) -> io::Result<()> {
    let d = db().map_err(io::Error::other)?;
    let txn = d
        .begin_write()
        .map_err(|e| io::Error::other(e.to_string()))?;
    let font_size = s.font_size.to_string();
    {
        let mut table = txn
            .open_table(SETTINGS)
            .map_err(|e| io::Error::other(e.to_string()))?;
        table
            .insert("theme", s.theme.as_str())
            .map_err(|e| io::Error::other(e.to_string()))?;
        table
            .insert("ui_font", s.ui_font.as_str())
            .map_err(|e| io::Error::other(e.to_string()))?;
        table
            .insert("term_font", s.term_font.as_str())
            .map_err(|e| io::Error::other(e.to_string()))?;
        table
            .insert("term_bg", s.term_bg.as_str())
            .map_err(|e| io::Error::other(e.to_string()))?;
        table
            .insert("font_size", font_size.as_str())
            .map_err(|e| io::Error::other(e.to_string()))?;
        table
            .insert("lang", s.lang.as_str())
            .map_err(|e| io::Error::other(e.to_string()))?;
    }
    txn.commit()
        .map_err(|e| io::Error::other(e.to_string()))?;
    Ok(())
}

// ---- Sessions（对应 Go 版 sessions.json，现落在 redb）----

/// 对应 Go 版 `loadSessionsFromDisk()` 的读取部分：返回 (token, username, expires_at RFC3339)。
/// 过期过滤仍由 handler 完成（与 Go 版一致）。
pub fn load_sessions() -> Vec<(String, String, String)> {
    let Ok(d) = db() else { return Vec::new() };
    let Ok(txn) = d.begin_read() else {
        return Vec::new();
    };
    let Ok(table) = txn.open_table(SESSIONS) else {
        return Vec::new();
    };
    let Ok(iter) = table.iter() else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for entry in iter {
        let Ok((k, v)) = entry else { continue };
        let t = v.value();
        out.push((k.value().to_string(), t.0.to_string(), t.1.to_string()));
    }
    out
}

/// 对应 Go 版 `saveSessionsToDisk()`：整表覆盖写入未过期快照，写错误按 Go 版忽略。
pub fn save_sessions(snapshot: &[(String, String, String)]) {
    let Ok(d) = db() else { return };
    let Ok(txn) = d.begin_write() else { return };
    {
        let Ok(mut table) = txn.open_table(SESSIONS) else {
            return;
        };
        if table.retain(|_, _| false).is_err() {
            return;
        }
        for (token, username, expires_at) in snapshot {
            if table
                .insert(token.as_str(), &(username.as_str(), expires_at.as_str()))
                .is_err()
            {
                return;
            }
        }
    }
    let _ = txn.commit();
}

// ---- SSH Profiles ----

fn load_ssh_profiles_raw() -> Vec<SSHProfile> {
    let Ok(d) = db() else { return Vec::new() };
    let Ok(txn) = d.begin_read() else {
        return Vec::new();
    };
    let Ok(order) = txn.open_table(PROFILE_ORDER) else {
        return Vec::new();
    };
    let Ok(profiles) = txn.open_table(PROFILES) else {
        return Vec::new();
    };
    let Ok(iter) = order.iter() else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for entry in iter {
        let Ok((_, id_guard)) = entry else { continue };
        let id = id_guard.value().to_string();
        let Some(value) = profiles.get(id.as_str()).ok().flatten() else {
            continue;
        };
        let t = value.value();
        out.push(SSHProfile {
            id,
            name: t.0.to_string(),
            host: t.1.to_string(),
            port: t.2,
            username: t.3.to_string(),
            password: t.4.to_string(),
            private_key: t.5.to_string(),
            passphrase: t.6.to_string(),
            auth_type: t.7.to_string(),
            created_at: t.8.to_string(),
        });
    }
    out
}

/// 整表覆盖写入 profiles（对应 Go 版 `writeJSON` 的一次性全量写），并按 Vec 顺序重建保序表。
fn write_ssh_profiles(profiles: &[SSHProfile]) -> Result<(), String> {
    let d = db()?;
    let txn = d.begin_write().map_err(|e| e.to_string())?;
    {
        let mut pt = txn.open_table(PROFILES).map_err(|e| e.to_string())?;
        let mut ot = txn
            .open_table(PROFILE_ORDER)
            .map_err(|e| e.to_string())?;
        pt.retain(|_, _| false).map_err(|e| e.to_string())?;
        ot.retain(|_, _| false).map_err(|e| e.to_string())?;
        for (i, p) in profiles.iter().enumerate() {
            pt.insert(
                p.id.as_str(),
                &(
                    p.name.as_str(),
                    p.host.as_str(),
                    p.port,
                    p.username.as_str(),
                    p.password.as_str(),
                    p.private_key.as_str(),
                    p.passphrase.as_str(),
                    p.auth_type.as_str(),
                    p.created_at.as_str(),
                ),
            )
            .map_err(|e| e.to_string())?;
            ot.insert(i as u64, p.id.as_str())
                .map_err(|e| e.to_string())?;
        }
    }
    txn.commit().map_err(|e| e.to_string())?;
    Ok(())
}

/// 对应 Go 版 `LoadSSHProfiles()`：读取并解密（内部使用，连接时取凭证）。
pub fn load_ssh_profiles() -> Vec<SSHProfile> {
    decrypt_profiles(&load_ssh_profiles_raw())
}

/// 对应 Go 版 `LoadSSHProfilesSafe()`：解密仅为判断字段是否有值，不对外暴露。
pub fn load_ssh_profiles_safe() -> Vec<SSHProfileSafe> {
    safe_list(&load_ssh_profiles_raw())
}

fn decrypt_profiles(raw: &[SSHProfile]) -> Vec<SSHProfile> {
    raw.iter()
        .map(|p| {
            let mut p = p.clone();
            // Go: `p.Password, _ = decrypt(p.Password)` —— 错误时结果为空串
            p.password = decrypt(&p.password).unwrap_or_default();
            p.private_key = decrypt(&p.private_key).unwrap_or_default();
            p.passphrase = decrypt(&p.passphrase).unwrap_or_default();
            p
        })
        .collect()
}

fn safe_list(raw: &[SSHProfile]) -> Vec<SSHProfileSafe> {
    decrypt_profiles(raw).iter().map(|p| p.to_safe()).collect()
}

/// 对应 Go 版 `SaveSSHProfile()`。
pub fn save_ssh_profile(mut p: SSHProfile) -> Result<Vec<SSHProfileSafe>, String> {
    p.password = encrypt(&p.password)?;
    p.private_key = encrypt(&p.private_key)?;
    p.passphrase = encrypt(&p.passphrase)?;

    let mut profiles = load_ssh_profiles_raw();
    for existing in profiles.iter_mut() {
        if existing.id == p.id {
            // 客户端未传敏感字段（空）时保留原有加密值
            if p.password.is_empty() {
                p.password = existing.password.clone();
            }
            if p.private_key.is_empty() {
                p.private_key = existing.private_key.clone();
            }
            if p.passphrase.is_empty() {
                p.passphrase = existing.passphrase.clone();
            }
            *existing = p;
            write_ssh_profiles(&profiles)?;
            return Ok(safe_list(&profiles));
        }
    }
    if p.id.is_empty() {
        p.id = generate_id();
    }
    p.created_at = Local::now().format("%Y-%m-%dT%H:%M:%S%:z").to_string();
    profiles.push(p);
    write_ssh_profiles(&profiles)?;
    Ok(safe_list(&profiles))
}

/// 对应 Go 版 `DeleteSSHProfile()`。
pub fn delete_ssh_profile(id: &str) -> Result<Vec<SSHProfileSafe>, String> {
    let profiles = load_ssh_profiles_raw();
    let updated: Vec<SSHProfile> = profiles.into_iter().filter(|p| p.id != id).collect();
    write_ssh_profiles(&updated)?;
    Ok(safe_list(&updated))
}
