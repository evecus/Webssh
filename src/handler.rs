//! HTTP 处理层 —— 与 Go 版 `internal/handler/handler.go` 逻辑一一对应。
//!
//! - 路由注册与 requireAuth 中间件
//! - setup / login / logout、登录频率限制、密码强度校验
//! - session 管理（内存快照 + redb sessions 表持久化）
//! - settings / ssh profiles / trust-host API
//! - WebSocket ↔ SSH 双向转发
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{LazyLock, Mutex, OnceLock, RwLock};

use axum::body::{to_bytes, Body};
use axum::extract::ws::{Message as WsMessage, WebSocket, WebSocketUpgrade};
use axum::extract::ConnectInfo;
use axum::http::{header, HeaderMap, HeaderValue, Method, Request, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::any;
use axum::Router;
use chrono::{DateTime, Duration, FixedOffset, Local, Utc};
use rand::RngCore;
use russh::ChannelMsg;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::ssh;
use crate::store;
use crate::template::{self, PageData};

// ---- 应用配置（对应 Go 版 AppConfig）----

#[derive(Clone, Copy)]
pub struct AppConfig {
    pub auth_enabled: bool,
    pub store_enabled: bool,
}

/// 由 main 在启动时注入。
pub static APP_CONFIG: OnceLock<AppConfig> = OnceLock::new();

fn cfg() -> AppConfig {
    APP_CONFIG.get().copied().unwrap_or(AppConfig {
        auth_enabled: false,
        store_enabled: false,
    })
}

// ---- Session 管理 ----

#[derive(Clone)]
struct Session {
    username: String,
    expires_at: DateTime<FixedOffset>,
}

static SESSIONS: LazyLock<RwLock<HashMap<String, Session>>> =
    LazyLock::new(|| RwLock::new(HashMap::new()));

/// 对应 Go 版 `loadSessionsFromDisk()`：仅加载未过期的会话。
/// 数据来源由 `data/sessions.json` 改为 redb 的 sessions 表（字段仍为 RFC3339 时间串）。
pub fn load_sessions_from_disk() {
    let now = Utc::now();
    let mut sessions = SESSIONS.write().unwrap();
    for (token, username, expires_at) in store::load_sessions() {
        let Ok(dt) = DateTime::parse_from_rfc3339(&expires_at) else {
            continue;
        };
        if now < dt.with_timezone(&Utc) {
            sessions.insert(
                token,
                Session {
                    username,
                    expires_at: dt,
                },
            );
        }
    }
}

/// 对应 Go 版 `saveSessionsToDisk()`：把未过期快照整表覆盖写入 redb。
fn save_sessions_to_disk() {
    let sessions = SESSIONS.read().unwrap();
    let now = Utc::now();
    let snapshot: Vec<(String, String, String)> = sessions
        .iter()
        .filter(|(_, s)| now < s.expires_at.with_timezone(&Utc))
        .map(|(token, s)| {
            (
                token.clone(),
                s.username.clone(),
                s.expires_at.to_rfc3339(),
            )
        })
        .collect();
    store::save_sessions(&snapshot);
}

/// 对应 Go 版 `newSession()`：32 字节随机 token（hex），24 小时有效。
fn new_session(username: &str) -> String {
    let mut b = [0u8; 32];
    rand::rng().fill_bytes(&mut b);
    let token = hex::encode(b);
    let expires_at = (Local::now() + Duration::hours(24)).fixed_offset();
    SESSIONS.write().unwrap().insert(
        token.clone(),
        Session {
            username: username.to_string(),
            expires_at,
        },
    );
    save_sessions_to_disk();
    token
}

fn cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
    let raw = headers.get(header::COOKIE)?.to_str().ok()?;
    for part in raw.split(';') {
        let part = part.trim();
        if let Some((k, v)) = part.split_once('=') {
            if k == name {
                return Some(v.to_string());
            }
        }
    }
    None
}

/// 对应 Go 版 `getSession()`。
fn get_session(headers: &HeaderMap) -> Option<Session> {
    let token = cookie_value(headers, "wssh_session")?;
    let sessions = SESSIONS.read().unwrap();
    let s = sessions.get(&token)?.clone();
    if Utc::now() > s.expires_at.with_timezone(&Utc) {
        None
    } else {
        Some(s)
    }
}

/// 对应 Go 版 `deleteSession()`。
fn delete_session(token: &str) {
    SESSIONS.write().unwrap().remove(token);
    save_sessions_to_disk();
}

// ---- 登录频率限制（对应 Go 版 checkLoginRateLimit / recordLoginFailure）----

struct LoginAttempt {
    count: i32,
    first_at: DateTime<Utc>,
    locked_until: DateTime<Utc>,
}

static LOGIN_ATTEMPTS: LazyLock<Mutex<HashMap<String, LoginAttempt>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

const MAX_LOGIN_ATTEMPTS: i32 = 5;

fn unix_epoch() -> DateTime<Utc> {
    DateTime::from_timestamp(0, 0).unwrap()
}

fn check_login_rate_limit(ip: &str) -> (bool, i32) {
    let mut attempts = LOGIN_ATTEMPTS.lock().unwrap();
    let now = Utc::now();
    match attempts.get_mut(ip) {
        None => (true, 0),
        Some(a) => {
            if now < a.locked_until {
                let remaining = (a.locked_until - now).num_seconds() as i32 + 1;
                return (false, remaining);
            }
            if now - a.first_at > Duration::minutes(5) {
                attempts.remove(ip);
                return (true, 0);
            }
            (a.count < MAX_LOGIN_ATTEMPTS, 0)
        }
    }
}

fn record_login_failure(ip: &str) {
    let mut attempts = LOGIN_ATTEMPTS.lock().unwrap();
    let now = Utc::now();
    match attempts.get_mut(ip) {
        Some(a) if now - a.first_at <= Duration::minutes(5) => {
            a.count += 1;
            if a.count >= MAX_LOGIN_ATTEMPTS {
                a.locked_until = now + Duration::minutes(15);
            }
        }
        _ => {
            attempts.insert(
                ip.to_string(),
                LoginAttempt {
                    count: 1,
                    first_at: now,
                    locked_until: unix_epoch(),
                },
            );
        }
    }
}

fn reset_login_failure(ip: &str) {
    LOGIN_ATTEMPTS.lock().unwrap().remove(ip);
}

/// 对应 Go 版 `getClientIP()`。
fn get_client_ip(headers: &HeaderMap, remote_addr: &str) -> String {
    if let Some(fwd) = headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
    {
        if !fwd.is_empty() {
            return fwd.split(',').next().unwrap_or("").trim().to_string();
        }
    }
    match remote_addr.rfind(':') {
        Some(i) => remote_addr[..i].to_string(),
        None => remote_addr.to_string(),
    }
}

/// 对应 Go 版 `validatePasswordStrength()`。
fn validate_password_strength(password: &str) -> String {
    if password.len() < 8 {
        return "密码长度至少 8 位".to_string();
    }
    let (mut has_upper, mut has_lower, mut has_digit) = (false, false, false);
    for c in password.chars() {
        if c.is_uppercase() {
            has_upper = true;
        } else if c.is_lowercase() {
            has_lower = true;
        } else if c.is_numeric() {
            has_digit = true;
        }
    }
    if !has_upper || !has_lower || !has_digit {
        "密码须包含大写字母、小写字母和数字".to_string()
    } else {
        String::new()
    }
}

// ---- 通用响应辅助 ----

fn text_response(status: StatusCode, msg: &str) -> Response {
    // 对应 Go 的 http.Error：text/plain; charset=utf-8，正文带换行
    (
        status,
        [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        format!("{}\n", msg),
    )
        .into_response()
}

fn json_response(value: &Value) -> Response {
    // 对应 Go 的 json.NewEncoder(w).Encode(v)：application/json + 末尾换行
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/json")],
        format!("{}\n", value),
    )
        .into_response()
}

fn redirect(location: &str) -> Response {
    // 对应 Go 的 http.Redirect(w, r, url, http.StatusFound)
    (
        StatusCode::FOUND,
        [(header::LOCATION, location)],
        format!("<a href=\"{}\">Found</a>.\n\n", location),
    )
        .into_response()
}

fn with_cookie(mut resp: Response, cookie: &str) -> Response {
    if let Ok(v) = HeaderValue::from_str(cookie) {
        resp.headers_mut().append(header::SET_COOKIE, v);
    }
    resp
}

fn render_page(tmpl: &str, data: &PageData) -> Response {
    // 对应 Go 的 renderPage：Content-Type: text/html; charset=utf-8
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        template::render(tmpl, data),
    )
        .into_response()
}

// ---- 表单 / 查询参数（对应 Go 的 r.FormValue / r.URL.Query()）----

fn query_value(query: &str, key: &str) -> String {
    for (k, v) in form_urlencoded::parse(query.as_bytes()) {
        if k == key {
            return v.into_owned();
        }
    }
    String::new()
}

fn form_value(query: &str, body: &[u8], key: &str) -> String {
    // Go 的 ParseForm 先合并 URL query，再合并 POST body（取第一个匹配值）
    for (k, v) in form_urlencoded::parse(query.as_bytes()) {
        if k == key {
            return v.into_owned();
        }
    }
    for (k, v) in form_urlencoded::parse(body) {
        if k == key {
            return v.into_owned();
        }
    }
    String::new()
}

// ---- requireAuth（对应 Go 版 appHandler.requireAuth）----

fn require_auth(path: &str, headers: &HeaderMap) -> Option<Response> {
    if !cfg().auth_enabled {
        return None;
    }
    if !store::auth_exists() {
        if path != "/setup" {
            return Some(redirect("/setup"));
        }
        return None;
    }
    if get_session(headers).is_none() {
        if path.starts_with("/api/") || path == "/ws" {
            return Some(text_response(StatusCode::UNAUTHORIZED, "Unauthorized"));
        }
        return Some(redirect("/login"));
    }
    None
}

// ---- 路由注册（对应 Go 版 Register）----

pub fn router() -> Router {
    if cfg().auth_enabled {
        load_sessions_from_disk();
    }
    Router::new().route("/ws", any(ws_route)).fallback(dispatch)
}

/// 所有非 /ws 请求的总入口（Go 的 ServeMux 精确路径 + "/" 兜底）。
async fn dispatch(req: Request<Body>) -> Response {
    let path = req.uri().path().to_string();
    let query = req.uri().query().unwrap_or("").to_string();
    let method = req.method().clone();
    let headers = req.headers().clone();
    let remote_addr = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|c| c.0.to_string())
        .unwrap_or_default();

    // requireAuth 只包裹 /api/*、/ws、/（与 Go 版注册方式一致）
    if path.starts_with("/api/") || path == "/ws" || !matches!(
        path.as_str(),
        "/setup" | "/login" | "/logout"
    ) {
        if let Some(resp) = require_auth(&path, &headers) {
            return resp;
        }
    }

    let body = to_bytes(req.into_body(), 16 * 1024 * 1024)
        .await
        .map(|b| b.to_vec())
        .unwrap_or_default();

    match path.as_str() {
        "/" => index_handler(&path),
        "/setup" => setup_handler(&method, &query, &body),
        "/login" => login_handler(&method, &query, &body, &headers, &remote_addr),
        "/logout" => logout_handler(&headers),
        "/api/settings" => settings_api_handler(&method, &body),
        "/api/ssh" => ssh_profiles_api_handler(&method, &query, &body),
        "/api/trust-host" => trust_host_api_handler(&method, &body),
        _ => text_response(StatusCode::NOT_FOUND, "404 page not found"),
    }
}

// ---- 页面处理器 ----

fn index_handler(path: &str) -> Response {
    if path != "/" {
        return text_response(StatusCode::NOT_FOUND, "404 page not found");
    }
    let c = cfg();
    render_page(
        template::INDEX_HTML_TEMPLATE,
        &PageData {
            store_enabled: c.store_enabled,
            auth_enabled: c.auth_enabled,
            ..PageData::new()
        },
    )
}

fn setup_handler(method: &Method, query: &str, body: &[u8]) -> Response {
    if !cfg().auth_enabled {
        return redirect("/");
    }
    if store::auth_exists() {
        return redirect("/login");
    }

    let mut data = PageData::new();

    if method.as_str() == "POST" {
        let username = form_value(query, body, "username").trim().to_string();
        let password = form_value(query, body, "password");
        let confirm = form_value(query, body, "confirm");

        if username.is_empty() || password.is_empty() {
            data.error = "用户名和密码不能为空".to_string();
            return render_page(template::SETUP_HTML_TEMPLATE, &data);
        }
        if password != confirm {
            data.error = "两次密码输入不一致".to_string();
            return render_page(template::SETUP_HTML_TEMPLATE, &data);
        }
        let strength = validate_password_strength(&password);
        if !strength.is_empty() {
            data.error = strength;
            return render_page(template::SETUP_HTML_TEMPLATE, &data);
        }
        // Go: bcrypt.DefaultCost == 10
        let hash = match bcrypt::hash(&password, 10) {
            Ok(h) => h,
            Err(_) => {
                data.error = "系统错误，请重试".to_string();
                return render_page(template::SETUP_HTML_TEMPLATE, &data);
            }
        };
        match store::save_auth(&store::AuthData {
            username,
            password_hash: hash,
        }) {
            Ok(()) => return redirect("/login?setup=ok"),
            Err(e) if e == "auth already initialized" => return redirect("/login"),
            Err(_) => {
                data.error = "保存失败，请重试".to_string();
                return render_page(template::SETUP_HTML_TEMPLATE, &data);
            }
        }
    }

    render_page(template::SETUP_HTML_TEMPLATE, &data)
}

fn login_handler(
    method: &Method,
    query: &str,
    body: &[u8],
    headers: &HeaderMap,
    remote_addr: &str,
) -> Response {
    if !cfg().auth_enabled {
        return redirect("/");
    }
    if !store::auth_exists() {
        return redirect("/setup");
    }
    if get_session(headers).is_some() {
        return redirect("/");
    }

    let mut data = PageData::new();
    data.success = query_value(query, "setup") == "ok";

    if method.as_str() == "POST" {
        let ip = get_client_ip(headers, remote_addr);

        let (allowed, wait_sec) = check_login_rate_limit(&ip);
        if !allowed {
            data.error = if wait_sec > 0 {
                "登录失败次数过多，请稍后再试"
            } else {
                "请求过于频繁，请稍后再试"
            }
            .to_string();
            return render_page(template::LOGIN_HTML_TEMPLATE, &data);
        }

        let username = form_value(query, body, "username").trim().to_string();
        let password = form_value(query, body, "password");

        let ok = match store::load_auth() {
            Ok(auth) => {
                auth.username == username
                    && bcrypt::verify(&password, &auth.password_hash).unwrap_or(false)
            }
            Err(_) => false,
        };
        if !ok {
            record_login_failure(&ip);
            data.error = "用户名或密码错误".to_string();
            return render_page(template::LOGIN_HTML_TEMPLATE, &data);
        }

        reset_login_failure(&ip);
        let token = new_session(&username);
        let resp = redirect("/");
        // 对应 Go: HttpOnly + MaxAge=86400 + SameSite=Strict
        return with_cookie(
            resp,
            &format!(
                "wssh_session={}; Path=/; HttpOnly; Max-Age=86400; SameSite=Strict",
                token
            ),
        );
    }

    render_page(template::LOGIN_HTML_TEMPLATE, &data)
}

fn logout_handler(headers: &HeaderMap) -> Response {
    if let Some(token) = cookie_value(headers, "wssh_session") {
        delete_session(&token);
    }
    let resp = redirect("/login");
    // 对应 Go: MaxAge=-1 → "Max-Age=0"
    with_cookie(resp, "wssh_session=; Path=/; Max-Age=0")
}

// ---- API 处理器 ----

fn settings_api_handler(method: &Method, body: &[u8]) -> Response {
    if !cfg().store_enabled {
        return text_response(StatusCode::FORBIDDEN, "Store not enabled");
    }
    match method.as_str() {
        "GET" => {
            let s = store::load_settings();
            json_response(&serde_json::to_value(s).unwrap_or(Value::Null))
        }
        "POST" => {
            let s: store::Settings = match serde_json::from_slice(body) {
                Ok(s) => s,
                Err(_) => return text_response(StatusCode::BAD_REQUEST, "invalid json"),
            };
            let _ = store::save_settings(&s); // Go 版忽略保存错误
            json_response(&serde_json::to_value(s).unwrap_or(Value::Null))
        }
        _ => text_response(StatusCode::METHOD_NOT_ALLOWED, "method not allowed"),
    }
}

fn ssh_profiles_api_handler(method: &Method, query: &str, body: &[u8]) -> Response {
    if !cfg().store_enabled {
        return text_response(StatusCode::FORBIDDEN, "Store not enabled");
    }
    match method.as_str() {
        "GET" => {
            // 对应 Go: LoadSSHProfilesSafe() —— 返回安全视图，不含明文凭证
            let profiles = store::load_ssh_profiles_safe();
            json_response(&serde_json::to_value(profiles).unwrap_or(Value::Null))
        }
        "POST" => {
            let p: store::SSHProfile = match serde_json::from_slice(body) {
                Ok(p) => p,
                Err(_) => return text_response(StatusCode::BAD_REQUEST, "invalid json"),
            };
            match store::save_ssh_profile(p) {
                Ok(profiles) => {
                    json_response(&serde_json::to_value(profiles).unwrap_or(Value::Null))
                }
                Err(_) => text_response(StatusCode::INTERNAL_SERVER_ERROR, "internal error"),
            }
        }
        "DELETE" => {
            let id = query_value(query, "id");
            if id.is_empty() {
                return text_response(StatusCode::BAD_REQUEST, "missing id");
            }
            match store::delete_ssh_profile(&id) {
                Ok(profiles) => {
                    json_response(&serde_json::to_value(profiles).unwrap_or(Value::Null))
                }
                Err(_) => text_response(StatusCode::INTERNAL_SERVER_ERROR, "internal error"),
            }
        }
        _ => text_response(StatusCode::METHOD_NOT_ALLOWED, "method not allowed"),
    }
}

/// 对应 Go 版 `trustHostAPIHandler()`：清除旧指纹，下次连接 TOFU 重新记录。
fn trust_host_api_handler(method: &Method, body: &[u8]) -> Response {
    if method.as_str() != "POST" {
        return text_response(StatusCode::METHOD_NOT_ALLOWED, "method not allowed");
    }
    #[derive(Deserialize)]
    struct Req {
        #[serde(default)]
        hostname: String,
    }
    let req: Req = match serde_json::from_slice(body) {
        Ok(r) => r,
        Err(_) => return text_response(StatusCode::BAD_REQUEST, "invalid request"),
    };
    if req.hostname.is_empty() {
        return text_response(StatusCode::BAD_REQUEST, "invalid request");
    }
    // 基本校验：防止路径穿越或注入
    if req.hostname.chars().any(|c| " \t\r\n/\\".contains(c)) {
        return text_response(StatusCode::BAD_REQUEST, "invalid hostname");
    }
    if let Err(e) = ssh::remove_known_host(&req.hostname) {
        log::error!(
            "trust-host: failed to remove known_hosts entry for {}: {}",
            req.hostname,
            e
        );
        return text_response(StatusCode::INTERNAL_SERVER_ERROR, "internal error");
    }
    json_response(&json!({"ok": true}))
}

// ---- WebSocket ↔ SSH ----

/// 对应 Go 版 `Message`。
#[derive(Deserialize, Default)]
struct Message {
    #[serde(rename = "type", default)]
    type_: String,
    #[serde(default)]
    data: String,
    #[serde(default)]
    host: String,
    #[serde(default)]
    port: i32,
    #[serde(default)]
    username: String,
    #[serde(default)]
    password: String,
    #[serde(default)]
    private_key: String,
    #[serde(default)]
    passphrase: String,
    #[serde(default)]
    rows: u32,
    #[serde(default)]
    cols: u32,
    #[serde(default)]
    profile_id: String,
}

async fn send_json(socket: &mut WebSocket, value: &Value) -> bool {
    socket
        .send(WsMessage::Text(value.to_string().into()))
        .await
        .is_ok()
}

fn ws_bytes(msg: WsMessage) -> Option<Vec<u8>> {
    match msg {
        WsMessage::Text(t) => Some(t.as_str().as_bytes().to_vec()),
        WsMessage::Binary(b) => Some(b.to_vec()),
        _ => None,
    }
}

/// 对应 Go 版 `wsHandler()` 的升级入口（含 makeUpgrader 的严格 Origin 校验）。
async fn ws_route(headers: HeaderMap, ws: WebSocketUpgrade) -> Response {
    if let Some(resp) = require_auth("/ws", &headers) {
        return resp;
    }
    if cfg().auth_enabled {
        let origin = headers
            .get(header::ORIGIN)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        let host = headers
            .get(header::HOST)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        let same = origin == format!("http://{}", host) || origin == format!("https://{}", host);
        if origin.is_empty() || !same {
            return text_response(
                StatusCode::FORBIDDEN,
                "websocket: request origin not allowed by Upgrader.CheckOrigin",
            );
        }
    }

    // 对应 Go: ReadBufferSize: 4096, WriteBufferSize: 4096
    ws.read_buffer_size(4096)
        .write_buffer_size(4096)
        .on_upgrade(handle_ws)
}

/// 对应 Go 版 wsHandler 主体：读取首条连接消息 → 建立 SSH → 双向转发。
async fn handle_ws(mut socket: WebSocket) {
    // 1) 首条消息：连接参数
    let first = loop {
        match socket.recv().await {
            Some(Ok(msg)) => match ws_bytes(msg) {
                Some(b) => break b,
                None => continue, // 跳过 Ping/Pong 等控制帧
            },
            _ => return,
        }
    };

    let msg: Message = match serde_json::from_slice(&first) {
        Ok(m) => m,
        Err(_) => {
            let _ = send_json(&mut socket, &json!({"type": "error", "data": "invalid request"})).await;
            return;
        }
    };

    let port = if msg.port == 0 { 22 } else { msg.port };

    // 2) 构建 SSH 配置：profile_id 模式从存储取凭证，否则使用直传凭证
    let ssh_cfg = if !msg.profile_id.is_empty() && cfg().store_enabled {
        let profiles = store::load_ssh_profiles();
        match profiles.iter().find(|p| p.id == msg.profile_id) {
            Some(p) => ssh::Config {
                host: p.host.clone(),
                port: p.port,
                username: p.username.clone(),
                password: p.password.clone(),
                private_key: p.private_key.clone(),
                passphrase: p.passphrase.clone(),
            },
            None => {
                let _ = send_json(
                    &mut socket,
                    &json!({"type": "error", "data": "profile not found"}),
                )
                .await;
                return;
            }
        }
    } else {
        ssh::Config {
            host: msg.host.clone(),
            port,
            username: msg.username.clone(),
            password: msg.password.clone(),
            private_key: msg.private_key.clone(),
            passphrase: msg.passphrase.clone(),
        }
    };

    let session = match ssh::connect(ssh_cfg).await {
        Ok(s) => s,
        Err(e) => {
            let _ = send_json(&mut socket, &json!({"type": "error", "data": e})).await;
            return;
        }
    };
    if !send_json(&mut socket, &json!({"type": "connected"})).await {
        return;
    }

    let (mut read, write, handle) = session.into_parts();

    // 3) 主循环：SSH 输出 → WS output，WS input/resize → SSH
    loop {
        tokio::select! {
            chan_msg = read.wait() => {
                match chan_msg {
                    Some(ChannelMsg::Data { data }) => {
                        let s = String::from_utf8_lossy(&data).into_owned();
                        if !send_json(&mut socket, &json!({"type": "output", "data": s})).await {
                            break;
                        }
                    }
                    Some(ChannelMsg::ExtendedData { data, .. }) => {
                        // 对应 Go 的 stderr 读循环：同样作为 output 发往前端
                        let s = String::from_utf8_lossy(&data).into_owned();
                        if !send_json(&mut socket, &json!({"type": "output", "data": s})).await {
                            break;
                        }
                    }
                    Some(ChannelMsg::Eof) | Some(ChannelMsg::Close) | None => {
                        // 对应 Go: stdout EOF → {"type":"closed"}
                        let _ = send_json(&mut socket, &json!({"type": "closed"})).await;
                        break;
                    }
                    _ => {}
                }
            }
            ws_msg = socket.recv() => {
                match ws_msg {
                    Some(Ok(msg)) => {
                        let bytes = match ws_bytes(msg) {
                            Some(b) => b,
                            None => continue,
                        };
                        let ws_msg: Message = match serde_json::from_slice(&bytes) {
                            Ok(m) => m,
                            Err(_) => continue,
                        };
                        match ws_msg.type_.as_str() {
                            "input" => {
                                if write.data_bytes(ws_msg.data.into_bytes()).await.is_err() {
                                    break;
                                }
                            }
                            "resize" => {
                                let rows = if ws_msg.rows == 0 { 24 } else { ws_msg.rows };
                                let cols = if ws_msg.cols == 0 { 80 } else { ws_msg.cols };
                                let _ = write.window_change(cols, rows, 0, 0).await;
                            }
                            _ => {}
                        }
                    }
                    _ => break, // WS 关闭或出错
                }
            }
        }
    }

    // 对应 Go: defer sshSession.Close()
    let _ = handle
        .disconnect(russh::Disconnect::ByApplication, "", "English")
        .await;
}
