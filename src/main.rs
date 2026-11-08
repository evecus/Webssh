//! WebSSH Console —— Rust 版入口，对应 Go 版 `cmd/webssh/main.go`。
//!
//! 所有源码均为 `.rs`：Web UI 内嵌在 `template.rs`，无第二种编程语言。
mod handler;
mod ssh;
mod store;
mod template;

use std::io;
use std::net::SocketAddr;
use std::os::unix::fs::DirBuilderExt;
use std::path::{Component, Path, PathBuf};

use handler::AppConfig;
use log::LevelFilter;

#[tokio::main]
async fn main() {
    env_logger::builder().filter_level(LevelFilter::Info).init();

    // --- 1. 定义参数 ---
    let args = parse_args();

    // --- 2. 处理工作目录切换 ---
    setup_work_dir(&args.workdir);

    // --- 3. 后续逻辑（路径已生效）---
    let mut port = args.port;
    if let Ok(v) = std::env::var("PORT") {
        if !v.is_empty() {
            if let Ok(p) = v.parse::<i32>() {
                port = p;
            }
        }
    }

    let mut auth_enabled = parse_bool(&args.auth);
    if let Ok(v) = std::env::var("AUTH") {
        if !v.is_empty() {
            auth_enabled = parse_bool(&v);
        }
    }

    let mut store_enabled = parse_bool(&args.store);
    if let Ok(v) = std::env::var("STORE") {
        if !v.is_empty() {
            store_enabled = parse_bool(&v);
        }
    }

    if !auth_enabled {
        log::warn!("⚠️  WARNING: Authentication is DISABLED.");
    }

    let mut allowed_hosts_arg = args.allowed_hosts.clone();
    if let Ok(v) = std::env::var("ALLOWED_HOSTS") {
        if !v.is_empty() {
            allowed_hosts_arg = v;
        }
    }
    let mut allowed_hosts: Vec<String> = Vec::new();
    if !allowed_hosts_arg.is_empty() {
        for p in allowed_hosts_arg.split(',') {
            let p = p.trim();
            if !p.is_empty() {
                allowed_hosts.push(p.to_string());
            }
        }
        log::info!("SSH target whitelist: {:?}", allowed_hosts);
    }
    let _ = ssh::ALLOWED_HOSTS.set(allowed_hosts);

    // 此时 store::ensure_data_dir() 会在新的 workdir 下创建目录
    if store_enabled || auth_enabled {
        if let Err(e) = store::ensure_data_dir() {
            fatal(&format!("Failed to create data directory: {}", e));
        }
        if store_enabled {
            if let Err(e) = store::load_or_create_encryption_key() {
                fatal(&format!("Failed to initialize encryption key: {}", e));
            }
        }
    }

    let _ = handler::APP_CONFIG.set(AppConfig {
        auth_enabled,
        store_enabled,
    });

    let app = handler::router();
    let addr = format!(":{}", port);
    log::info!("WebSSH Console started on {}", addr);

    // Go 的 net.Listen("tcp", ":port") 监听全部接口；优先 IPv6 双栈，失败回退 IPv4
    let listener = match tokio::net::TcpListener::bind(format!("[::]:{}", port)).await {
        Ok(l) => l,
        Err(_) => tokio::net::TcpListener::bind(format!("0.0.0.0:{}", port))
            .await
            .unwrap_or_else(|e| fatal(&e.to_string())),
    };

    if let Err(e) = axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    {
        fatal(&e.to_string());
    }
}

fn fatal(msg: &str) -> ! {
    log::error!("{}", msg);
    std::process::exit(1)
}

// ---- 命令行参数（对应 Go 的 flag 包用法，不引入额外依赖）----

struct Args {
    port: i32,
    auth: String,
    store: String,
    allowed_hosts: String,
    workdir: String,
}

fn parse_args() -> Args {
    let mut args = Args {
        port: 8888,
        auth: "false".to_string(),
        store: "false".to_string(),
        allowed_hosts: String::new(),
        workdir: String::new(),
    };
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let mut i = 0;
    while i < argv.len() {
        let arg = &argv[i];
        if arg == "-h" || arg == "--help" || arg == "-help" {
            print_usage();
            std::process::exit(0);
        }
        let (key, inline) = match arg.split_once('=') {
            Some((k, v)) => (k, Some(v.to_string())),
            None => (arg.as_str(), None),
        };
        let key = key.trim_start_matches('-');
        let value = match inline {
            Some(v) => v,
            None => {
                i += 1;
                argv.get(i).cloned().unwrap_or_default()
            }
        };
        match key {
            "port" => args.port = value.parse::<i32>().unwrap_or(8888),
            "auth" => args.auth = value,
            "store" => args.store = value,
            "allowed-hosts" => args.allowed_hosts = value,
            "workdir" => args.workdir = value,
            _ => log::warn!("unknown flag: {}", arg),
        }
        i += 1;
    }
    args
}

fn print_usage() {
    eprintln!("Usage of webssh:");
    eprintln!("  -port int        HTTP server port (default 8888)");
    eprintln!("  -auth string     Enable authentication (true/false) (default \"false\")");
    eprintln!("  -store string    Enable data storage (true/false) (default \"false\")");
    eprintln!("  -allowed-hosts string  Comma-separated list of allowed SSH target hosts");
    eprintln!("  -workdir string  Set the working directory (default is current directory)");
}

/// 对应 Go 版 `setupWorkDir()`：支持 -workdir / WORK_DIR，创建后切换进程工作目录。
fn setup_work_dir(path: &str) {
    let mut path = path.to_string();
    if path.is_empty() {
        path = std::env::var("WORK_DIR").unwrap_or_default();
    }
    if path.is_empty() {
        return;
    }

    let abs = match absolutize(&path) {
        Ok(p) => p,
        Err(e) => fatal(&format!(
            "❌ Failed to resolve absolute path for {}: {}",
            path, e
        )),
    };

    if !abs.exists() {
        log::info!("Creating working directory: {}", abs.display());
        if let Err(e) = std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o755)
            .create(&abs)
        {
            fatal(&format!("❌ Failed to create workdir: {}", e));
        }
    }

    if let Err(e) = std::env::set_current_dir(&abs) {
        fatal(&format!(
            "❌ Failed to change working directory to {}: {}",
            abs.display(),
            e
        ));
    }
    log::info!("✅ Working directory set to: {}", abs.display());
}

/// Go `filepath.Abs` 的等价实现：转绝对路径 + 词法 Clean（不要求路径存在）。
fn absolutize(path: &str) -> io::Result<PathBuf> {
    let p = Path::new(path);
    let joined = if p.is_absolute() {
        p.to_path_buf()
    } else {
        std::env::current_dir()?.join(p)
    };
    let mut out = PathBuf::new();
    for comp in joined.components() {
        match comp {
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            c => out.push(c.as_os_str()),
        }
    }
    Ok(out)
}

/// 对应 Go 版 `parseBool()`。
fn parse_bool(s: &str) -> bool {
    let s = s.trim().to_lowercase();
    s == "true" || s == "1" || s == "yes"
}
