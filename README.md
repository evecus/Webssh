# WebSSH Console（Rust 版）

原 Go 版 webssh 的 **纯 Rust 改写**：逻辑与 Go 版保持一致，Web UI 全部以字符串常量内嵌在 `src/template.rs`（`.rs` 文件）中，项目源码不引入第二种编程语言。使用 `axum` + `tokio` + `russh` + `redb`（均为纯 Rust）实现 HTTP / WebSocket / SSH 与持久化。

> **存储**：结构化数据全部落在 `redb` 单文件数据库 `data/webssh.redb`（0600），运行时不产生任何 JSON 文件。`serde_json` 只用于浏览器与服务端之间的 HTTP / WebSocket 通信协议——前端 JS 逐字沿用 Go 版，必须收发 JSON，因此该依赖无法移除；它不参与任何持久化。

## 源码结构

| 文件 | 对应 Go 版 | 职责 |
|------|-----------|------|
| `src/main.rs` | `cmd/webssh/main.go` | 命令行参数、环境变量、工作目录切换、启动服务 |
| `src/store.rs` | `internal/store/store.go` | AES-256-GCM 加密、auth / settings / sessions / ssh profiles 的 redb 持久化 |
| `src/ssh.rs` | `internal/ssh/ssh.go` | 主机白名单、TOFU known_hosts、SSH 认证、PTY、读写 |
| `src/handler.rs` | `internal/handler/handler.go` | 路由、会话、登录限流、页面、API、WebSocket 转发 |
| `src/template.rs` | `internal/handler/template.go` | **Web UI（HTML/CSS/JS 内嵌于 `.rs`）** + 迷你模板渲染器 |

> 注：两个 `.github/workflows/*.yml` 是 GitHub Actions 要求的配置文件，不是应用源码；运行时不需要 Go、Node、Python 等任何其他语言环境。

## 运行参数（与 Go 版一致）

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `-port <端口>` | `8888` | HTTP 监听端口 |
| `-auth true` | `false` | 启用网页登录认证 |
| `-store true` | `false` | 启用数据持久化存储 |
| `-allowed-hosts <列表>` | 空 | 逗号分隔的 SSH 目标主机白名单，支持 `*` / `?` / `[...]` 通配符 |
| `-workdir <目录>` | 当前目录 | 切换进程工作目录（不存在则创建） |

环境变量：`PORT`、`AUTH`、`STORE`、`ALLOWED_HOSTS`、`WORK_DIR`，优先级高于命令行参数。
布尔值解析规则与 Go 版相同：`true` / `1` / `yes`（不区分大小写、去空白）为真。

```bash
./webssh                                  # 无认证、无存储
./webssh -port 9000                       # 自定义端口
./webssh -auth true                       # 首次访问自动跳转 /setup
./webssh -store true                      # 保存主题/字体/SSH 配置
./webssh -auth true -store true -port 8080
```

## 与 Go 版一致的关键行为

- **认证**：`/setup` 首次设置账户（bcrypt cost=10，密码至少 8 位且含大小写字母与数字）；`/login` 失败 5 次锁定 15 分钟；会话 token 为 32 字节随机 hex、有效期 24 小时、持久化到 `data/webssh.redb` 的 `sessions` 表，Cookie `HttpOnly` + `SameSite=Strict` + `Max-Age=86400`。
- **requireAuth**：认证开启且未初始化时跳转 `/setup`；`/api/*` 与 `/ws` 未登录返回 401，页面跳转 `/login`；认证开启时 WebSocket 严格校验 `Origin` 同源。
- **存储**：`data/secret.key`（0600）保存 32 字节密钥；敏感字段用 AES-256-GCM 加密后以 `enc:` + hex 存放于 redb；`/api/ssh` 的 GET 只返回 `has_password` / `has_key` / `has_passphrase` 安全视图。
- **SSH**：支持密码与私钥（可带口令）认证；`xterm-256color` PTY 120×40，终端模式 `ECHO=1, ISPEED/OSPEED=14400`；TOFU 主机密钥校验写入 `data/known_hosts`，指纹变化返回含 `host key mismatch` 的错误供前端弹出信任确认框。
- **WebSocket 协议**：首条 JSON 为连接参数（`host/port/username/password/private_key/passphrase` 或 `profile_id`），随后 `{"type":"input","data":...}` / `{"type":"resize","rows":..,"cols":..}`；服务端返回 `connected` / `output` / `error` / `closed`。

## 编译

需要 **Rust ≥ 1.90**（redb 4.5 的 MSRV）。

```bash
# 本地（glibc 动态链接）
cargo build --release

# 本地（musl 静态链接，需要 musl-tools）
rustup target add x86_64-unknown-linux-musl
cargo build --release --target x86_64-unknown-linux-musl
```

### GitHub Actions 自动构建

两个 workflow 分别产出 **完全静态的 musl 二进制**：

| Workflow | Target | 产物 |
|----------|--------|------|
| `build-linux-amd64-musl.yml` | `x86_64-unknown-linux-musl` | `webssh-linux-amd64-musl` |
| `build-linux-arm64-musl.yml` | `aarch64-unknown-linux-musl` | `webssh-linux-arm64-musl` |

触发方式：推送 `v*` 标签，或在 Actions 页面手动 `workflow_dispatch`。
两者都借助 `cross` 的 Docker 镜像提供 musl 交叉工具链（cross 使用宿主 `stable` 工具链，满足 redb 的 1.90 MSRV），构建后用 `readelf` 校验无 `PT_INTERP`（确认纯静态），再上传为 Actions Artifact。

产物可直接运行（无需任何系统库）：

```bash
chmod +x webssh-linux-amd64-musl
./webssh-linux-amd64-musl -port 8888
```

## data 目录

启用 `-auth` 或 `-store` 后在工作目录下创建：

```
data/
├── webssh.redb   # redb 单文件数据库（0600）
├── secret.key    # 加密密钥（-store 时，0600）
└── known_hosts   # TOFU 主机公钥（0600）
```

`webssh.redb` 内含五张表，值全部为 redb 原生类型（无 JSON 序列化）：

| 表 | 键 | 值 |
|----|----|----|
| `auth` | `username` / `password_hash` | 账户名、bcrypt 哈希 |
| `settings` | 字段名 | 字符串（`font_size` 存十进制） |
| `sessions` | token | `(username, expires_at RFC3339)` |
| `profiles` | id | 9 元组：`name / host / port / username / password / private_key / passphrase / auth_type / created_at` |
| `profile_order` | 插入序号 | id（保证列表顺序与 Go 版 slice 一致） |

redb 提供 ACID 事务与崩溃安全，取代 Go 版 `RWMutex` + 逐个 JSON 文件的写入。**不做旧版迁移**：旧的 `auth.json` / `settings.json` / `ssh.json` / `sessions.json` 不会被读取，如需保留请先备份再删除。
