package handler

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"html/template"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/gorilla/websocket"
	"golang.org/x/crypto/bcrypt"

	"github.com/yourusername/webssh/internal/store"
	sshtunnel "github.com/yourusername/webssh/internal/ssh"
)

// AppConfig holds runtime feature flags
type AppConfig struct {
	AuthEnabled  bool
	StoreEnabled bool
}

// ---- WebSocket Upgrader（修复问题2：严格 Origin 校验，防止 CSRF） ----

func makeUpgrader(cfg AppConfig) websocket.Upgrader {
	return websocket.Upgrader{
		ReadBufferSize:  4096,
		WriteBufferSize: 4096,
		CheckOrigin: func(r *http.Request) bool {
			if !cfg.AuthEnabled {
				return true // 无认证模式下放行（依赖网络层隔离）
			}
			origin := r.Header.Get("Origin")
			if origin == "" {
				return false
			}
			// 只允许与当前服务器同源
			host := r.Host
			return origin == "http://"+host || origin == "https://"+host
		},
	}
}

// ---- 登录频率限制（修复问题4：防止暴力破解） ----

type loginAttempt struct {
	count     int
	firstAt   time.Time
	lockedUntil time.Time
}

const (
	maxLoginAttempts  = 5               // 窗口内最大失败次数
	attemptWindow     = 5 * time.Minute // 计数窗口
	lockoutDuration   = 15 * time.Minute // 锁定时长
)

var (
	loginAttempts   = map[string]*loginAttempt{}
	loginAttemptsMu sync.Mutex
)

// getClientIP 提取客户端 IP
func getClientIP(r *http.Request) string {
	if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
		parts := strings.Split(fwd, ",")
		return strings.TrimSpace(parts[0])
	}
	ip := r.RemoteAddr
	if i := strings.LastIndex(ip, ":"); i != -1 {
		ip = ip[:i]
	}
	return ip
}

// checkLoginRateLimit 返回 (允许, 剩余等待秒数)
func checkLoginRateLimit(ip string) (bool, int) {
	loginAttemptsMu.Lock()
	defer loginAttemptsMu.Unlock()

	now := time.Now()
	a, ok := loginAttempts[ip]
	if !ok {
		return true, 0
	}

	// 在锁定期内
	if now.Before(a.lockedUntil) {
		remaining := int(a.lockedUntil.Sub(now).Seconds()) + 1
		return false, remaining
	}

	// 窗口已过期，重置
	if now.Sub(a.firstAt) > attemptWindow {
		delete(loginAttempts, ip)
		return true, 0
	}

	return a.count < maxLoginAttempts, 0
}

// recordLoginFailure 记录一次失败
func recordLoginFailure(ip string) {
	loginAttemptsMu.Lock()
	defer loginAttemptsMu.Unlock()

	now := time.Now()
	a, ok := loginAttempts[ip]
	if !ok || now.Sub(a.firstAt) > attemptWindow {
		loginAttempts[ip] = &loginAttempt{count: 1, firstAt: now}
		return
	}
	a.count++
	if a.count >= maxLoginAttempts {
		a.lockedUntil = now.Add(lockoutDuration)
	}
}

// resetLoginFailure 登录成功后清除记录
func resetLoginFailure(ip string) {
	loginAttemptsMu.Lock()
	defer loginAttemptsMu.Unlock()
	delete(loginAttempts, ip)
}

// ---- 密码强度校验（修复问题6） ----

const minPasswordLength = 8

func validatePasswordStrength(password string) string {
	if len(password) < minPasswordLength {
		return "密码长度至少 8 位"
	}
	var hasUpper, hasLower, hasDigit bool
	for _, c := range password {
		switch {
		case unicode.IsUpper(c):
			hasUpper = true
		case unicode.IsLower(c):
			hasLower = true
		case unicode.IsDigit(c):
			hasDigit = true
		}
	}
	if !hasUpper || !hasLower || !hasDigit {
		return "密码须包含大写字母、小写字母和数字"
	}
	return ""
}

// ---- Session Management ----

type session struct {
	Username  string    `json:"username"`
	ExpiresAt time.Time `json:"expires_at"`
}

var (
	sessions   = map[string]*session{}
	sessionsMu sync.RWMutex
)

func sessionsFilePath() string {
	return store.DataDir + "/sessions.json"
}

func loadSessionsFromDisk() {
	data, err := os.ReadFile(sessionsFilePath())
	if err != nil {
		return
	}
	var saved map[string]*session
	if err := json.Unmarshal(data, &saved); err != nil {
		return
	}
	now := time.Now()
	sessionsMu.Lock()
	defer sessionsMu.Unlock()
	for token, s := range saved {
		if now.Before(s.ExpiresAt) {
			sessions[token] = s
		}
	}
}

func saveSessionsToDisk() {
	sessionsMu.RLock()
	snapshot := make(map[string]*session, len(sessions))
	now := time.Now()
	for token, s := range sessions {
		if now.Before(s.ExpiresAt) {
			snapshot[token] = s
		}
	}
	sessionsMu.RUnlock()

	data, err := json.MarshalIndent(snapshot, "", "  ")
	if err != nil {
		return
	}
	// 修复问题5：使用严格权限 0600 写文件
	os.WriteFile(sessionsFilePath(), data, 0600) //nolint:errcheck
}

func newSession(username string) string {
	b := make([]byte, 32) // 增加 token 长度（256 bit 熵）
	rand.Read(b)
	token := hex.EncodeToString(b)
	sessionsMu.Lock()
	sessions[token] = &session{Username: username, ExpiresAt: time.Now().Add(24 * time.Hour)}
	sessionsMu.Unlock()
	saveSessionsToDisk()
	return token
}

func getSession(r *http.Request) *session {
	c, err := r.Cookie("wssh_session")
	if err != nil {
		return nil
	}
	sessionsMu.RLock()
	s := sessions[c.Value]
	sessionsMu.RUnlock()
	if s == nil || time.Now().After(s.ExpiresAt) {
		return nil
	}
	return s
}

func deleteSession(token string) {
	sessionsMu.Lock()
	delete(sessions, token)
	sessionsMu.Unlock()
	saveSessionsToDisk()
}

// ---- Register Routes ----

func Register(mux *http.ServeMux, cfg AppConfig) {
	h := &appHandler{cfg: cfg}

	if cfg.AuthEnabled {
		loadSessionsFromDisk()
	}

	mux.HandleFunc("/setup", h.setupHandler)
	mux.HandleFunc("/login", h.loginHandler)
	mux.HandleFunc("/logout", h.logoutHandler)
	mux.HandleFunc("/api/settings", h.requireAuth(h.settingsAPIHandler))
	mux.HandleFunc("/api/ssh", h.requireAuth(h.sshProfilesAPIHandler))
	mux.HandleFunc("/ws", h.requireAuth(h.wsHandler))
	mux.HandleFunc("/", h.requireAuth(h.indexHandler))
}

type appHandler struct {
	cfg AppConfig
}

func (a *appHandler) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !a.cfg.AuthEnabled {
			next(w, r)
			return
		}
		if !store.AuthExists() {
			if r.URL.Path != "/setup" {
				http.Redirect(w, r, "/setup", http.StatusFound)
				return
			}
			next(w, r)
			return
		}
		if getSession(r) == nil {
			if strings.HasPrefix(r.URL.Path, "/api/") || r.URL.Path == "/ws" {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		next(w, r)
	}
}

type pageConfig struct {
	StoreEnabled bool
	AuthEnabled  bool
}

func (a *appHandler) renderPage(w http.ResponseWriter, tmplStr string, data interface{}) {
	tmpl, err := template.New("page").Parse(tmplStr)
	if err != nil {
		http.Error(w, "Template error", 500) // 修复问题9：不暴露内部错误详情
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := tmpl.Execute(w, data); err != nil {
		log.Printf("template render error: %v", err)
	}
}

func (a *appHandler) indexHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	a.renderPage(w, indexHTMLTemplate, pageConfig{
		StoreEnabled: a.cfg.StoreEnabled,
		AuthEnabled:  a.cfg.AuthEnabled,
	})
}

func (a *appHandler) setupHandler(w http.ResponseWriter, r *http.Request) {
	if !a.cfg.AuthEnabled {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	if store.AuthExists() {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	data := map[string]interface{}{"Error": ""}

	if r.Method == http.MethodPost {
		username := strings.TrimSpace(r.FormValue("username"))
		password := r.FormValue("password")
		confirm := r.FormValue("confirm")

		if username == "" || password == "" {
			data["Error"] = "用户名和密码不能为空"
			a.renderPage(w, setupHTMLTemplate, data)
			return
		}
		if password != confirm {
			data["Error"] = "两次密码输入不一致"
			a.renderPage(w, setupHTMLTemplate, data)
			return
		}

		// 修复问题6：密码强度校验
		if msg := validatePasswordStrength(password); msg != "" {
			data["Error"] = msg
			a.renderPage(w, setupHTMLTemplate, data)
			return
		}

		hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			data["Error"] = "系统错误，请重试" // 修复问题9：不暴露内部错误
			a.renderPage(w, setupHTMLTemplate, data)
			return
		}

		// 修复问题10：SaveAuth 内部使用互斥锁防止并发竞态
		if err := store.SaveAuth(&store.AuthData{
			Username:     username,
			PasswordHash: string(hash),
		}); err != nil {
			if err.Error() == "auth already initialized" {
				http.Redirect(w, r, "/login", http.StatusFound)
				return
			}
			data["Error"] = "保存失败，请重试" // 修复问题9：不暴露内部错误
			a.renderPage(w, setupHTMLTemplate, data)
			return
		}

		http.Redirect(w, r, "/login?setup=ok", http.StatusFound)
		return
	}

	a.renderPage(w, setupHTMLTemplate, data)
}

func (a *appHandler) loginHandler(w http.ResponseWriter, r *http.Request) {
	if !a.cfg.AuthEnabled {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	if !store.AuthExists() {
		http.Redirect(w, r, "/setup", http.StatusFound)
		return
	}
	if getSession(r) != nil {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	data := map[string]interface{}{
		"Error":   "",
		"Success": r.URL.Query().Get("setup") == "ok",
	}

	if r.Method == http.MethodPost {
		ip := getClientIP(r)

		// 修复问题4：检查频率限制
		allowed, waitSec := checkLoginRateLimit(ip)
		if !allowed {
			if waitSec > 0 {
				data["Error"] = "登录失败次数过多，请稍后再试"
			} else {
				data["Error"] = "请求过于频繁，请稍后再试"
			}
			a.renderPage(w, loginHTMLTemplate, data)
			return
		}

		username := strings.TrimSpace(r.FormValue("username"))
		password := r.FormValue("password")

		authData, err := store.LoadAuth()
		if err != nil || authData.Username != username ||
			bcrypt.CompareHashAndPassword([]byte(authData.PasswordHash), []byte(password)) != nil {
			recordLoginFailure(ip) // 记录失败
			data["Error"] = "用户名或密码错误"
			a.renderPage(w, loginHTMLTemplate, data)
			return
		}

		resetLoginFailure(ip) // 登录成功，清除失败记录

		token := newSession(username)
		http.SetCookie(w, &http.Cookie{
			Name:     "wssh_session",
			Value:    token,
			Path:     "/",
			HttpOnly: true,
			MaxAge:   86400,
			SameSite: http.SameSiteStrictMode, // 修复问题2+11：Lax -> Strict
			// Secure 由 HTTPS 层控制；若强制 HTTPS 可设为 true
		})
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	a.renderPage(w, loginHTMLTemplate, data)
}

func (a *appHandler) logoutHandler(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie("wssh_session"); err == nil {
		deleteSession(c.Value)
	}
	http.SetCookie(w, &http.Cookie{Name: "wssh_session", Value: "", Path: "/", MaxAge: -1})
	http.Redirect(w, r, "/login", http.StatusFound)
}

func (a *appHandler) settingsAPIHandler(w http.ResponseWriter, r *http.Request) {
	if !a.cfg.StoreEnabled {
		http.Error(w, "Store not enabled", http.StatusForbidden)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	switch r.Method {
	case http.MethodGet:
		s, _ := store.LoadSettings()
		json.NewEncoder(w).Encode(s)
	case http.MethodPost:
		var s store.Settings
		if err := json.NewDecoder(r.Body).Decode(&s); err != nil {
			http.Error(w, "invalid json", 400)
			return
		}
		store.SaveSettings(&s)
		json.NewEncoder(w).Encode(s)
	default:
		http.Error(w, "method not allowed", 405)
	}
}

func (a *appHandler) sshProfilesAPIHandler(w http.ResponseWriter, r *http.Request) {
	if !a.cfg.StoreEnabled {
		http.Error(w, "Store not enabled", http.StatusForbidden)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	switch r.Method {
	case http.MethodGet:
		// 修复问题12：返回安全视图，不含明文凭证
		profiles, _ := store.LoadSSHProfilesSafe()
		json.NewEncoder(w).Encode(profiles)
	case http.MethodPost:
		var p store.SSHProfile
		if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
			http.Error(w, "invalid json", 400)
			return
		}
		profiles, err := store.SaveSSHProfile(p)
		if err != nil {
			http.Error(w, "internal error", 500) // 修复问题9：不暴露内部错误
			return
		}
		json.NewEncoder(w).Encode(profiles)
	case http.MethodDelete:
		id := r.URL.Query().Get("id")
		if id == "" {
			http.Error(w, "missing id", 400)
			return
		}
		profiles, err := store.DeleteSSHProfile(id)
		if err != nil {
			http.Error(w, "internal error", 500)
			return
		}
		json.NewEncoder(w).Encode(profiles)
	default:
		http.Error(w, "method not allowed", 405)
	}
}

// ---- WebSocket ----

type Message struct {
	Type       string `json:"type"`
	Data       string `json:"data,omitempty"`
	Host       string `json:"host,omitempty"`
	Port       int    `json:"port,omitempty"`
	Username   string `json:"username,omitempty"`
	Password   string `json:"password,omitempty"`
	PrivateKey string `json:"private_key,omitempty"`
	Passphrase string `json:"passphrase,omitempty"`
	Rows       uint32 `json:"rows,omitempty"`
	Cols       uint32 `json:"cols,omitempty"`
	ProfileID  string `json:"profile_id,omitempty"` // 通过 ID 使用已存储凭证
}

type wsConn struct {
	mu sync.Mutex
	c  *websocket.Conn
}

func (w *wsConn) writeJSON(v interface{}) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.c.WriteJSON(v)
}

func (a *appHandler) wsHandler(w http.ResponseWriter, r *http.Request) {
	upgrader := makeUpgrader(a.cfg) // 修复问题2：使用严格 Origin 校验的 upgrader
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("websocket upgrade error: %v", err)
		return
	}
	defer conn.Close()

	wsc := &wsConn{c: conn}

	_, raw, err := conn.ReadMessage()
	if err != nil {
		return
	}

	var msg Message
	if err := json.Unmarshal(raw, &msg); err != nil {
		wsc.writeJSON(map[string]string{"type": "error", "data": "invalid request"})
		return
	}

	if msg.Port == 0 {
		msg.Port = 22
	}

	var sshCfg sshtunnel.Config

	// 若指定了 profile_id，从存储中取凭证（避免凭证在网络上传输）
	if msg.ProfileID != "" && a.cfg.StoreEnabled {
		profiles, err := store.LoadSSHProfiles()
		if err != nil {
			wsc.writeJSON(map[string]string{"type": "error", "data": "failed to load profiles"})
			return
		}
		found := false
		for _, p := range profiles {
			if p.ID == msg.ProfileID {
				sshCfg = sshtunnel.Config{
					Host:       p.Host,
					Port:       p.Port,
					Username:   p.Username,
					Password:   p.Password,
					PrivateKey: []byte(p.PrivateKey),
					Passphrase: []byte(p.Passphrase),
				}
				found = true
				break
			}
		}
		if !found {
			wsc.writeJSON(map[string]string{"type": "error", "data": "profile not found"})
			return
		}
	} else {
		// 直接传入凭证模式（临时连接）
		sshCfg = sshtunnel.Config{
			Host:       msg.Host,
			Port:       msg.Port,
			Username:   msg.Username,
			Password:   msg.Password,
			PrivateKey: []byte(msg.PrivateKey),
			Passphrase: []byte(msg.Passphrase),
		}
	}

	sshSession, err := sshtunnel.Connect(sshCfg)
	if err != nil {
		wsc.writeJSON(map[string]string{"type": "error", "data": err.Error()})
		return
	}
	defer sshSession.Close()

	wsc.writeJSON(map[string]string{"type": "connected"})

	outCh := make(chan []byte, 128)
	errCh := make(chan error, 2)
	sshSession.ReadLoop(outCh, errCh)

	type wsRawMsg struct {
		data []byte
		err  error
	}
	wsMsgCh := make(chan wsRawMsg, 32)
	go func() {
		for {
			_, raw, err := conn.ReadMessage()
			wsMsgCh <- wsRawMsg{data: raw, err: err}
			if err != nil {
				return
			}
		}
	}()

	for {
		select {
		case data, ok := <-outCh:
			if !ok {
				return
			}
			if err := wsc.writeJSON(map[string]string{"type": "output", "data": string(data)}); err != nil {
				return
			}

		case sshErr := <-errCh:
			if sshErr != nil {
				wsc.writeJSON(map[string]string{"type": "error", "data": sshErr.Error()})
			} else {
				wsc.writeJSON(map[string]string{"type": "closed"})
			}
			return

		case wsm := <-wsMsgCh:
			if wsm.err != nil {
				return
			}
			var wsMsg Message
			if err := json.Unmarshal(wsm.data, &wsMsg); err != nil {
				continue
			}
			switch wsMsg.Type {
			case "input":
				if _, err := sshSession.Write([]byte(wsMsg.Data)); err != nil {
					return
				}
			case "resize":
				rows, cols := wsMsg.Rows, wsMsg.Cols
				if rows == 0 {
					rows = 24
				}
				if cols == 0 {
					cols = 80
				}
				sshSession.Resize(rows, cols)
			}
		}
	}
}
