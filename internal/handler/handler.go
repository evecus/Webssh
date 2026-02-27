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

var upgrader = websocket.Upgrader{
	ReadBufferSize:  4096,
	WriteBufferSize: 4096,
	CheckOrigin:     func(r *http.Request) bool { return true },
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

// sessionsFilePath 返回会话持久化文件路径（仅auth模式下使用）
func sessionsFilePath() string {
	return store.DataDir + "/sessions.json"
}

// loadSessionsFromDisk 从文件恢复会话（程序启动时调用）
func loadSessionsFromDisk() {
	data, err := os.ReadFile(sessionsFilePath())
	if err != nil {
		return // 文件不存在则跳过
	}
	var saved map[string]*session
	if err := json.Unmarshal(data, &saved); err != nil {
		return
	}
	now := time.Now()
	sessionsMu.Lock()
	defer sessionsMu.Unlock()
	for token, s := range saved {
		if now.Before(s.ExpiresAt) { // 只恢复未过期的
			sessions[token] = s
		}
	}
}

// saveSessionsToDisk 将当前有效会话写入文件
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
	os.WriteFile(sessionsFilePath(), data, 0600) //nolint:errcheck
}

func newSession(username string) string {
	b := make([]byte, 24)
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

	// 启动时从磁盘恢复未过期会话
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
		http.Error(w, "Template error: "+err.Error(), 500)
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
		if len(password) < 1 {
			data["Error"] = "密码不能为空"
			a.renderPage(w, setupHTMLTemplate, data)
			return
		}

		hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			data["Error"] = "系统错误，请重试"
			a.renderPage(w, setupHTMLTemplate, data)
			return
		}

		if err := store.SaveAuth(&store.AuthData{
			Username:     username,
			PasswordHash: string(hash),
		}); err != nil {
			data["Error"] = "保存失败: " + err.Error()
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
		username := strings.TrimSpace(r.FormValue("username"))
		password := r.FormValue("password")

		authData, err := store.LoadAuth()
		if err != nil || authData.Username != username ||
			bcrypt.CompareHashAndPassword([]byte(authData.PasswordHash), []byte(password)) != nil {
			data["Error"] = "用户名或密码错误"
			a.renderPage(w, loginHTMLTemplate, data)
			return
		}

		token := newSession(username)
		http.SetCookie(w, &http.Cookie{
			Name:     "wssh_session",
			Value:    token,
			Path:     "/",
			HttpOnly: true,
			MaxAge:   86400,
			SameSite: http.SameSiteLaxMode,
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
		profiles, _ := store.LoadSSHProfiles()
		json.NewEncoder(w).Encode(profiles)
	case http.MethodPost:
		var p store.SSHProfile
		if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
			http.Error(w, "invalid json", 400)
			return
		}
		profiles, err := store.SaveSSHProfile(p)
		if err != nil {
			http.Error(w, err.Error(), 500)
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
			http.Error(w, err.Error(), 500)
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

	cfg := sshtunnel.Config{
		Host:       msg.Host,
		Port:       msg.Port,
		Username:   msg.Username,
		Password:   msg.Password,
		PrivateKey: []byte(msg.PrivateKey),
		Passphrase: []byte(msg.Passphrase),
	}

	sshSession, err := sshtunnel.Connect(cfg)
	if err != nil {
		wsc.writeJSON(map[string]string{"type": "error", "data": err.Error()})
		return
	}
	defer sshSession.Close()

	wsc.writeJSON(map[string]string{"type": "connected"})

	outCh := make(chan []byte, 128)
	errCh := make(chan error, 2)
	sshSession.ReadLoop(outCh, errCh)

	// wsMsgCh 接收来自浏览器的WebSocket消息，独立goroutine阻塞读取
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
		// SSH输出 → 浏览器
		case data, ok := <-outCh:
			if !ok {
				return
			}
			if err := wsc.writeJSON(map[string]string{"type": "output", "data": string(data)}); err != nil {
				return
			}

		// SSH会话结束
		case sshErr := <-errCh:
			if sshErr != nil {
				wsc.writeJSON(map[string]string{"type": "error", "data": sshErr.Error()})
			} else {
				wsc.writeJSON(map[string]string{"type": "closed"})
			}
			return

		// 浏览器输入 → SSH
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
