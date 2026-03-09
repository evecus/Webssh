package store

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const DataDir = "data"

var mu sync.RWMutex

// setupMu 专用于 setup 阶段，防止并发竞态写入 auth.json（修复问题10）
var setupMu sync.Mutex

var encryptionKey []byte

func LoadOrCreateEncryptionKey() error {
	keyPath := filepath.Join(DataDir, "secret.key")
	data, err := os.ReadFile(keyPath)
	if err == nil && len(data) == 64 {
		key, err := hex.DecodeString(string(data))
		if err == nil && len(key) == 32 {
			encryptionKey = key
			return nil
		}
	}
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return err
	}
	encoded := hex.EncodeToString(key)
	if err := os.WriteFile(keyPath, []byte(encoded), 0600); err != nil {
		return err
	}
	encryptionKey = key
	return nil
}

func encrypt(plaintext string) (string, error) {
	if plaintext == "" || encryptionKey == nil {
		return plaintext, nil
	}
	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return "enc:" + hex.EncodeToString(ciphertext), nil
}

func decrypt(ciphertext string) (string, error) {
	const prefix = "enc:"
	if len(ciphertext) < len(prefix) || ciphertext[:len(prefix)] != prefix {
		return ciphertext, nil
	}
	if encryptionKey == nil {
		return "", errors.New("encryption key not loaded")
	}
	data, err := hex.DecodeString(ciphertext[len(prefix):])
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return "", errors.New("ciphertext too short")
	}
	plaintext, err := gcm.Open(nil, data[:nonceSize], data[nonceSize:], nil)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}

func generateID() string {
	b := make([]byte, 8)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		h := sha256.Sum256([]byte(time.Now().String()))
		return hex.EncodeToString(h[:8])
	}
	return time.Now().Format("20060102150405") + hex.EncodeToString(b)
}

type AuthData struct {
	Username     string `json:"username"`
	PasswordHash string `json:"password_hash"`
}

// SSHProfile stores an SSH connection profile.
// Password/PrivateKey/Passphrase fields are NEVER sent to the client in plaintext.
// The API returns a masked version via SSHProfileSafe.
type SSHProfile struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Host       string `json:"host"`
	Port       int    `json:"port"`
	Username   string `json:"username"`
	Password   string `json:"password,omitempty"`
	PrivateKey string `json:"private_key,omitempty"`
	Passphrase string `json:"passphrase,omitempty"`
	AuthType   string `json:"auth_type"`
	CreatedAt  string `json:"created_at"`
}

// SSHProfileSafe 是对外 API 安全视图：敏感字段仅用布尔标志表示是否已设置（修复问题12）
type SSHProfileSafe struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Host        string `json:"host"`
	Port        int    `json:"port"`
	Username    string `json:"username"`
	AuthType    string `json:"auth_type"`
	HasPassword bool   `json:"has_password"`
	HasKey      bool   `json:"has_key"`
	HasPassphrase bool  `json:"has_passphrase"`
	CreatedAt   string `json:"created_at"`
}

// ToSafe 将 SSHProfile 转为安全视图（不含明文凭证）
func (p SSHProfile) ToSafe() SSHProfileSafe {
	return SSHProfileSafe{
		ID:            p.ID,
		Name:          p.Name,
		Host:          p.Host,
		Port:          p.Port,
		Username:      p.Username,
		AuthType:      p.AuthType,
		HasPassword:   p.Password != "",
		HasKey:        p.PrivateKey != "",
		HasPassphrase: p.Passphrase != "",
		CreatedAt:     p.CreatedAt,
	}
}

type Settings struct {
	Theme    string `json:"theme"`
	UIFont   string `json:"ui_font"`
	TermFont string `json:"term_font"`
	TermBg   string `json:"term_bg"`
	FontSize int    `json:"font_size"`
	Lang     string `json:"lang"`
}

func EnsureDataDir() error {
	return os.MkdirAll(DataDir, 0750)
}

func filePath(name string) string {
	return filepath.Join(DataDir, name)
}

func readJSON(name string, v interface{}) error {
	mu.RLock()
	defer mu.RUnlock()
	data, err := os.ReadFile(filePath(name))
	if err != nil {
		return err
	}
	return json.Unmarshal(data, v)
}

func writeJSON(name string, v interface{}) error {
	mu.Lock()
	defer mu.Unlock()
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filePath(name), data, 0640)
}

// ---- Auth ----

func LoadAuth() (*AuthData, error) {
	var a AuthData
	if err := readJSON("auth.json", &a); err != nil {
		return nil, err
	}
	return &a, nil
}

// SaveAuth 使用专用互斥锁，防止 setup 阶段并发写入竞态（修复问题10）
func SaveAuth(a *AuthData) error {
	setupMu.Lock()
	defer setupMu.Unlock()
	// 再次检查：防止在等待锁期间已被写入
	if _, err := os.Stat(filePath("auth.json")); err == nil {
		return errors.New("auth already initialized")
	}
	return writeJSON("auth.json", a)
}

func AuthExists() bool {
	_, err := os.Stat(filePath("auth.json"))
	return err == nil
}

// ---- Settings ----

func LoadSettings() (*Settings, error) {
	var s Settings
	if err := readJSON("settings.json", &s); err != nil {
		return &Settings{
			Theme:    "purple-pink",
			UIFont:   "'Outfit','Noto Sans SC',sans-serif",
			TermFont: "'JetBrains Mono',monospace",
			TermBg:   "dark",
			FontSize: 14,
			Lang:     "zh",
		}, nil
	}
	if s.TermBg == "" {
		s.TermBg = "dark"
	}
	if s.FontSize == 0 {
		s.FontSize = 14
	}
	return &s, nil
}

func SaveSettings(s *Settings) error {
	return writeJSON("settings.json", s)
}

// ---- SSH Profiles ----

func LoadSSHProfilesRaw() ([]SSHProfile, error) {
	var profiles []SSHProfile
	if err := readJSON("ssh.json", &profiles); err != nil {
		return []SSHProfile{}, nil
	}
	return profiles, nil
}

// LoadSSHProfiles 读取并解密，返回完整的 SSHProfile（内部使用，如连接时取凭证）
func LoadSSHProfiles() ([]SSHProfile, error) {
	profiles, err := LoadSSHProfilesRaw()
	if err != nil {
		return nil, err
	}
	return decryptProfiles(profiles), nil
}

// LoadSSHProfilesSafe 返回安全视图列表，不含任何明文凭证（供 API 对外使用，修复问题12）
func LoadSSHProfilesSafe() ([]SSHProfileSafe, error) {
	profiles, err := LoadSSHProfilesRaw()
	if err != nil {
		return nil, err
	}
	// 解密以判断字段是否有值（注意：解密后的值不对外暴露）
	decrypted := decryptProfiles(profiles)
	result := make([]SSHProfileSafe, len(decrypted))
	for i, p := range decrypted {
		result[i] = p.ToSafe()
	}
	return result, nil
}

func decryptProfiles(raw []SSHProfile) []SSHProfile {
	result := make([]SSHProfile, len(raw))
	for i, p := range raw {
		p.Password, _ = decrypt(p.Password)
		p.PrivateKey, _ = decrypt(p.PrivateKey)
		p.Passphrase, _ = decrypt(p.Passphrase)
		result[i] = p
	}
	return result
}

func SaveSSHProfile(p SSHProfile) ([]SSHProfileSafe, error) {
	var err error
	if p.Password, err = encrypt(p.Password); err != nil {
		return nil, err
	}
	if p.PrivateKey, err = encrypt(p.PrivateKey); err != nil {
		return nil, err
	}
	if p.Passphrase, err = encrypt(p.Passphrase); err != nil {
		return nil, err
	}

	profiles, _ := LoadSSHProfilesRaw()
	for i, existing := range profiles {
		if existing.ID == p.ID {
			// 若客户端未传敏感字段（空），则保留原有加密值
			if p.Password == "" {
				p.Password = existing.Password
			}
			if p.PrivateKey == "" {
				p.PrivateKey = existing.PrivateKey
			}
			if p.Passphrase == "" {
				p.Passphrase = existing.Passphrase
			}
			profiles[i] = p
			if err := writeJSON("ssh.json", profiles); err != nil {
				return nil, err
			}
			return safeList(profiles), nil
		}
	}
	if p.ID == "" {
		p.ID = generateID()
	}
	p.CreatedAt = time.Now().Format(time.RFC3339)
	profiles = append(profiles, p)
	if err := writeJSON("ssh.json", profiles); err != nil {
		return nil, err
	}
	return safeList(profiles), nil
}

func DeleteSSHProfile(id string) ([]SSHProfileSafe, error) {
	profiles, _ := LoadSSHProfilesRaw()
	var updated []SSHProfile
	for _, p := range profiles {
		if p.ID != id {
			updated = append(updated, p)
		}
	}
	if updated == nil {
		updated = []SSHProfile{}
	}
	if err := writeJSON("ssh.json", updated); err != nil {
		return nil, err
	}
	return safeList(updated), nil
}

// safeList 将加密存储的 profiles 转为安全视图列表
func safeList(raw []SSHProfile) []SSHProfileSafe {
	decrypted := decryptProfiles(raw)
	result := make([]SSHProfileSafe, len(decrypted))
	for i, p := range decrypted {
		result[i] = p.ToSafe()
	}
	return result
}
