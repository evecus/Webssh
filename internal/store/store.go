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

// encryptionKey 用于加密SSH敏感字段（密码/私钥/passphrase）
// 从 data/secret.key 文件读取或自动生成
var encryptionKey []byte

// LoadOrCreateEncryptionKey 从文件加载或创建加密密钥
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
	// 生成新的32字节随机key
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

// encrypt 使用AES-GCM加密明文，返回 "enc:" 前缀的hex编码密文
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

// decrypt 解密 encrypt() 产生的密文；若不是加密格式则原样返回（兼容旧数据）
func decrypt(ciphertext string) (string, error) {
	const prefix = "enc:"
	if len(ciphertext) < len(prefix) || ciphertext[:len(prefix)] != prefix {
		return ciphertext, nil // 旧数据明文兼容
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

// generateID 使用 crypto/rand 生成唯一ID，杜绝时间戳碰撞
func generateID() string {
	b := make([]byte, 8)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		h := sha256.Sum256([]byte(time.Now().String()))
		return hex.EncodeToString(h[:8])
	}
	return time.Now().Format("20060102150405") + hex.EncodeToString(b)
}

// AuthData stores hashed credentials
type AuthData struct {
	Username     string `json:"username"`
	PasswordHash string `json:"password_hash"`
}

// SSHProfile stores an SSH connection profile
type SSHProfile struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Host       string `json:"host"`
	Port       int    `json:"port"`
	Username   string `json:"username"`
	Password   string `json:"password,omitempty"`
	PrivateKey string `json:"private_key,omitempty"`
	Passphrase string `json:"passphrase,omitempty"`
	AuthType   string `json:"auth_type"` // "password" or "key"
	CreatedAt  string `json:"created_at"`
}

// Settings stores UI preferences
type Settings struct {
	Theme    string `json:"theme"`
	UIFont   string `json:"ui_font"`
	TermFont string `json:"term_font"`
	TermBg   string `json:"term_bg"`   // 终端背景主题，如 "dark","dracula","solarized"...
	FontSize int    `json:"font_size"` // 终端字号，如 12,13,14,16,18
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

func SaveAuth(a *AuthData) error {
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
	// 给旧数据补默认值
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

// LoadSSHProfilesRaw 读取原始（加密状态）的profiles，内部使用
func LoadSSHProfilesRaw() ([]SSHProfile, error) {
	var profiles []SSHProfile
	if err := readJSON("ssh.json", &profiles); err != nil {
		return []SSHProfile{}, nil
	}
	return profiles, nil
}

// LoadSSHProfiles 读取并解密所有profiles，供外部调用
func LoadSSHProfiles() ([]SSHProfile, error) {
	profiles, err := LoadSSHProfilesRaw()
	if err != nil {
		return nil, err
	}
	return decryptProfiles(profiles), nil
}

// decryptProfiles 解密一批profiles中的敏感字段（返回副本，不修改原数据）
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

func SaveSSHProfile(p SSHProfile) ([]SSHProfile, error) {
	// 加密敏感字段
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
	// Check if updating existing
	for i, existing := range profiles {
		if existing.ID == p.ID {
			profiles[i] = p
			return decryptProfiles(profiles), writeJSON("ssh.json", profiles)
		}
	}
	if p.ID == "" {
		p.ID = generateID()
	}
	p.CreatedAt = time.Now().Format(time.RFC3339)
	profiles = append(profiles, p)
	return decryptProfiles(profiles), writeJSON("ssh.json", profiles)
}

func DeleteSSHProfile(id string) ([]SSHProfile, error) {
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
	return decryptProfiles(updated), writeJSON("ssh.json", updated)
}


