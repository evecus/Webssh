package ssh

import (
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// AllowedHosts 若非空，则限制可连接的目标主机白名单（逗号分隔，支持通配符）
// 由外部（main.go）注入，空代表不限制
var AllowedHosts []string

const knownHostsFile = "data/known_hosts"

var khMu sync.Mutex

// isHostAllowed 检查目标 host 是否在白名单内；白名单为空时放行
func isHostAllowed(host string) bool {
	if len(AllowedHosts) == 0 {
		return true
	}
	for _, pattern := range AllowedHosts {
		matched, err := filepath.Match(pattern, host)
		if err == nil && matched {
			return true
		}
		if pattern == host {
			return true
		}
	}
	return false
}

func ensureKnownHostsFile() error {
	if err := os.MkdirAll(filepath.Dir(knownHostsFile), 0750); err != nil {
		return err
	}
	f, err := os.OpenFile(knownHostsFile, os.O_CREATE|os.O_APPEND, 0600)
	if err != nil {
		return err
	}
	return f.Close()
}

// tofuHostKeyCallback 实现 TOFU（Trust On First Use）策略：
// 首次连接记录指纹；后续连接严格校验，指纹变化则拒绝（防MITM）
func tofuHostKeyCallback(hostname string, remote net.Addr, key ssh.PublicKey) error {
	khMu.Lock()
	defer khMu.Unlock()

	if err := ensureKnownHostsFile(); err != nil {
		return fmt.Errorf("failed to ensure known_hosts: %w", err)
	}

	checkCb, err := knownhosts.New(knownHostsFile)
	if err != nil {
		return fmt.Errorf("failed to load known_hosts: %w", err)
	}

	err = checkCb(hostname, remote, key)
	if err == nil {
		return nil // 已知且匹配
	}

	var keyErr *knownhosts.KeyError
	if ke, ok := err.(*knownhosts.KeyError); ok {
		keyErr = ke
	}

	if keyErr != nil && len(keyErr.Want) == 0 {
		// 首次连接 —— 追加记录（TOFU）
		line := knownhosts.Line([]string{hostname}, key)
		f, werr := os.OpenFile(knownHostsFile, os.O_APPEND|os.O_WRONLY, 0600)
		if werr != nil {
			return fmt.Errorf("failed to write known_hosts: %w", werr)
		}
		defer f.Close()
		if _, werr = fmt.Fprintln(f, line); werr != nil {
			return fmt.Errorf("failed to append known_hosts: %w", werr)
		}
		return nil
	}

	// 指纹不匹配 —— 拒绝（可能是 MITM）
	return fmt.Errorf("SSH host key mismatch for %s: possible MITM attack. "+
		"If the host key legitimately changed, remove its entry from data/known_hosts", hostname)
}

// RemoveKnownHost 从 known_hosts 删除指定 hostname 的记录（主机密钥更换时使用）
func RemoveKnownHost(hostname string) error {
	khMu.Lock()
	defer khMu.Unlock()
	data, err := os.ReadFile(knownHostsFile)
	if err != nil {
		return err
	}
	var kept []byte
	for len(data) > 0 {
		var line []byte
		i := 0
		for i < len(data) && data[i] != '\n' {
			i++
		}
		line = data[:i]
		if i < len(data) {
			data = data[i+1:]
		} else {
			data = data[i:]
		}
		if len(line) == 0 || line[0] == '#' {
			kept = append(kept, line...)
			kept = append(kept, '\n')
			continue
		}
		hosts, _, _, _, parseErr := ssh.ParseKnownHosts(line)
		if parseErr != nil {
			kept = append(kept, line...)
			kept = append(kept, '\n')
			continue
		}
		match := false
		for _, h := range hosts {
			if h == hostname {
				match = true
				break
			}
		}
		if !match {
			kept = append(kept, line...)
			kept = append(kept, '\n')
		}
	}
	return os.WriteFile(knownHostsFile, kept, 0600)
}

type Config struct {
	Host       string
	Port       int
	Username   string
	Password   string
	PrivateKey []byte
	Passphrase []byte
}

type Session struct {
	client  *ssh.Client
	session *ssh.Session
	stdin   io.WriteCloser
	stdout  io.Reader
	stderr  io.Reader
}

func Connect(cfg Config) (*Session, error) {
	// 白名单检查（防止服务器被用作跳板/SSRF）
	if !isHostAllowed(cfg.Host) {
		return nil, fmt.Errorf("host %q is not in the allowed hosts list", cfg.Host)
	}

	authMethods := []ssh.AuthMethod{}

	if len(cfg.PrivateKey) > 0 {
		var signer ssh.Signer
		var err error
		if len(cfg.Passphrase) > 0 {
			signer, err = ssh.ParsePrivateKeyWithPassphrase(cfg.PrivateKey, cfg.Passphrase)
		} else {
			signer, err = ssh.ParsePrivateKey(cfg.PrivateKey)
		}
		if err != nil {
			return nil, fmt.Errorf("failed to parse private key: %w", err)
		}
		authMethods = append(authMethods, ssh.PublicKeys(signer))
	}

	if cfg.Password != "" {
		authMethods = append(authMethods, ssh.Password(cfg.Password))
	}

	if len(authMethods) == 0 {
		return nil, fmt.Errorf("no authentication method provided")
	}

	clientConfig := &ssh.ClientConfig{
		User:            cfg.Username,
		Auth:            authMethods,
		HostKeyCallback: tofuHostKeyCallback,
		Timeout:         15 * time.Second,
	}

	addr := fmt.Sprintf("%s:%d", cfg.Host, cfg.Port)
	client, err := ssh.Dial("tcp", addr, clientConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to connect: %w", err)
	}

	session, err := client.NewSession()
	if err != nil {
		client.Close()
		return nil, fmt.Errorf("failed to create session: %w", err)
	}

	modes := ssh.TerminalModes{
		ssh.ECHO:          1,
		ssh.TTY_OP_ISPEED: 14400,
		ssh.TTY_OP_OSPEED: 14400,
	}

	if err := session.RequestPty("xterm-256color", 40, 120, modes); err != nil {
		session.Close()
		client.Close()
		return nil, fmt.Errorf("failed to request pty: %w", err)
	}

	stdin, err := session.StdinPipe()
	if err != nil {
		session.Close()
		client.Close()
		return nil, fmt.Errorf("failed to get stdin: %w", err)
	}

	stdout, err := session.StdoutPipe()
	if err != nil {
		session.Close()
		client.Close()
		return nil, fmt.Errorf("failed to get stdout: %w", err)
	}

	stderr, err := session.StderrPipe()
	if err != nil {
		session.Close()
		client.Close()
		return nil, fmt.Errorf("failed to get stderr: %w", err)
	}

	if err := session.Shell(); err != nil {
		session.Close()
		client.Close()
		return nil, fmt.Errorf("failed to start shell: %w", err)
	}

	return &Session{
		client:  client,
		session: session,
		stdin:   stdin,
		stdout:  stdout,
		stderr:  stderr,
	}, nil
}

func (s *Session) Write(data []byte) (int, error) {
	return s.stdin.Write(data)
}

func (s *Session) Resize(rows, cols uint32) error {
	return s.session.WindowChange(int(rows), int(cols))
}

func (s *Session) ReadLoop(outCh chan<- []byte, errCh chan<- error) {
	go func() {
		buf := make([]byte, 32*1024)
		for {
			n, err := s.stdout.Read(buf)
			if n > 0 {
				data := make([]byte, n)
				copy(data, buf[:n])
				outCh <- data
			}
			if err != nil {
				if err != io.EOF {
					errCh <- err
				} else {
					errCh <- nil
				}
				return
			}
		}
	}()

	go func() {
		buf := make([]byte, 32*1024)
		for {
			n, err := s.stderr.Read(buf)
			if n > 0 {
				data := make([]byte, n)
				copy(data, buf[:n])
				outCh <- data
			}
			if err != nil {
				return
			}
		}
	}()
}

func (s *Session) Close() {
	if s.session != nil {
		s.session.Close()
	}
	if s.client != nil {
		s.client.Close()
	}
}

// Ping checks if host is reachable
func Ping(host string, port int) error {
	if !isHostAllowed(host) {
		return fmt.Errorf("host %q is not allowed", host)
	}
	addr := fmt.Sprintf("%s:%d", host, port)
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return err
	}
	conn.Close()
	return nil
}
