package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/yourusername/webssh/internal/handler"
	sshtunnel "github.com/yourusername/webssh/internal/ssh"
	"github.com/yourusername/webssh/internal/store"
)

func main() {
	// --- 1. 定义参数 ---
	portFlag := flag.Int("port", 8888, "HTTP server port")
	authFlag := flag.String("auth", "false", "Enable authentication (true/false)")
	storeFlag := flag.String("store", "false", "Enable data storage (true/false)")
	allowedHostsFlag := flag.String("allowed-hosts", "", "Comma-separated list of allowed SSH target hosts")
	// 新增 workdir 参数
	workDirFlag := flag.String("workdir", "", "Set the working directory (default is current directory)")
	
	flag.Parse()

	// --- 2. 处理工作目录切换 (核心修改) ---
	setupWorkDir(*workDirFlag)

	// --- 3. 后续逻辑 (保持原样，但路径已生效) ---
	port := *portFlag
	if v := os.Getenv("PORT"); v != "" {
		if p, err := strconv.Atoi(v); err == nil {
			port = p
		}
	}

	authEnabled := parseBool(*authFlag)
	if v := os.Getenv("AUTH"); v != "" {
		authEnabled = parseBool(v)
	}

	storeEnabled := parseBool(*storeFlag)
	if v := os.Getenv("STORE"); v != "" {
		storeEnabled = parseBool(v)
	}

	if !authEnabled {
		log.Println("⚠️  WARNING: Authentication is DISABLED.")
	}

	if v := os.Getenv("ALLOWED_HOSTS"); v != "" {
		*allowedHostsFlag = v
	}
	if *allowedHostsFlag != "" {
		parts := strings.Split(*allowedHostsFlag, ",")
		for _, p := range parts {
			p = strings.TrimSpace(p)
			if p != "" {
				sshtunnel.AllowedHosts = append(sshtunnel.AllowedHosts, p)
			}
		}
		log.Printf("SSH target whitelist: %v", sshtunnel.AllowedHosts)
	}

	// 此时 store.EnsureDataDir() 会在新的 workdir 下创建目录
	if storeEnabled || authEnabled {
		if err := store.EnsureDataDir(); err != nil {
			log.Fatalf("Failed to create data directory: %v", err)
		}
		if storeEnabled {
			if err := store.LoadOrCreateEncryptionKey(); err != nil {
				log.Fatalf("Failed to initialize encryption key: %v", err)
			}
		}
	}

	cfg := handler.AppConfig{
		AuthEnabled:  authEnabled,
		StoreEnabled: storeEnabled,
	}

	mux := http.NewServeMux()
	handler.Register(mux, cfg)

	addr := fmt.Sprintf(":%d", port)
	log.Printf("WebSSH Console started on %s", addr)

	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatal(err)
	}
}

// setupWorkDir 处理目录切换逻辑
func setupWorkDir(path string) {
	if path == "" {
		// 如果没传参数，尝试看环境变量有没有指定
		path = os.Getenv("WORK_DIR")
	}

	if path != "" {
		absPath, err := filepath.Abs(path)
		if err != nil {
			log.Fatalf("❌ Failed to resolve absolute path for %s: %v", path, err)
		}

		// 检查目录是否存在，不存在则尝试创建
		if _, err := os.Stat(absPath); os.IsNotExist(err) {
			log.Printf("Creating working directory: %s", absPath)
			if err := os.MkdirAll(absPath, 0755); err != nil {
				log.Fatalf("❌ Failed to create workdir: %v", err)
			}
		}

		// 切换进程工作目录
		if err := os.Chdir(absPath); err != nil {
			log.Fatalf("❌ Failed to change working directory to %s: %v", absPath, err)
		}
		log.Printf("✅ Working directory set to: %s", absPath)
	}
}

func parseBool(s string) bool {
	s = strings.ToLower(strings.TrimSpace(s))
	return s == "true" || s == "1" || s == "yes"
}
