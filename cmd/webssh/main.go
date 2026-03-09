package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/yourusername/webssh/internal/handler"
	sshtunnel "github.com/yourusername/webssh/internal/ssh"
	"github.com/yourusername/webssh/internal/store"
)

func main() {
	portFlag := flag.Int("port", 8888, "HTTP server port")
	authFlag := flag.String("auth", "false", "Enable authentication (true/false)")
	storeFlag := flag.String("store", "false", "Enable data storage (true/false)")
	// 修复问题7：添加白名单参数，限制可连接的目标主机
	allowedHostsFlag := flag.String("allowed-hosts", "", "Comma-separated list of allowed SSH target hosts (empty = allow all, e.g. '10.0.0.*,myserver.com')")
	flag.Parse()

	// Resolve port (env overrides flag)
	port := *portFlag
	if v := os.Getenv("PORT"); v != "" {
		if p, err := strconv.Atoi(v); err == nil {
			port = p
		}
	}

	// Resolve auth
	authEnabled := parseBool(*authFlag)
	if v := os.Getenv("AUTH"); v != "" {
		authEnabled = parseBool(v)
	}

	// Resolve store
	storeEnabled := parseBool(*storeFlag)
	if v := os.Getenv("STORE"); v != "" {
		storeEnabled = parseBool(v)
	}

	// 修复问题3：若未启用认证，打印明确安全警告（而非静默允许）
	if !authEnabled {
		log.Println("⚠️  WARNING: Authentication is DISABLED. Anyone with network access can use this service.")
		log.Println("   Start with -auth=true to enable authentication.")
	}

	// 注入白名单到 SSH 包（修复问题7）
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
	} else {
		log.Println("ℹ️  No SSH host whitelist configured. All targets are allowed.")
	}

	// Create data directory when store or auth is enabled
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
	log.Printf("WebSSH Console started → http://0.0.0.0%s  (auth=%v, store=%v)", addr, authEnabled, storeEnabled)
	if authEnabled && !store.AuthExists() {
		log.Printf("⚠  AUTH mode: No credentials found. Visit http://localhost%s/setup to create your account.", addr)
	}

	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatal(err)
	}
}

func parseBool(s string) bool {
	s = strings.ToLower(strings.TrimSpace(s))
	return s == "true" || s == "1" || s == "yes"
}
