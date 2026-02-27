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
	"github.com/yourusername/webssh/internal/store"
)

func main() {
	portFlag := flag.Int("port", 8888, "HTTP server port")
	authFlag := flag.String("auth", "false", "Enable authentication (true/false)")
	storeFlag := flag.String("store", "false", "Enable data storage (true/false)")
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

	// Create data directory when store or auth is enabled
	if storeEnabled || authEnabled {
		if err := store.EnsureDataDir(); err != nil {
			log.Fatalf("Failed to create data directory: %v", err)
		}
		// 加载或生成加密密钥（用于保护SSH敏感字段）
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

