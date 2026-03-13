package main

import (
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"time"
	"strconv"
	"strings"
	"syscall"

	"github.com/sprawl/clauth/internal/broker"
)

// version is set at build time via -ldflags.
var version = "dev"

// multiUint32 implements flag.Value for a repeatable --admin-uid flag.
type multiUint32 []uint32

func (m *multiUint32) String() string {
	parts := make([]string, len(*m))
	for i, v := range *m {
		parts[i] = fmt.Sprintf("%d", v)
	}
	return strings.Join(parts, ",")
}

func (m *multiUint32) Set(s string) error {
	v, err := strconv.ParseUint(s, 10, 32)
	if err != nil {
		return fmt.Errorf("invalid UID %q: %w", s, err)
	}
	*m = append(*m, uint32(v))
	return nil
}

func main() {
	var (
		policyPath     = flag.String("policy", envOrDefault("CLAUTH_POLICY", "/etc/clauth/policy.yaml"), "path to policy YAML file")
		signerSocket   = flag.String("signer-socket", envOrDefault("CLAUTH_SIGNER_SOCKET", "/run/clauth/signer.sock"), "path to signer IPC socket")
		listenSocket   = flag.String("listen", envOrDefault("CLAUTH_LISTEN", "/run/clauth/broker.sock"), "path for broker Unix socket")
		auditLogPath   = flag.String("audit-log", envOrDefault("CLAUTH_AUDIT_LOG", "/var/log/clauth/audit.json"), "path to audit log file")
		dashboardListen = flag.String("dashboard-listen", envOrDefault("CLAUTH_DASHBOARD_LISTEN", ":8553"), "TCP address for dashboard listener")
		dashboardToken  = flag.String("dashboard-token", envOrDefault("CLAUTH_DASHBOARD_TOKEN", ""), "API token for dashboard (auto-generated if empty)")
		socketGroup     = flag.String("socket-group", envOrDefault("CLAUTH_SOCKET_GROUP", "clauth-agents"), "Group for broker socket ownership")
		dashboardDir    = flag.String("dashboard-dir", envOrDefault("CLAUTH_DASHBOARD_DIR", "/opt/clauth/dashboard"), "directory for static dashboard files")
		mcpListen       = flag.String("mcp-listen", envOrDefault("CLAUTH_MCP_LISTEN", ":8554"), "TCP address for MCP listener")
		showVersion    = flag.Bool("version", false, "print version and exit")
	)

	var adminUIDs multiUint32
	// Parse default admin UIDs from environment.
	if envAdmins := os.Getenv("CLAUTH_ADMIN_UIDS"); envAdmins != "" {
		for _, s := range strings.Split(envAdmins, ",") {
			s = strings.TrimSpace(s)
			if s == "" {
				continue
			}
			if err := adminUIDs.Set(s); err != nil {
				log.Fatalf("invalid CLAUTH_ADMIN_UIDS value: %v", err)
			}
		}
	}
	flag.Var(&adminUIDs, "admin-uid", "UID allowed admin operations (can be repeated)")
	flag.Parse()

	if *showVersion {
		fmt.Printf("clauth-broker %s\n", version)
		os.Exit(0)
	}

	// Default admin UID is 0 (root) if none specified.
	if len(adminUIDs) == 0 {
		adminUIDs = append(adminUIDs, 0)
	}

	// Auto-generate dashboard token if not provided.
	if *dashboardToken == "" {
		b := make([]byte, 24)
		if _, err := rand.Read(b); err != nil {
			log.Fatalf("[broker] failed to generate dashboard token: %v", err)
		}
		*dashboardToken = hex.EncodeToString(b)
	}

	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds)
	log.Printf("[broker] clauth-broker %s starting", version)
	log.Printf("[broker] policy:    %s", *policyPath)
	log.Printf("[broker] signer:    %s", *signerSocket)
	log.Printf("[broker] listen:    %s", *listenSocket)
	log.Printf("[broker] audit:     %s", *auditLogPath)
	log.Printf("[broker] admins:    %s", adminUIDs.String())
	log.Printf("[broker] dashboard: %s", *dashboardListen)
	log.Printf("[broker] dashboard token: %s...%s", (*dashboardToken)[:4], (*dashboardToken)[len(*dashboardToken)-4:])
	log.Printf("[broker] dashboard dir:   %s", *dashboardDir)
	log.Printf("[broker] mcp:           %s", *mcpListen)

	// Parse auth cache TTL. Default 60s, set to "0" to disable.
	var authCacheTTL time.Duration
	if v := os.Getenv("CLAUTH_AUTH_CACHE_TTL"); v != "" {
		if v == "0" || v == "off" || v == "false" {
			authCacheTTL = -1 // sentinel: explicitly disabled
		} else {
			d, err := time.ParseDuration(v)
			if err != nil {
				log.Fatalf("invalid CLAUTH_AUTH_CACHE_TTL: %v", err)
			}
			authCacheTTL = d
		}
	}

	cfg := broker.BrokerConfig{
		PolicyPath:     *policyPath,
		SignerSocket:   *signerSocket,
		ListenSocket:   *listenSocket,
		AuditLogPath:   *auditLogPath,
		AdminUIDs:      adminUIDs,
		DashboardAddr:  *dashboardListen,
		DashboardToken: *dashboardToken,
		DashboardDir:   *dashboardDir,
		SocketGroup:    *socketGroup,
		MCPAddr:        *mcpListen,
		AuthCacheTTL:   authCacheTTL,
	}

	srv, err := broker.NewBrokerServer(cfg)
	if err != nil {
		log.Fatalf("[broker] failed to initialize: %v", err)
	}

	// Set up SIGHUP handler for policy reload.
	go func() {
		hupCh := make(chan os.Signal, 1)
		signal.Notify(hupCh, syscall.SIGHUP)
		for range hupCh {
			log.Printf("[broker] received SIGHUP, reloading policy...")
			if err := srv.ReloadPolicy(); err != nil {
				log.Printf("[broker] policy reload failed: %v", err)
			}
		}
	}()

	// Start graceful shutdown handler in background.
	go srv.GracefulShutdown()

	// Start serving (blocks until shutdown).
	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("[broker] server error: %v", err)
	}
}

// envOrDefault returns the environment variable value if set, otherwise the default.
func envOrDefault(key, defaultVal string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return defaultVal
}
