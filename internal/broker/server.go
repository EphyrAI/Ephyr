package broker

import (
	"bufio"
	"encoding/json"
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/sprawl/clauth/internal/audit"
	"github.com/sprawl/clauth/internal/auth"
	"github.com/sprawl/clauth/internal/policy"
	"github.com/sprawl/clauth/internal/signer"
)

// BrokerConfig holds all configuration for the broker server.
type BrokerConfig struct {
	PolicyPath     string   // path to policy YAML file
	SignerSocket   string   // path to signer IPC Unix socket
	ListenSocket   string   // path for the broker's own Unix socket
	AuditLogPath   string   // path to the audit log file
	AdminUIDs      []uint32 // UIDs allowed admin operations
	SocketGroup    string   // group name for broker socket (e.g. "clauth-agents")
	DashboardAddr  string   // TCP address for dashboard listener (e.g. ":8553")
	DashboardToken string   // API token for dashboard authentication
	DashboardDir   string   // directory for serving static dashboard files
	MCPAddr        string   // TCP address for MCP listener (e.g. ":8554")
}

// BrokerServer is the central broker service that ties together policy
// evaluation, signer IPC, session management, and certificate state.
type BrokerServer struct {
	cfg        BrokerConfig
	listener   net.Listener
	httpServer *http.Server

	// Dashboard TCP listener and HTTP server.
	dashboardListener net.Listener
	dashboardHTTP     *http.Server

	// Policy engine and loader (guarded by policyMu for hot-reloading).
	policyMu     sync.RWMutex
	policyLoader *policy.Loader
	policyCfg    *policy.ResolvedConfig
	policyEngine *policy.Engine

	// Signer IPC client.
	signerClient *signer.Client

	// Session manager.
	sessions *auth.SessionManager

	// Certificate and pending-request state.
	state *CertState

	// Rate limiter.
	limiter *rateLimiter

	// Audit logger.
	auditLog *audit.AuditLogger

	// Admin UIDs for authorization checks.
	adminUIDs []uint32

	// Server start time for uptime reporting.
	startTime time.Time

	// WebSocket event hub for real-time dashboard events.
	eventHub *EventHub

	// Host access controller for per-host enable/disable toggles.
	hostCtl *HostController

	configMgr *ConfigManager
	mcpServer *MCPServer
	activityStore *ActivityStore
	proxyEngine   *ProxyEngine
	// Counters for granted and denied certificate requests (atomic).
	grantCount uint64
	denyCount  uint64
}

// NewBrokerServer initializes all components and returns a ready-to-start server.
func NewBrokerServer(cfg BrokerConfig) (*BrokerServer, error) {
	// Apply defaults.
	if cfg.ListenSocket == "" {
		cfg.ListenSocket = "/run/clauth/broker.sock"
	}
	if cfg.SignerSocket == "" {
		cfg.SignerSocket = "/run/clauth/signer.sock"
	}
	if cfg.PolicyPath == "" {
		cfg.PolicyPath = "/etc/clauth/policy.yaml"
	}
	if cfg.AuditLogPath == "" {
		cfg.AuditLogPath = "/var/log/clauth/audit.json"
	}

	// Load policy.
	loader, resolved, err := policy.LoadFromFile(cfg.PolicyPath)
	if err != nil {
		return nil, fmt.Errorf("broker: load policy: %w", err)
	}
	engine := policy.NewEngine(loader, resolved)

	// Initialize signer client.
	signerClient := signer.NewClient(cfg.SignerSocket)

	// Ensure audit log directory exists.
	auditDir := filepath.Dir(cfg.AuditLogPath)
	if err := os.MkdirAll(auditDir, 0750); err != nil {
		return nil, fmt.Errorf("broker: create audit log dir %s: %w", auditDir, err)
	}

	// Initialize audit logger.
	auditLogger, err := audit.NewLogger(cfg.AuditLogPath, true)
	if err != nil {
		return nil, fmt.Errorf("broker: init audit logger: %w", err)
	}

	// Configure rate limiter from policy.
	rawCfg := resolved.Raw
	rl := newRateLimiter(
		rawCfg.Global.RateLimit.RequestsPerWindow,
		rawCfg.Global.RateLimit.WindowSeconds,
	)

	bs := &BrokerServer{
		cfg:          cfg,
		policyLoader: loader,
		policyCfg:    resolved,
		policyEngine: engine,
		signerClient: signerClient,
		sessions:     auth.NewSessionManager(),
		state:        NewCertState(),
		limiter:      rl,
		auditLog:     auditLogger,
		adminUIDs:    cfg.AdminUIDs,
		startTime:    time.Now(),
		eventHub:     NewEventHub(),
		hostCtl:      NewHostController(),
		configMgr:    NewConfigManager("/var/lib/clauth/hosts.json"),
	}

	// Seed host configs from policy targets.
	policyTargets := make(map[string]policyTarget)
	for name, t := range resolved.Raw.Targets {
		policyTargets[name] = policyTarget{
			Host:         t.Host,
			Port:         t.Port,
			VLAN:         t.VLAN,
			AllowedRoles: t.AllowedRoles,
			MaxTTL:       t.MaxTTL,
			AutoApprove:  t.AutoApprove,
			Description:  t.Description,
		}
	}
	bs.configMgr.InitFromPolicy(policyTargets)

	// Initialize activity store (10000 entry ring buffer).
	bs.activityStore = NewActivityStore(10000)

	return bs, nil
}

// ListenAndServe starts the broker HTTP server on the configured Unix socket.
// It also starts the TCP dashboard listener if configured.
// It blocks until the server is shut down.
func (bs *BrokerServer) ListenAndServe() error {
	// Ensure the socket directory exists.
	socketDir := filepath.Dir(bs.cfg.ListenSocket)
	if err := os.MkdirAll(socketDir, 0755); err != nil {
		return fmt.Errorf("broker: create socket dir %s: %w", socketDir, err)
	}

	// Remove any stale socket file.
	os.Remove(bs.cfg.ListenSocket)

	// Create the Unix listener.
	listener, err := net.Listen("unix", bs.cfg.ListenSocket)
	if err != nil {
		return fmt.Errorf("broker: listen on %s: %w", bs.cfg.ListenSocket, err)
	}
	bs.listener = listener

	// Set socket permissions: owner=clauth-broker, group=clauth-agents (or configured group).
	if err := os.Chmod(bs.cfg.ListenSocket, 0660); err != nil {
		listener.Close()
		return fmt.Errorf("broker: chmod socket: %w", err)
	}
	if bs.cfg.SocketGroup != "" {
		if gid, err := lookupGroupID(bs.cfg.SocketGroup); err == nil {
			if err := os.Chown(bs.cfg.ListenSocket, -1, gid); err != nil {
				log.Printf("[broker] warning: chown socket to group %s: %v", bs.cfg.SocketGroup, err)
			}
		} else {
			log.Printf("[broker] warning: lookup group %s: %v", bs.cfg.SocketGroup, err)
		}
	}

	// Build HTTP mux with all routes.
	mux := bs.routes()

	// Wrap with rate limiter.
	handler := RateLimitMiddleware(bs.limiter, mux)

	bs.httpServer = &http.Server{
		Handler: handler,
		// ConnContext injects peer credentials into every request's context.
		ConnContext: bs.connContext,
	}

	bs.auditLog.LogEvent(audit.AuditEvent{
		Severity:  audit.SeverityInfo,
		EventType: audit.EventStartup,
		Details: map[string]string{
			"listen":    bs.cfg.ListenSocket,
			"policy":    bs.cfg.PolicyPath,
			"signer":    bs.cfg.SignerSocket,
			"dashboard": bs.cfg.DashboardAddr,
		},
	})

	log.Printf("[broker] listening on %s", bs.cfg.ListenSocket)

	// Start dashboard TCP listener in a goroutine.
	if bs.cfg.DashboardAddr != "" {
		go bs.startDashboardListener()
	}

	if bs.cfg.MCPAddr != "" {
		go bs.startMCPListener()
	}

	// Serve (blocks until shutdown).
	if err := bs.httpServer.Serve(listener); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("broker: serve: %w", err)
	}

	return nil
}

// connContext is the http.Server.ConnContext function. It extracts SO_PEERCRED
// from the Unix socket connection and stores the caller's UID in the context.
func (bs *BrokerServer) connContext(ctx context.Context, conn net.Conn) context.Context {
	uid, _, err := auth.GetPeerCred(conn)
	if err != nil {
		log.Printf("[broker] warning: failed to get peer credentials: %v", err)
		return ctx
	}
	return withUID(ctx, uid)
}

// routes builds the HTTP routing table using Go 1.22+ enhanced patterns.
func (bs *BrokerServer) routes() *http.ServeMux {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /v1/health", bs.handleHealth)
	mux.HandleFunc("POST /v1/session", bs.handleCreateSession)
	mux.HandleFunc("GET /v1/session", bs.handleGetSession)
	mux.HandleFunc("POST /v1/request", bs.handleRequest)
	mux.HandleFunc("GET /v1/certs", bs.handleListCerts)
	mux.HandleFunc("DELETE /v1/certs/{serial}", bs.handleRevokeCert)
	mux.HandleFunc("GET /v1/targets", bs.handleListTargets)
	mux.HandleFunc("POST /v1/approve/{request_id}", bs.handleApprove)
	mux.HandleFunc("POST /v1/deny/{request_id}", bs.handleDeny)
	mux.HandleFunc("POST /v1/admin/hosts/{name}/toggle", bs.handleAdminToggleHost)

	return mux
}

// GracefulShutdown sets up signal handlers for SIGTERM and SIGINT and
// performs a clean shutdown when triggered. This method blocks.
func (bs *BrokerServer) GracefulShutdown() {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)

	sig := <-sigCh
	log.Printf("[broker] received %s, shutting down...", sig)

	bs.auditLog.LogEvent(audit.AuditEvent{
		Severity:  audit.SeverityInfo,
		EventType: audit.EventShutdown,
		Details:   map[string]string{"signal": sig.String()},
	})

	// Give in-flight requests 5 seconds to complete.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := bs.httpServer.Shutdown(ctx); err != nil {
		log.Printf("[broker] shutdown error: %v", err)
	}

	// Shut down dashboard listener if running.
	if bs.dashboardHTTP != nil {
		dCtx, dCancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer dCancel()
		if err := bs.dashboardHTTP.Shutdown(dCtx); err != nil {
			log.Printf("[dashboard] shutdown error: %v", err)
		}
	}

	bs.state.Stop()
	bs.auditLog.Close()

	// Clean up socket.
	os.Remove(bs.cfg.ListenSocket)

	log.Printf("[broker] shutdown complete")
}

// ReloadPolicy loads the policy file from disk and swaps the engine atomically.
// This is called on SIGHUP.
func (bs *BrokerServer) ReloadPolicy() error {
	newResolved, err := bs.policyLoader.Reload()
	if err != nil {
		return fmt.Errorf("broker: reload policy: %w", err)
	}
	newEngine := policy.NewEngine(bs.policyLoader, newResolved)

	bs.policyMu.Lock()
	bs.policyCfg = newResolved
	bs.policyEngine = newEngine
	bs.policyMu.Unlock()

	// Update rate limiter with new config.
	rawCfg := newResolved.Raw
	bs.limiter = newRateLimiter(
		rawCfg.Global.RateLimit.RequestsPerWindow,
		rawCfg.Global.RateLimit.WindowSeconds,
	)

	bs.auditLog.LogEvent(audit.AuditEvent{
		Severity:  audit.SeverityInfo,
		EventType: audit.EventPolicyReload,
		Details:   map[string]string{"path": bs.cfg.PolicyPath},
	})

	log.Printf("[broker] policy reloaded from %s", bs.cfg.PolicyPath)
	return nil
}

// startMCPListener starts the TCP HTTP server for the MCP endpoint on
// the configured MCPAddr. It is called from ListenAndServe as a goroutine.
func (bs *BrokerServer) startMCPListener() {
	if bs.cfg.MCPAddr == "" {
		return
	}

	listener, err := net.Listen("tcp", bs.cfg.MCPAddr)
	if err != nil {
		log.Printf("[mcp] failed to listen on %s: %v", bs.cfg.MCPAddr, err)
		return
	}

	// Build authenticator from policy.
	auth := NewMCPAuthenticator()
	bs.policyMu.RLock()
	for name, agent := range bs.policyCfg.Raw.Agents {
		if agent.APIKeyHash == "" {
			continue
		}
		// Get allowed roles: union of all target allowed_roles.
		var roles []string
		roleSet := make(map[string]bool)
		for _, t := range bs.policyCfg.Raw.Targets {
			for _, r := range t.AllowedRoles {
				if !roleSet[r] {
					roleSet[r] = true
					roles = append(roles, r)
				}
			}
		}
		auth.AddAgent(MCPAgentConfig{
			Name:          name,
			APIKeyHash:    agent.APIKeyHash,
			Roles:         roles,
			MaxConcurrent: agent.MaxConcurrentCerts,
			AutoApprove:   true,
		})
	}
	bs.policyMu.RUnlock()

	mcpSrv := NewMCPServer(bs, auth)
	pool := NewExecSessionPool(bs, 5)
	mcpSrv.SetExecPool(pool)

	// Initialize proxy engine.
	proxyPolicy := DefaultNetworkPolicy
	// Load network policy overrides from services config dir.
	npPath := "/var/lib/clauth/network_policy.json"
	if npData, err := os.ReadFile(npPath); err == nil {
		var np NetworkPolicy
		if err := json.Unmarshal(npData, &np); err == nil {
			proxyPolicy = &np
			log.Printf("[mcp] loaded network policy from %s (external=%s, %d allow patterns)", npPath, np.External, len(np.ExternalAllow))
		} else {
			log.Printf("[mcp] warning: failed to parse %s: %v, using defaults", npPath, err)
		}
	}
	proxyEngine := NewProxyEngine(bs, "/var/lib/clauth/services.json", proxyPolicy)
	mcpSrv.SetProxyEngine(proxyEngine)
	bs.proxyEngine = proxyEngine

	bs.mcpServer = mcpSrv

	mux := http.NewServeMux()
	mux.HandleFunc("POST /mcp", mcpSrv.ServeHTTP)
	// SSE placeholder for server-to-client notifications.
	mux.HandleFunc("GET /mcp", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	server := &http.Server{Handler: mux}

	log.Printf("[mcp] listening on %s", bs.cfg.MCPAddr)

	bs.auditLog.LogEvent(audit.AuditEvent{
		Severity:  audit.SeverityInfo,
		EventType: "mcp_started",
		Details:   map[string]string{"listen": bs.cfg.MCPAddr},
	})

	if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
		log.Printf("[mcp] server error: %v", err)
	}
}

// lookupGroupID resolves a group name to its numeric GID by parsing /etc/group.
func lookupGroupID(name string) (int, error) {
	f, err := os.Open("/etc/group")
	if err != nil {
		return 0, err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		parts := strings.SplitN(scanner.Text(), ":", 4)
		if len(parts) >= 3 && parts[0] == name {
			gid, err := strconv.Atoi(parts[2])
			if err != nil {
				return 0, fmt.Errorf("invalid gid for %s: %w", name, err)
			}
			return gid, nil
		}
	}
	return 0, fmt.Errorf("group %q not found", name)
}
