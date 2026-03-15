package broker

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"crypto/subtle"
	"github.com/EphyrAI/Ephyr/internal/audit"
)

// dashboardAuth returns middleware that validates a dashboard API token.
// Static file requests (/ and /static/) are allowed without authentication.
func dashboardAuth(token string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Allow static file serving and the root page without auth.
		if r.URL.Path == "/" || strings.HasPrefix(r.URL.Path, "/static/") {
			next.ServeHTTP(w, r)
			return
		}
		// Check token from Authorization header or query param.
		t := r.Header.Get("Authorization")
		if strings.HasPrefix(t, "Bearer ") {
			t = t[7:]
		}
		if t == "" {
			t = r.URL.Query().Get("token")
		}
		if subtle.ConstantTimeCompare([]byte(t), []byte(token)) != 1 {
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// corsMiddleware adds CORS headers for the dashboard. Instead of a wildcard
// origin, it reflects the request's Origin header so that browser-based
// credential requests (cookies, Authorization) work correctly while
// preventing arbitrary cross-origin access from sites without an Origin.
func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" {
			// Reflect the requesting origin. All dashboard access is
			// already behind token authentication, and reflecting the
			// origin (rather than using "*") ensures browsers enforce
			// credential checks properly.
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Vary", "Origin")
		}
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// DashboardSummary is the JSON response for GET /v1/dashboard/summary.
type DashboardSummary struct {
	Hostname        string `json:"hostname"`
	IP              string `json:"ip"`
	Uptime          string `json:"uptime"`
	BrokerStatus    string `json:"broker_status"`
	CAKeyStatus     string `json:"ca_key_status"`
	ActiveCerts     int    `json:"active_certs"`
	PendingRequests int    `json:"pending_requests"`
	TotalGranted    uint64 `json:"total_granted"`
	TotalDenied     uint64 `json:"total_denied"`
	AgentsActive    int    `json:"agents_active"`
	HostsOnline     int    `json:"hosts_online"`
	HostsEnabled    int    `json:"hosts_enabled"`
	SignerOK        bool   `json:"signer_ok"`
	ActiveGrants    int    `json:"active_grants,omitempty"`
	GrantMode       string `json:"grant_mode,omitempty"`
	TasksActive     int    `json:"tasks_active"`
	TasksDelegated  int    `json:"tasks_delegated"`
	TasksCreated    int64  `json:"tasks_created_total"`
	Revocations     int64  `json:"revocations_total"`
	CommandsDenied  int64  `json:"commands_denied"`
	AutoRevocations int64  `json:"auto_revocations"`
	MacaroonsMinted int64  `json:"macaroons_minted"`
}

// DashboardHost is a single host entry for GET /v1/dashboard/hosts.
type DashboardHost struct {
	Name           string   `json:"name"`
	Host           string   `json:"host"`
	VLAN           int      `json:"vlan,omitempty"`
	Status         string   `json:"status"`
	Role           string   `json:"role"`
	AccessEnabled  bool     `json:"access_enabled"`
	ActiveSessions int      `json:"active_sessions"`
	Description    string   `json:"description"`
	AllowedRoles   []string `json:"allowed_roles"`
	Port           int      `json:"port"`
	AutoApprove    bool     `json:"auto_approve"`
}

// DashboardSession is a single session entry for GET /v1/dashboard/sessions.
type DashboardSession struct {
	Serial    string `json:"serial"`
	Agent     string `json:"agent"`
	Target    string `json:"target"`
	Type      string `json:"type"`
	Role      string `json:"role"`
	Principal string `json:"principal"`
	CertTTL   int64  `json:"cert_ttl"`
	MaxTTL    int64  `json:"max_ttl"`
	IssuedAt  string `json:"issued_at"`
	ExpiresAt string `json:"expires_at"`
	Status    string `json:"status"`
}

// GrantSettings represents the settings for the access grant system.
type GrantSettings struct {
	Mode              string `json:"mode"`
	DefaultServiceTTL string `json:"default_service_ttl"`
	DefaultMCPTTL     string `json:"default_mcp_ttl"`
	ActiveGrants      int    `json:"active_grants"`
}

// dashboardWriteCheck validates whether a dashboard operation should proceed.
// Currently, all dashboard access is controlled by a single shared token
// (configured via DashboardToken). The token holder is treated as an admin.
//
// When MCP-based dashboard tools are added (allowing agents to call dashboard
// management endpoints programmatically), this function should be extended to
// check the agent's ResolvedAgentPerms.Dashboard level:
//   - DashboardNone:     deny all access
//   - DashboardViewer:   allow read-only endpoints
//   - DashboardOperator: allow toggle and revoke operations
//   - DashboardAdmin:    allow all operations including config changes
//
// TODO: Implement per-agent dashboard RBAC when dashboard management tools
// are added to the MCP server. This will require passing the agent identity
// (from MCP authentication) through to these handlers.
func dashboardWriteCheck() error {
	// All dashboard HTTP access is currently gated by the shared dashboard
	// token. The token holder has full admin privileges by definition.
	// Per-agent RBAC enforcement is deferred until MCP-based dashboard
	// access is implemented.
	return nil
}

// startDashboardListener starts the TCP HTTP server for the dashboard on
// the configured DashboardAddr. It is called from ListenAndServe as a
// goroutine.
func (bs *BrokerServer) startDashboardListener() {
	if bs.cfg.DashboardAddr == "" {
		return
	}

	mux := bs.dashboardRoutes()

	// Wrap with auth middleware (token check) then CORS.
	handler := corsMiddleware(dashboardAuth(bs.cfg.DashboardToken, mux))

	ln, err := net.Listen("tcp", bs.cfg.DashboardAddr)
	if err != nil {
		log.Printf("[dashboard] failed to listen on %s: %v", bs.cfg.DashboardAddr, err)
		return
	}
	bs.dashboardListener = ln

	bs.dashboardHTTP = &http.Server{
		Handler:      handler,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
	}

	log.Printf("[dashboard] listening on %s", bs.cfg.DashboardAddr)

	if err := bs.dashboardHTTP.Serve(ln); err != nil && err != http.ErrServerClosed {
		log.Printf("[dashboard] serve error: %v", err)
	}
}

// dashboardRoutes builds the mux for the TCP dashboard listener. It includes
// all the v1 API routes (health, certs, targets, etc.) plus dashboard-specific
// endpoints.
func (bs *BrokerServer) dashboardRoutes() *http.ServeMux {
	mux := http.NewServeMux()

	// --- Mirror all existing v1 API routes ---
	mux.HandleFunc("GET /v1/health", bs.handleHealth)
	mux.HandleFunc("GET /v1/certs", bs.handleListCerts)
	mux.HandleFunc("GET /v1/targets", bs.handleListTargets)

	// --- Dashboard-specific routes ---
	mux.HandleFunc("GET /v1/dashboard/summary", bs.handleDashboardSummary)
	mux.HandleFunc("GET /v1/dashboard/hosts", bs.handleDashboardHosts)
	mux.HandleFunc("GET /v1/dashboard/sessions", bs.handleDashboardSessions)
	mux.HandleFunc("GET /v1/dashboard/audit", bs.handleDashboardAudit)
	mux.HandleFunc("POST /v1/dashboard/hosts/{name}/toggle", bs.handleDashboardToggleHost)
	mux.HandleFunc("POST /v1/dashboard/sessions/{serial}/revoke", bs.handleDashboardRevokeSession)

	// --- WebSocket event stream ---
	mux.HandleFunc("GET /v1/events", bs.eventHub.HandleWebSocket(bs.cfg.DashboardToken))

	// --- Host configuration API ---
	mux.HandleFunc("GET /v1/dashboard/config/hosts", bs.handleGetHostConfigs)
	mux.HandleFunc("GET /v1/dashboard/config/hosts/{name}", bs.handleGetHostConfig)
	mux.HandleFunc("PUT /v1/dashboard/config/hosts/{name}", bs.handleUpdateHostConfig)
	mux.HandleFunc("DELETE /v1/dashboard/config/hosts/{name}", bs.handleDeleteHostConfig)
	mux.HandleFunc("GET /v1/dashboard/config/roles", bs.handleGetRoles)

	// --- WebSocket terminal proxy ---
	mux.HandleFunc("GET /v1/dashboard/terminal", bs.HandleTerminal)

	// --- Activity monitoring API ---
	mux.HandleFunc("GET /v1/dashboard/activity", bs.handleGetActivity)
	mux.HandleFunc("GET /v1/dashboard/activity/summary", bs.handleGetActivitySummary)
	mux.HandleFunc("GET /v1/dashboard/activity/agent/{name}", bs.handleGetAgentActivity)

	// --- Service config management (CRUD) ---
	mux.HandleFunc("GET /v1/dashboard/services", bs.handleListServices)
	mux.HandleFunc("GET /v1/dashboard/services/{name}", bs.handleGetService)
	mux.HandleFunc("PUT /v1/dashboard/services/{name}", bs.handleUpdateService)
	mux.HandleFunc("DELETE /v1/dashboard/services/{name}", bs.handleDeleteService)

	// --- Remote MCP federation CRUD ---
	mux.HandleFunc("GET /v1/dashboard/remotes", bs.handleListRemotes)
	mux.HandleFunc("GET /v1/dashboard/remotes/{name}", bs.handleGetRemote)
	mux.HandleFunc("PUT /v1/dashboard/remotes/{name}", bs.handlePutRemote)
	mux.HandleFunc("DELETE /v1/dashboard/remotes/{name}", bs.handleDeleteRemote)
	mux.HandleFunc("POST /v1/dashboard/remotes/{name}/refresh", bs.handleRefreshRemote)

	// --- Toggle endpoints ---
	mux.HandleFunc("POST /v1/dashboard/services/{name}/toggle", bs.handleToggleService)
	mux.HandleFunc("POST /v1/dashboard/remotes/{name}/toggle", bs.handleToggleRemote)

	// --- RBAC permissions ---
	mux.HandleFunc("GET /v1/dashboard/permissions", bs.handleDashboardPermissions)

	// --- Grant management ---
	mux.HandleFunc("POST /v1/dashboard/grants/{id}/revoke", bs.handleRevokeGrant)
	mux.HandleFunc("GET /v1/dashboard/settings/grants", bs.handleGetGrantSettings)
	mux.HandleFunc("PUT /v1/dashboard/settings/grants", bs.handleUpdateGrantSettings)

	// --- Task management ---
	mux.HandleFunc("GET /v1/dashboard/tasks", bs.handleDashboardTasks)
	mux.HandleFunc("GET /v1/dashboard/tasks/{id}", bs.handleDashboardTaskDetail)
	mux.HandleFunc("POST /v1/dashboard/tasks/{id}/revoke", bs.handleDashboardRevokeTask)

	// --- Metrics ---
	mux.HandleFunc("GET /v1/metrics", bs.handleMetrics)

	// --- Static file serving for the React dashboard ---
	if bs.cfg.DashboardDir != "" {
		fs := http.FileServer(http.Dir(bs.cfg.DashboardDir))
		// Wrap with no-cache headers to prevent stale dashboard
		nocache := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
			w.Header().Set("Pragma", "no-cache")
			fs.ServeHTTP(w, r)
		})
		mux.Handle("/", nocache)
	}

	return mux
}

// handleDashboardSummary serves GET /v1/dashboard/summary.
func (bs *BrokerServer) handleDashboardSummary(w http.ResponseWriter, r *http.Request) {
	signerOK := true
	caStatus := "loaded"
	if err := bs.signerClient.Ping(); err != nil {
		signerOK = false
		caStatus = "unavailable"
	}

	uptime := time.Since(bs.startTime)
	uptimeStr := formatUptime(uptime)

	// Count active agents (unique agent names with active certs).
	certs := bs.state.ListAllCerts()
	agentSet := make(map[string]struct{})
	for _, c := range certs {
		agentSet[c.AgentName] = struct{}{}
	}

	// Count hosts and enabled hosts from policy.
	bs.policyMu.RLock()
	targets := bs.policyCfg.Raw.Targets
	bs.policyMu.RUnlock()

	hostsTotal := len(targets)
	hostsEnabled := 0
	for name := range targets {
		if bs.hostCtl.IsEnabled(name) {
			hostsEnabled++
		}
	}

	hostname, _ := os.Hostname()

	// Use UDP dial to determine local IP — net.InterfaceAddrs() requires
	// AF_NETLINK which is blocked by systemd RestrictAddressFamilies.
	localIP := "127.0.0.1"
	if conn, err := net.Dial("udp", "192.168.0.1:80"); err == nil {
		localIP = conn.LocalAddr().(*net.UDPAddr).IP.String()
		conn.Close()
	}

	// Include active grants in the session and agent counts.
	grantCount := 0
	if bs.grantStore != nil {
		for _, g := range bs.grantStore.ListActive() {
			grantCount++
			agentSet[g.Agent] = struct{}{}
		}
	}

	resp := DashboardSummary{
		Hostname:        hostname,
		IP:              localIP,
		Uptime:          uptimeStr,
		BrokerStatus:    "healthy",
		CAKeyStatus:     caStatus,
		ActiveCerts:     len(certs) + grantCount,
		PendingRequests: len(bs.state.ListPending()),
		TotalGranted:    atomic.LoadUint64(&bs.grantCount),
		TotalDenied:     atomic.LoadUint64(&bs.denyCount),
		AgentsActive:    len(agentSet),
		HostsOnline:     hostsTotal,
		HostsEnabled:    hostsEnabled,
		SignerOK:        signerOK,
	}
	if bs.grantStore != nil {
		resp.ActiveGrants = bs.grantStore.ActiveCount()
		resp.GrantMode = string(bs.grantStore.Mode)
	}
	if bs.taskMgr != nil {
		resp.TasksActive = bs.taskMgr.TaskCount()
		resp.TasksDelegated = bs.taskMgr.CountDelegations()
	}
	if bs.metrics != nil {
		resp.TasksCreated = bs.metrics.TasksCreated.Load()
		resp.Revocations = bs.metrics.WatermarkRevocations.Load()
		resp.CommandsDenied = bs.metrics.CommandsDenied.Load()
		resp.AutoRevocations = bs.metrics.AutoRevocations.Load()
		resp.MacaroonsMinted = bs.metrics.MacaroonsMinted.Load()
	}
	writeJSON(w, http.StatusOK, resp)
}

// handleDashboardHosts serves GET /v1/dashboard/hosts.
func (bs *BrokerServer) handleDashboardHosts(w http.ResponseWriter, r *http.Request) {
	bs.policyMu.RLock()
	targets := bs.policyCfg.Raw.Targets
	bs.policyMu.RUnlock()

	activeCerts := bs.state.ListAllCerts()

	// Count active sessions per target.
	sessionCounts := make(map[string]int)
	for _, c := range activeCerts {
		sessionCounts[c.Target]++
	}

	hosts := make([]DashboardHost, 0, len(targets))
	for name, t := range targets {
		port := t.Port
		if port == 0 {
			port = 22
		}
		hosts = append(hosts, DashboardHost{
			Name:           name,
			Host:           t.Host,
			VLAN:           t.VLAN,
			Status:         "online",
			Role:           t.Description,
			AccessEnabled:  bs.hostCtl.IsEnabled(name),
			ActiveSessions: sessionCounts[name],
			Description:    t.Description,
			AllowedRoles:   t.AllowedRoles,
			Port:           port,
			AutoApprove:    t.AutoApprove,
		})
	}

	writeJSON(w, http.StatusOK, hosts)
}

// handleDashboardSessions serves GET /v1/dashboard/sessions.
func (bs *BrokerServer) handleDashboardSessions(w http.ResponseWriter, r *http.Request) {
	activeCerts := bs.state.ListAllCerts()

	// Look up max TTL from policy for each target.
	bs.policyMu.RLock()
	rc := bs.policyCfg
	bs.policyMu.RUnlock()

	sessions := make([]DashboardSession, 0, len(activeCerts))
	for _, c := range activeCerts {
		remaining := time.Until(c.ExpiresAt).Seconds()
		if remaining < 0 {
			remaining = 0
		}

		maxTTL := rc.GlobalMaxTTL
		if tMax, ok := rc.TargetMaxTTLs[c.Target]; ok {
			maxTTL = tMax
		}

		status := "active"
		if time.Now().After(c.ExpiresAt) {
			status = "expired"
		}

		sessions = append(sessions, DashboardSession{
			Serial:    c.Serial,
			Agent:     c.AgentName,
			Target:    c.Target,
			Type:      "ssh_cert",
			Role:      c.Role,
			Principal: c.Principal,
			CertTTL:   int64(remaining),
			MaxTTL:    int64(maxTTL.Seconds()),
			IssuedAt:  c.IssuedAt.Format(time.RFC3339),
			ExpiresAt: c.ExpiresAt.Format(time.RFC3339),
			Status:    status,
		})
	}

	// Include service and MCP grants from the grant store.
	if bs.grantStore != nil {
		for _, g := range bs.grantStore.ListAll() {
			remaining := time.Until(g.ExpiresAt).Seconds()
			if remaining < 0 {
				remaining = 0
			}
			status := "active"
			if g.Status == "revoked" {
				status = "revoked"
			} else if time.Now().After(g.ExpiresAt) {
				status = "expired"
			}

			// Determine MaxTTL based on grant type.
			var maxTTL int64
			switch g.Type {
			case GrantTypeService:
				maxTTL = int64(bs.grantStore.DefaultServiceTTL.Seconds())
			case GrantTypeMCP:
				maxTTL = int64(bs.grantStore.DefaultMCPTTL.Seconds())
			default:
				maxTTL = 300 // 5 minute fallback
			}

			ds := DashboardSession{
				Serial:    g.ID,
				Agent:     g.Agent,
				Target:    g.Target,
				Type:      string(g.Type),
				CertTTL:   int64(remaining),
				MaxTTL:    maxTTL,
				IssuedAt:  g.IssuedAt.Format(time.RFC3339),
				ExpiresAt: g.ExpiresAt.Format(time.RFC3339),
				Status:    status,
			}
			// Add role from details if available.
			if g.Details != nil {
				if role, ok := g.Details["role"]; ok {
					ds.Role = role
				}
				if authType, ok := g.Details["auth_type"]; ok {
					ds.Principal = authType
				}
			}
			sessions = append(sessions, ds)
		}
	}

	writeJSON(w, http.StatusOK, sessions)
}

// handleDashboardAudit serves GET /v1/dashboard/audit?limit=50&type=grant.
func (bs *BrokerServer) handleDashboardAudit(w http.ResponseWriter, r *http.Request) {
	limitStr := r.URL.Query().Get("limit")
	limit := 50
	if limitStr != "" {
		if v, err := strconv.Atoi(limitStr); err == nil && v > 0 {
			limit = v
		}
	}
	typeFilter := r.URL.Query().Get("type")

	// Read the audit log file.
	f, err := os.Open(bs.cfg.AuditLogPath)
	if err != nil {
		writeJSON(w, http.StatusOK, []interface{}{})
		return
	}
	defer f.Close()

	// Read all lines (audit is append-only).
	var allLines []string
	scanner := bufio.NewScanner(f)
	// Increase buffer for long lines.
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}
		allLines = append(allLines, line)
	}

	// Filter by type first, then apply limit (fixes: limit before filter
	// returned empty results for rare event types).
	var events []json.RawMessage
	// Walk backwards from newest to collect up to limit matching entries.
	for i := len(allLines) - 1; i >= 0 && len(events) < limit; i-- {
		line := allLines[i]
		if typeFilter != "" {
			var evt map[string]interface{}
			if err := json.Unmarshal([]byte(line), &evt); err != nil {
				continue
			}
			if et, ok := evt["event_type"].(string); ok {
				if !strings.Contains(et, typeFilter) {
					continue
				}
			}
		}
		events = append(events, json.RawMessage(line))
	}
	// Reverse to restore chronological order (oldest first).
	for i, j := 0, len(events)-1; i < j; i, j = i+1, j-1 {
		events[i], events[j] = events[j], events[i]
	}

	if events == nil {
		events = []json.RawMessage{}
	}

	writeJSON(w, http.StatusOK, events)
}

// handleDashboardToggleHost serves POST /v1/dashboard/hosts/{name}/toggle.
// Security: Currently protected by the shared dashboard token only.
// Dashboard RBAC level required: operator or admin (when per-agent auth is implemented).
func (bs *BrokerServer) handleDashboardToggleHost(w http.ResponseWriter, r *http.Request) {
	if err := dashboardWriteCheck(); err != nil {
		writeError(w, http.StatusForbidden, err.Error())
		return
	}
	name := r.PathValue("name")
	if name == "" {
		writeError(w, http.StatusBadRequest, "host name is required")
		return
	}

	// Verify the host exists in policy.
	bs.policyMu.RLock()
	_, exists := bs.policyCfg.Raw.Targets[name]
	bs.policyMu.RUnlock()
	if !exists {
		writeError(w, http.StatusNotFound, fmt.Sprintf("host %q not found in policy", name))
		return
	}

	newState := bs.hostCtl.Toggle(name)

	// If toggled off, revoke all active certs for this host.
	if !newState {
		certs := bs.state.ListAllCerts()
		for _, c := range certs {
			if c.Target == name {
				bs.state.RemoveCert(c.Serial)
				bs.policyEngine.RemoveCert(parseSerial(c.Serial))

				bs.auditLog.LogEvent(audit.AuditEvent{
					Severity:  audit.SeverityWarn,
					EventType: audit.EventCertRevoked,
					Agent:     c.AgentName,
					Target:    c.Target,
					Role:      c.Role,
					Serial:    c.Serial,
					Reason:    "host access disabled via dashboard",
				})

				bs.eventHub.Broadcast(Event{
					Type: "cert_revoked",
					Data: map[string]string{
						"serial": c.Serial,
						"agent":  c.AgentName,
						"target": c.Target,
						"reason": "host disabled",
					},
				})
			}
		}
	}

	stateLabel := "enabled"
	if !newState {
		stateLabel = "disabled"
	}

	bs.auditLog.LogEvent(audit.AuditEvent{
		Severity:  audit.SeverityWarn,
		EventType: "host_toggle",
		Target:    name,
		Reason:    fmt.Sprintf("Host %s %s via dashboard from %s", name, stateLabel, r.RemoteAddr),
		Details: map[string]string{
			"host":   name,
			"action": stateLabel,
		},
	})

	bs.eventHub.Broadcast(Event{
		Type: "host_toggle",
		Data: map[string]string{
			"host":  name,
			"state": stateLabel,
		},
	})

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"host":           name,
		"access_enabled": newState,
	})
}

// handleDashboardRevokeSession serves POST /v1/dashboard/sessions/{serial}/revoke.
// Security: Currently protected by the shared dashboard token only.
// Dashboard RBAC level required: operator or admin (when per-agent auth is implemented).
func (bs *BrokerServer) handleDashboardRevokeSession(w http.ResponseWriter, r *http.Request) {
	if err := dashboardWriteCheck(); err != nil {
		writeError(w, http.StatusForbidden, err.Error())
		return
	}
	serial := r.PathValue("serial")
	if serial == "" {
		writeError(w, http.StatusBadRequest, "serial is required")
		return
	}

	cert, found := bs.state.GetCert(serial)
	if !found {
		writeError(w, http.StatusNotFound, "certificate not found")
		return
	}

	bs.state.RemoveCert(serial)
	bs.policyEngine.RemoveCert(parseSerial(serial))

	bs.auditLog.LogEvent(audit.AuditEvent{
		Severity:  audit.SeverityInfo,
		EventType: audit.EventCertRevoked,
		Agent:     cert.AgentName,
		Target:    cert.Target,
		Role:      cert.Role,
		Serial:    serial,
		Reason:    "revoked via dashboard",
	})

	bs.eventHub.Broadcast(Event{
		Type: "cert_revoked",
		Data: map[string]string{
			"serial": serial,
			"agent":  cert.AgentName,
			"target": cert.Target,
			"reason": "dashboard revocation",
		},
	})

	writeJSON(w, http.StatusOK, map[string]string{
		"status": "revoked",
		"serial": serial,
	})
}

// formatUptime formats a duration into a human-readable string like "4d 7h".
func formatUptime(d time.Duration) string {
	days := int(d.Hours()) / 24
	hours := int(d.Hours()) % 24
	minutes := int(d.Minutes()) % 60

	if days > 0 {
		return fmt.Sprintf("%dd %dh", days, hours)
	}
	if hours > 0 {
		return fmt.Sprintf("%dh %dm", hours, minutes)
	}
	return fmt.Sprintf("%dm", minutes)
}

// handleListServices serves GET /v1/dashboard/services
func (bs *BrokerServer) handleListServices(w http.ResponseWriter, r *http.Request) {
	if bs.proxyEngine == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "proxy not initialized"})
		return
	}
	services := bs.proxyEngine.ListServices()
	if services == nil {
		services = []*ServiceConfig{}
	}
	writeJSON(w, http.StatusOK, services)
}

// handleGetService serves GET /v1/dashboard/services/{name}
func (bs *BrokerServer) handleGetService(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if bs.proxyEngine == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "proxy not initialized"})
		return
	}
	svc, ok := bs.proxyEngine.GetService(name)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "service not found"})
		return
	}
	writeJSON(w, http.StatusOK, svc)
}

// handleUpdateService serves PUT /v1/dashboard/services/{name}
// Security: Currently protected by the shared dashboard token only.
// Dashboard RBAC level required: admin (when per-agent auth is implemented).
func (bs *BrokerServer) handleUpdateService(w http.ResponseWriter, r *http.Request) {
	if err := dashboardWriteCheck(); err != nil {
		writeError(w, http.StatusForbidden, err.Error())
		return
	}
	name := r.PathValue("name")
	if bs.proxyEngine == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "proxy not initialized"})
		return
	}

	var svc ServiceConfig
	if err := json.NewDecoder(r.Body).Decode(&svc); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON: " + err.Error()})
		return
	}
	svc.Name = name

	if err := bs.proxyEngine.AddService(&svc); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "name": name})
}

// handleDeleteService serves DELETE /v1/dashboard/services/{name}
// Security: Currently protected by the shared dashboard token only.
// Dashboard RBAC level required: admin (when per-agent auth is implemented).
func (bs *BrokerServer) handleDeleteService(w http.ResponseWriter, r *http.Request) {
	if err := dashboardWriteCheck(); err != nil {
		writeError(w, http.StatusForbidden, err.Error())
		return
	}
	name := r.PathValue("name")
	if bs.proxyEngine == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "proxy not initialized"})
		return
	}

	if err := bs.proxyEngine.RemoveService(name); err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "name": name})
}

// handleListRemotes serves GET /v1/dashboard/remotes.
// Returns all remote MCP server configs with runtime state.
func (bs *BrokerServer) handleListRemotes(w http.ResponseWriter, r *http.Request) {
	if bs.federator == nil {
		writeJSON(w, http.StatusOK, []struct{}{})
		return
	}
	states := bs.federator.ListRemoteStates()
	if states == nil {
		states = []RemoteStateInfo{}
	}
	writeJSON(w, http.StatusOK, states)
}

// handleGetRemote serves GET /v1/dashboard/remotes/{name}.
// Returns a single remote's config with runtime state.
func (bs *BrokerServer) handleGetRemote(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if bs.federator == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "federation not configured"})
		return
	}
	state := bs.federator.GetRemoteState(name)
	if state == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "remote not found"})
		return
	}
	writeJSON(w, http.StatusOK, state)
}

// handlePutRemote serves PUT /v1/dashboard/remotes/{name}.
// Creates or updates a remote MCP server config.
// Security: Currently protected by the shared dashboard token only.
// Dashboard RBAC level required: admin (when per-agent auth is implemented).
func (bs *BrokerServer) handlePutRemote(w http.ResponseWriter, r *http.Request) {
	if err := dashboardWriteCheck(); err != nil {
		writeError(w, http.StatusForbidden, err.Error())
		return
	}
	name := r.PathValue("name")
	if bs.federator == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "federation not configured"})
		return
	}

	var cfg RemoteMCPConfig
	if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON: " + err.Error()})
		return
	}
	cfg.Name = name // enforce URL path name

	// If a remote with this name already exists, remove it first so AddRemote
	// succeeds (AddRemote rejects duplicates). This makes PUT idempotent.
	_ = bs.federator.RemoveRemote(name)

	if err := bs.federator.AddRemote(cfg); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	bs.auditLog.LogEvent(audit.AuditEvent{
		Severity:  audit.SeverityInfo,
		EventType: "remote_added",
		Target:    name,
		Details: map[string]string{
			"url":    cfg.URL,
			"remote": r.RemoteAddr,
		},
	})

	bs.eventHub.Broadcast(Event{
		Type: "remote_added",
		Data: map[string]string{
			"name": name,
			"url":  cfg.URL,
		},
	})

	writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "name": name})
}

// handleDeleteRemote serves DELETE /v1/dashboard/remotes/{name}.
// Removes a remote MCP server and stops its background refresh.
// Security: Currently protected by the shared dashboard token only.
// Dashboard RBAC level required: admin (when per-agent auth is implemented).
func (bs *BrokerServer) handleDeleteRemote(w http.ResponseWriter, r *http.Request) {
	if err := dashboardWriteCheck(); err != nil {
		writeError(w, http.StatusForbidden, err.Error())
		return
	}
	name := r.PathValue("name")
	if bs.federator == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "federation not configured"})
		return
	}

	if err := bs.federator.RemoveRemote(name); err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
		return
	}

	bs.auditLog.LogEvent(audit.AuditEvent{
		Severity:  audit.SeverityWarn,
		EventType: "remote_removed",
		Target:    name,
		Details: map[string]string{
			"remote": r.RemoteAddr,
		},
	})

	bs.eventHub.Broadcast(Event{
		Type: "remote_removed",
		Data: map[string]string{
			"name": name,
		},
	})

	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted", "name": name})
}

// handleRefreshRemote serves POST /v1/dashboard/remotes/{name}/refresh.
// Forces re-discovery of a remote's tools and resources.
func (bs *BrokerServer) handleRefreshRemote(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if bs.federator == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "federation not configured"})
		return
	}

	state := bs.federator.getState(name)
	if state == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "remote not found"})
		return
	}

	// Trigger discovery in background so the response returns immediately.
	go func() {
		if err := bs.federator.discoverRemote(state); err != nil {
			log.Printf("[federation] manual refresh of %s failed: %v", name, err)
		}
	}()

	bs.eventHub.Broadcast(Event{
		Type: "remote_refresh",
		Data: map[string]string{
			"name": name,
		},
	})

	writeJSON(w, http.StatusOK, map[string]string{"status": "refreshing", "name": name})
}

// handleToggleService serves POST /v1/dashboard/services/{name}/toggle.
// Security: Currently protected by the shared dashboard token only.
// Dashboard RBAC level required: operator or admin (when per-agent auth is implemented).
func (bs *BrokerServer) handleToggleService(w http.ResponseWriter, r *http.Request) {
	if err := dashboardWriteCheck(); err != nil {
		writeError(w, http.StatusForbidden, err.Error())
		return
	}
	name := r.PathValue("name")
	if bs.proxyEngine == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "proxy not configured"})
		return
	}
	svc, ok := bs.proxyEngine.GetServiceDirect(name)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "service not found"})
		return
	}
	// Toggle: nil or true -> false, false -> true
	newEnabled := true
	if svc.Enabled == nil || *svc.Enabled {
		newEnabled = false
	}
	svc.Enabled = &newEnabled
	if err := bs.proxyEngine.SaveServices(); err != nil {
		log.Printf("[dashboard] failed to save services: %v", err)
	}

	svcAction := "disabled"
	if newEnabled {
		svcAction = "enabled"
	}
	bs.auditLog.LogEvent(audit.AuditEvent{
		Severity:  audit.SeverityWarn,
		EventType: "service_toggle",
		Target:    name,
		Reason:    fmt.Sprintf("Service %s %s via dashboard", name, svcAction),
		Details: map[string]string{
			"service": name,
			"action":  svcAction,
		},
	})

	bs.eventHub.Broadcast(Event{
		Type: "service_toggle",
		Data: map[string]string{
			"name":    name,
			"enabled": fmt.Sprintf("%v", newEnabled),
		},
	})

	writeJSON(w, http.StatusOK, map[string]interface{}{"name": name, "enabled": newEnabled})
}

// handleToggleRemote serves POST /v1/dashboard/remotes/{name}/toggle.
// Security: Currently protected by the shared dashboard token only.
// Dashboard RBAC level required: operator or admin (when per-agent auth is implemented).
func (bs *BrokerServer) handleToggleRemote(w http.ResponseWriter, r *http.Request) {
	if err := dashboardWriteCheck(); err != nil {
		writeError(w, http.StatusForbidden, err.Error())
		return
	}
	name := r.PathValue("name")
	if bs.federator == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "federation not configured"})
		return
	}
	state := bs.federator.getState(name)
	if state == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "remote not found"})
		return
	}
	state.mu.Lock()
	state.Config.Enabled = !state.Config.Enabled
	newEnabled := state.Config.Enabled
	if !newEnabled {
		state.Status = RemoteStatusDisconnected
		state.StatusMessage = "disabled by dashboard"
	}
	state.mu.Unlock()
	if err := bs.federator.save(); err != nil {
		log.Printf("[dashboard] failed to save remotes: %v", err)
	}

	remoteAction := "disabled"
	if newEnabled {
		remoteAction = "enabled"
	}
	bs.auditLog.LogEvent(audit.AuditEvent{
		Severity:  audit.SeverityWarn,
		EventType: "remote_toggle",
		Target:    name,
		Reason:    fmt.Sprintf("Remote %s %s via dashboard", name, remoteAction),
		Details: map[string]string{
			"remote": name,
			"action": remoteAction,
		},
	})

	bs.eventHub.Broadcast(Event{
		Type: "remote_toggle",
		Data: map[string]string{
			"name":    name,
			"enabled": fmt.Sprintf("%v", newEnabled),
		},
	})

	writeJSON(w, http.StatusOK, map[string]interface{}{"name": name, "enabled": newEnabled})
}


// handleRevokeGrant serves POST /v1/dashboard/grants/{id}/revoke.
// Security: Currently protected by the shared dashboard token only.
// Dashboard RBAC level required: operator or admin (when per-agent auth is implemented).
func (bs *BrokerServer) handleRevokeGrant(w http.ResponseWriter, r *http.Request) {
	if err := dashboardWriteCheck(); err != nil {
		writeError(w, http.StatusForbidden, err.Error())
		return
	}
	id := r.PathValue("id")
	if bs.grantStore == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "grants not configured"})
		return
	}
	ok, reason := bs.grantStore.Revoke(id)
	if !ok {
		status := http.StatusNotFound
		if reason == "grant already revoked" {
			status = http.StatusConflict
		}
		writeJSON(w, status, map[string]string{"error": reason})
		return
	}
	bs.eventHub.Broadcast(Event{
		Type: "grant_revoked",
		Data: map[string]string{"id": id},
	})
	writeJSON(w, http.StatusOK, map[string]string{"status": "revoked", "id": id})
}

// handleGetGrantSettings serves GET /v1/dashboard/settings/grants.
func (bs *BrokerServer) handleGetGrantSettings(w http.ResponseWriter, r *http.Request) {
	if bs.grantStore == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "grants not configured"})
		return
	}
	writeJSON(w, http.StatusOK, GrantSettings{
		Mode:              string(bs.grantStore.Mode),
		DefaultServiceTTL: bs.grantStore.DefaultServiceTTL.String(),
		DefaultMCPTTL:     bs.grantStore.DefaultMCPTTL.String(),
		ActiveGrants:      bs.grantStore.ActiveCount(),
	})
}

// handleUpdateGrantSettings serves PUT /v1/dashboard/settings/grants.
// Security: Currently protected by the shared dashboard token only.
// Dashboard RBAC level required: admin (when per-agent auth is implemented).
func (bs *BrokerServer) handleUpdateGrantSettings(w http.ResponseWriter, r *http.Request) {
	if err := dashboardWriteCheck(); err != nil {
		writeError(w, http.StatusForbidden, err.Error())
		return
	}
	if bs.grantStore == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "grants not configured"})
		return
	}
	var req GrantSettings
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}
	if req.Mode == "ttl" || req.Mode == "passthrough" {
		bs.grantStore.Mode = GrantMode(req.Mode)
	}
	if req.DefaultServiceTTL != "" {
		if d, err := time.ParseDuration(req.DefaultServiceTTL); err == nil && d > 0 {
			bs.grantStore.DefaultServiceTTL = d
		}
	}
	if req.DefaultMCPTTL != "" {
		if d, err := time.ParseDuration(req.DefaultMCPTTL); err == nil && d > 0 {
			bs.grantStore.DefaultMCPTTL = d
		}
	}
	bs.eventHub.Broadcast(Event{
		Type: "settings_changed",
		Data: map[string]string{"section": "grants", "mode": string(bs.grantStore.Mode)},
	})
	writeJSON(w, http.StatusOK, GrantSettings{
		Mode:              string(bs.grantStore.Mode),
		DefaultServiceTTL: bs.grantStore.DefaultServiceTTL.String(),
		DefaultMCPTTL:     bs.grantStore.DefaultMCPTTL.String(),
		ActiveGrants:      bs.grantStore.ActiveCount(),
	})
}

// DashboardTask is a single task entry for GET /v1/dashboard/tasks.
type DashboardTask struct {
	ID           string        `json:"id"`
	RootID       string        `json:"root_id"`
	ParentID     string        `json:"parent_id"`
	AgentName    string        `json:"agent_name"`
	Description  string        `json:"description"`
	Depth        int           `json:"depth"`
	Lineage      []string      `json:"lineage"`
	CreatedAt    time.Time     `json:"created_at"`
	ExpiresAt    time.Time     `json:"expires_at"`
	RemainingTTL float64       `json:"remaining_ttl_seconds"`
	MaxTTL       float64       `json:"max_ttl_seconds"`
	Status       string        `json:"status"`
	CanDelegate  bool          `json:"can_delegate"`
	ChildCount   int           `json:"child_count"`
	Envelope     *TaskEnvelope `json:"envelope"`
	HolderBound  bool          `json:"holder_bound"`
	BindDeadline *time.Time    `json:"bind_deadline,omitempty"`
	InitiatedBy  string        `json:"initiated_by,omitempty"`
	TokenType    string        `json:"token_type"`
}

// DashboardTaskDetail is the detailed response for GET /v1/dashboard/tasks/{id}.
type DashboardTaskDetail struct {
	DashboardTask
	Children       []DashboardTask `json:"children"`
	Tree           []DashboardTask `json:"tree"`
	LineageDetails []LineageEntry  `json:"lineage_details"`
}

// LineageEntry describes one ancestor in a task's lineage chain.
type LineageEntry struct {
	ID          string `json:"id"`
	Description string `json:"description"`
	Depth       int    `json:"depth"`
	Status      string `json:"status"`
}

// taskToDashboard converts a Task to a DashboardTask for API responses.
func (bs *BrokerServer) taskToDashboard(task *Task) DashboardTask {
	now := time.Now()
	remaining := task.ExpiresAt.Sub(now).Seconds()
	if remaining < 0 {
		remaining = 0
	}
	maxTTL := task.ExpiresAt.Sub(task.CreatedAt).Seconds()
	status := "active"
	if bs.revocation != nil && bs.revocation.IsRevoked(task.ID) {
		status = "revoked"
	}
	childCount := 0
	if bs.taskMgr != nil {
		childCount = len(bs.taskMgr.GetChildren(task.ID))
	}
	dt := DashboardTask{
		ID:           task.ID,
		RootID:       task.RootID,
		ParentID:     task.ParentID,
		AgentName:    task.AgentName,
		Description:  task.Description,
		Depth:        task.Depth,
		Lineage:      task.Lineage,
		CreatedAt:    task.CreatedAt,
		ExpiresAt:    task.ExpiresAt,
		RemainingTTL: remaining,
		MaxTTL:       maxTTL,
		Status:       status,
		CanDelegate:  task.CanDelegate,
		ChildCount:   childCount,
		Envelope:     &task.Envelope,
		HolderBound:  task.HolderBound,
		InitiatedBy:  task.InitiatedBy,
	}
	if !task.BindDeadline.IsZero() {
		bd := task.BindDeadline
		dt.BindDeadline = &bd
	}
	if task.MacaroonSigDigest != "" {
		dt.TokenType = "macaroon"
	} else {
		dt.TokenType = "jwt"
	}
	return dt
}

// handleDashboardTasks serves GET /v1/dashboard/tasks.
// Optional query parameter: ?agent=<name> to filter by agent.
func (bs *BrokerServer) handleDashboardTasks(w http.ResponseWriter, r *http.Request) {
	if bs.taskMgr == nil {
		writeJSON(w, http.StatusOK, map[string]interface{}{"tasks": []interface{}{}, "count": 0})
		return
	}

	agentFilter := r.URL.Query().Get("agent")
	var tasks []*Task
	if agentFilter != "" {
		tasks = bs.taskMgr.ListTasks(agentFilter)
	} else {
		tasks = bs.taskMgr.ListAllTasks()
	}

	result := make([]DashboardTask, 0, len(tasks))
	for _, t := range tasks {
		result = append(result, bs.taskToDashboard(t))
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"tasks": result,
		"count": len(result),
	})
}

// handleDashboardTaskDetail serves GET /v1/dashboard/tasks/{id}.
func (bs *BrokerServer) handleDashboardTaskDetail(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "task id is required")
		return
	}

	if bs.taskMgr == nil {
		writeError(w, http.StatusNotFound, "task not found")
		return
	}

	task := bs.taskMgr.GetTask(id)
	if task == nil {
		writeError(w, http.StatusNotFound, "task not found")
		return
	}

	dt := bs.taskToDashboard(task)

	// Get children.
	childTasks := bs.taskMgr.GetChildren(id)
	children := make([]DashboardTask, 0, len(childTasks))
	for _, c := range childTasks {
		children = append(children, bs.taskToDashboard(c))
	}

	// Get full tree.
	treeTasks := bs.taskMgr.GetTaskTree(task.RootID)
	tree := make([]DashboardTask, 0, len(treeTasks))
	for _, t := range treeTasks {
		tree = append(tree, bs.taskToDashboard(t))
	}

	// Resolve lineage details.
	lineageDetails := make([]LineageEntry, 0, len(task.Lineage))
	for _, lid := range task.Lineage {
		entry := LineageEntry{ID: lid}
		if ancestor := bs.taskMgr.GetTask(lid); ancestor != nil {
			entry.Description = ancestor.Description
			entry.Depth = ancestor.Depth
			entry.Status = "active"
			if bs.revocation != nil && bs.revocation.IsRevoked(lid) {
				entry.Status = "revoked"
			}
		} else {
			entry.Description = ""
			entry.Status = "expired"
		}
		lineageDetails = append(lineageDetails, entry)
	}

	detail := DashboardTaskDetail{
		DashboardTask:  dt,
		Children:       children,
		Tree:           tree,
		LineageDetails: lineageDetails,
	}

	writeJSON(w, http.StatusOK, detail)
}

// handleDashboardRevokeTask serves POST /v1/dashboard/tasks/{id}/revoke.
// Supports ?preview=true to return impact without actually revoking.
// Security: Currently protected by the shared dashboard token only.
// Dashboard RBAC level required: operator or admin (when per-agent auth is implemented).
func (bs *BrokerServer) handleDashboardRevokeTask(w http.ResponseWriter, r *http.Request) {
	if err := dashboardWriteCheck(); err != nil {
		writeError(w, http.StatusForbidden, err.Error())
		return
	}

	id := r.PathValue("id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "task id is required")
		return
	}

	if bs.taskMgr == nil {
		writeError(w, http.StatusNotFound, "task not found")
		return
	}

	task := bs.taskMgr.GetTask(id)
	if task == nil {
		writeError(w, http.StatusNotFound, "task not found")
		return
	}

	// Get full tree to find descendants.
	treeTasks := bs.taskMgr.GetTaskTree(task.RootID)

	// Count descendants: tasks in the tree whose lineage contains this task's ID,
	// excluding the task itself.
	var descendants []*Task
	for _, t := range treeTasks {
		if t.ID == id {
			continue
		}
		for _, lid := range t.Lineage {
			if lid == id {
				descendants = append(descendants, t)
				break
			}
		}
	}

	preview := r.URL.Query().Get("preview") == "true"
	if preview {
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"task_id":       id,
			"cascade_count": len(descendants),
			"preview":       true,
		})
		return
	}

	// Revoke the task itself.
	if bs.revocation != nil {
		bs.revocation.Revoke(id)
	}
	bs.taskMgr.RevokeTask(id)

	// Cascade revoke all descendants.
	for _, d := range descendants {
		if bs.revocation != nil {
			bs.revocation.Revoke(d.ID)
		}
		bs.taskMgr.RevokeTask(d.ID)
	}

	// Update metrics.
	if bs.metrics != nil {
		bs.metrics.WatermarkRevocations.Add(1 + int64(len(descendants)))
	}

	// Audit log.
	bs.auditLog.LogEvent(audit.AuditEvent{
		Severity:  audit.SeverityWarn,
		EventType: "task_revoke_dashboard",
		Agent:     task.AgentName,
		Details: map[string]string{
			"task_id":       id,
			"cascade_count": strconv.Itoa(len(descendants)),
			"remote":        r.RemoteAddr,
		},
	})

	// WebSocket broadcast.
	if bs.eventHub != nil {
		bs.eventHub.Broadcast(Event{
			Type: "task_revoked",
			Data: map[string]string{
				"task_id":       id,
				"agent":         task.AgentName,
				"cascade_count": strconv.Itoa(len(descendants)),
			},
		})
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"revoked":       id,
		"cascade_count": len(descendants),
	})
}

// handleDashboardPermissions serves GET /v1/dashboard/permissions.
// Returns resolved RBAC permissions for all configured agents.
func (bs *BrokerServer) handleDashboardPermissions(w http.ResponseWriter, r *http.Request) {
	bs.policyMu.RLock()
	agentPerms := bs.policyCfg.AgentPerms
	raw := bs.policyCfg.Raw
	bs.policyMu.RUnlock()

	type targetPerm struct {
		Roles       []string `json:"roles"`
		AutoApprove *bool    `json:"auto_approve,omitempty"`
	}
	type servicePerm struct {
		Methods []string `json:"methods,omitempty"`
	}
	type remotePerm struct {
		Tools []string `json:"tools,omitempty"`
	}
	type agentPermView struct {
		LegacyMode bool                    `json:"legacy_mode"`
		Dashboard  string                  `json:"dashboard"`
		SSH        map[string]targetPerm   `json:"ssh"`
		Services   map[string]servicePerm  `json:"services"`
		Remotes    map[string]remotePerm   `json:"remotes"`
		Inherits   []string                `json:"inherits,omitempty"`
	}

	result := make(map[string]agentPermView)
	for name, perms := range agentPerms {
		view := agentPermView{
			LegacyMode: perms.LegacyMode,
			SSH:        make(map[string]targetPerm),
			Services:   make(map[string]servicePerm),
			Remotes:    make(map[string]remotePerm),
		}
		// Dashboard level
		switch perms.Dashboard {
		case 1: view.Dashboard = "viewer"
		case 2: view.Dashboard = "operator"
		case 3: view.Dashboard = "admin"
		default: view.Dashboard = "none"
		}
		for k, v := range perms.SSHAccess {
			view.SSH[k] = targetPerm{Roles: v.Roles, AutoApprove: v.AutoApprove}
		}
		for k, v := range perms.ServiceAccess {
			view.Services[k] = servicePerm{Methods: v.Methods}
		}
		for k, v := range perms.RemoteAccess {
			view.Remotes[k] = remotePerm{Tools: v.Tools}
		}
		// Include inherits from raw policy
		if agent, ok := raw.Agents[name]; ok {
			view.Inherits = agent.Inherits
		}
		result[name] = view
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(result)
}

// handleMetrics serves GET /v1/metrics in Prometheus exposition format.
func (bs *BrokerServer) handleMetrics(w http.ResponseWriter, r *http.Request) {
	if bs.metrics == nil {
		http.Error(w, "metrics not initialized", http.StatusInternalServerError)
		return
	}
	// Sync auth cache stats before serving.
	if bs.mcpServer != nil && bs.mcpServer.auth != nil {
		hits, misses := bs.mcpServer.auth.CacheStats()
		bs.metrics.AuthCacheHits.Store(hits)
		bs.metrics.AuthCacheMisses.Store(misses)
	}
	bs.metrics.ServePrometheus(w, r)
}
