package broker

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/sprawl/clauth/internal/audit"
	"github.com/sprawl/clauth/internal/auth"
	"github.com/sprawl/clauth/internal/policy"
	"github.com/sprawl/clauth/internal/signer"
)

// --- JSON request/response types ---

// CertRequest is the JSON body for POST /v1/request.
type CertRequest struct {
	Target    string `json:"target"`
	Role      string `json:"role"`
	Duration  string `json:"duration"`            // Go duration string, e.g. "5m"
	PublicKey string `json:"public_key,omitempty"` // authorized_key format
}

// CertResponse is the JSON response for POST /v1/request.
type CertResponse struct {
	Status      string `json:"status"`               // "granted", "denied", or "pending"
	Certificate string `json:"certificate,omitempty"` // cert in authorized_key format
	Serial      string `json:"serial,omitempty"`
	ExpiresAt   string `json:"expires_at,omitempty"` // RFC3339
	Reason      string `json:"reason,omitempty"`
	RequestID   string `json:"request_id,omitempty"` // only when pending
	Principal   string `json:"principal,omitempty"`
	Host        string `json:"host,omitempty"`
	Port        int    `json:"port,omitempty"`
}

// SessionRequest is the JSON body for POST /v1/session.
type SessionRequest struct {
	AgentName string `json:"agent_name"`
}

// SessionResponse is the JSON response for POST /v1/session.
type SessionResponse struct {
	Token     string `json:"token"`
	AgentName string `json:"agent_name"`
	UID       uint32 `json:"uid"`
}

// HealthResponse is the JSON response for GET /v1/health.
type HealthResponse struct {
	Status      string `json:"status"`
	Uptime      string `json:"uptime"`
	ActiveCerts int    `json:"active_certs"`
	PendingReqs int    `json:"pending_requests"`
	SignerOK    bool   `json:"signer_ok"`
}

// TargetInfo is a single target entry returned by GET /v1/targets.
type TargetInfo struct {
	Name         string   `json:"name"`
	Host         string   `json:"host"`
	Port         int      `json:"port"`
	AllowedRoles []string `json:"allowed_roles"`
	AutoApprove  bool     `json:"auto_approve"`
	Description  string   `json:"description,omitempty"`
}

// --- Handlers ---

// handleHealth serves GET /v1/health.
func (bs *BrokerServer) handleHealth(w http.ResponseWriter, r *http.Request) {
	signerOK := true
	if err := bs.signerClient.Ping(); err != nil {
		signerOK = false
	}

	resp := HealthResponse{
		Status:      "ok",
		Uptime:      time.Since(bs.startTime).Round(time.Second).String(),
		ActiveCerts: len(bs.state.ListAllCerts()),
		PendingReqs: len(bs.state.ListPending()),
		SignerOK:    signerOK,
	}
	writeJSON(w, http.StatusOK, resp)
}

// handleCreateSession serves POST /v1/session.
func (bs *BrokerServer) handleCreateSession(w http.ResponseWriter, r *http.Request) {
	uid, ok := ContextUID(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "unable to identify caller")
		return
	}

	var req SessionRequest
	// Allow empty body - auto-detect agent from UID if not provided.
	if r.Body != nil && r.ContentLength != 0 {
		json.NewDecoder(r.Body).Decode(&req)
	}

	// If agent_name not provided, resolve from UID.
	if req.AgentName == "" {
		name, found := bs.resolveAgentByUID(uid)
		if !found {
			writeError(w, http.StatusForbidden, fmt.Sprintf("uid %d is not registered as any agent in policy", uid))
			return
		}
		req.AgentName = name
	} else {
		if !bs.isKnownAgent(req.AgentName, uid) {
			writeError(w, http.StatusForbidden, fmt.Sprintf("uid %d is not registered as agent %q in policy", uid, req.AgentName))
			return
		}
	}

	token, err := bs.sessions.CreateSession(req.AgentName, uid)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to create session: "+err.Error())
		return
	}

	bs.auditLog.LogEvent(audit.AuditEvent{
		Severity:  audit.SeverityInfo,
		EventType: audit.EventSessionStart,
		Agent:     req.AgentName,
		Details:   map[string]string{"uid": fmt.Sprintf("%d", uid)},
	})

	bs.eventHub.Broadcast(Event{
		Type: "session_start",
		Data: map[string]interface{}{
			"agent": req.AgentName,
			"uid":   uid,
		},
	})

	writeJSON(w, http.StatusOK, SessionResponse{
		Token:     token,
		AgentName: req.AgentName,
		UID:       uid,
	})
}


// handleGetSession serves GET /v1/session (whoami).
func (bs *BrokerServer) handleGetSession(w http.ResponseWriter, r *http.Request) {
	uid, ok := ContextUID(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "unable to identify caller")
		return
	}

	// Check X-Session-Token header.
	token := r.Header.Get("X-Session-Token")
	if token == "" {
		token = r.Header.Get("Authorization")
		if len(token) > 7 && token[:7] == "Bearer " {
			token = token[7:]
		}
	}

	if token == "" {
		writeError(w, http.StatusUnauthorized, "missing session token")
		return
	}

	agentName, sessUID, valid := bs.sessions.ValidateSession(token)
	if !valid || sessUID != uid {
		writeError(w, http.StatusUnauthorized, "invalid session")
		return
	}

	session := bs.sessions.GetSessionByAgent(agentName)
	if session == nil {
		writeError(w, http.StatusNotFound, "session not found")
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"token":      token[:8] + "..." + token[len(token)-8:],
		"agent_name": agentName,
		"uid":        sessUID,
		"created_at": session.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
		"last_seen":  session.LastSeen.Format("2006-01-02T15:04:05Z07:00"),
	})
}

// handleRequest serves POST /v1/request -- the main certificate request pipeline.
func (bs *BrokerServer) handleRequest(w http.ResponseWriter, r *http.Request) {
	uid, ok := ContextUID(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "unable to identify caller")
		return
	}

	// Extract session token from Authorization or X-Session-Token header.
	token := r.Header.Get("Authorization")
	if token == "" {
		token = r.Header.Get("X-Session-Token")
	}
	if token == "" {
		writeError(w, http.StatusUnauthorized, "missing session token (Authorization or X-Session-Token header)")
		return
	}
	// Strip "Bearer " prefix if present.
	if len(token) > 7 && token[:7] == "Bearer " {
		token = token[7:]
	}

	agentName, sessUID, valid := bs.sessions.ValidateSession(token)
	if !valid {
		writeError(w, http.StatusUnauthorized, "invalid or expired session token")
		return
	}
	// Ensure the session UID matches the socket peer UID (prevent token theft).
	if sessUID != uid {
		writeError(w, http.StatusForbidden, "session UID does not match connection UID")
		return
	}

	// Parse the request body.
	var req CertRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	if req.Target == "" || req.Role == "" {
		writeError(w, http.StatusBadRequest, "target and role are required")
		return
	}

	// Check host access controller before policy evaluation.
	if !bs.hostCtl.IsEnabled(req.Target) {
		atomic.AddUint64(&bs.denyCount, 1)

		bs.auditLog.LogEvent(audit.AuditEvent{
			Severity:  audit.SeverityWarn,
			EventType: audit.EventCertDenied,
			Agent:     agentName,
			Target:    req.Target,
			Role:      req.Role,
			Reason:    "host access disabled",
		})

		bs.eventHub.Broadcast(Event{
			Type: "cert_denied",
			Data: map[string]interface{}{
				"agent":  agentName,
				"target": req.Target,
				"role":   req.Role,
				"reason": "host access disabled",
			},
		})

		writeJSON(w, http.StatusForbidden, CertResponse{
			Status: "denied",
			Reason: "host access is currently disabled",
		})
		return
	}

	// Parse duration (0 means "use policy default").
	var duration time.Duration
	if req.Duration != "" {
		var err error
		duration, err = time.ParseDuration(req.Duration)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid duration: "+err.Error())
			return
		}
	}

	// Evaluate policy.
	bs.policyMu.RLock()
	evalResult := bs.policyEngine.Evaluate(policy.EvalRequest{
		AgentUID:   int(uid),
		TargetName: req.Target,
		RoleName:   req.Role,
		Duration:   duration,
	})
	bs.policyMu.RUnlock()

	switch evalResult.Decision {
	case policy.Deny:
		atomic.AddUint64(&bs.denyCount, 1)

		bs.auditLog.LogEvent(audit.AuditEvent{
			Severity:  audit.SeverityWarn,
			EventType: audit.EventCertDenied,
			Agent:     agentName,
			Target:    req.Target,
			Role:      req.Role,
			Duration:  duration.String(),
			Reason:    evalResult.Reason,
		})

		bs.eventHub.Broadcast(Event{
			Type: "cert_denied",
			Data: map[string]interface{}{
				"agent":  agentName,
				"target": req.Target,
				"role":   req.Role,
				"reason": evalResult.Reason,
			},
		})

		writeJSON(w, http.StatusForbidden, CertResponse{
			Status: "denied",
			Reason: evalResult.Reason,
		})
		return

	case policy.Pending:
		// Store as pending request for admin approval.
		pending := &PendingRequest{
			AgentName:   agentName,
			AgentUID:    uid,
			Target:      req.Target,
			Role:        req.Role,
			Duration:    evalResult.ClampedDuration,
			RequestedAt: time.Now(),
			PublicKey:   req.PublicKey,
		}
		reqID := bs.state.AddPending(pending)

		bs.auditLog.LogEvent(audit.AuditEvent{
			Severity:  audit.SeverityInfo,
			EventType: audit.EventCertPending,
			Agent:     agentName,
			Target:    req.Target,
			Role:      req.Role,
			Duration:  evalResult.ClampedDuration.String(),
			Reason:    evalResult.Reason,
			Details:   map[string]string{"request_id": reqID},
		})

		writeJSON(w, http.StatusAccepted, CertResponse{
			Status:    "pending",
			Reason:    evalResult.Reason,
			RequestID: reqID,
		})
		return

	case policy.Approve:
		// Fall through to signing.
	}

	// Issue the certificate via signer IPC.
	cert, err := bs.issueCert(agentName, req.Target, evalResult.Principal, req.PublicKey, evalResult.ClampedDuration, req.Role)
	if err != nil {
		log.Printf("[broker] sign error for %s -> %s: %v", agentName, req.Target, err)
		writeError(w, http.StatusInternalServerError, "signing failed: "+err.Error())
		return
	}

	// Track the certificate in local state.
	activeCert := &ActiveCert{
		Serial:      cert.Serial,
		AgentName:   agentName,
		AgentUID:    uid,
		Target:      req.Target,
		Role:        req.Role,
		Principal:   evalResult.Principal,
		IssuedAt:    time.Now(),
		ExpiresAt:   parseRFC3339(cert.ExpiresAt),
		Certificate: cert.Certificate,
	}
	bs.state.AddCert(activeCert)

	// Issue an SSH cert access grant so it appears alongside service/MCP grants.
	if bs.grantStore != nil {
		bs.grantStore.Issue(GrantTypeSSHCert, agentName, req.Target, evalResult.ClampedDuration, map[string]string{
			"role":      req.Role,
			"principal": evalResult.Principal,
			"serial":    cert.Serial,
		})
	}

	// Track in policy engine as well (for concurrent cert limits).
	bs.policyEngine.TrackCert(parseSerial(cert.Serial), int(uid), req.Target, req.Role, parseRFC3339(cert.ExpiresAt))

	atomic.AddUint64(&bs.grantCount, 1)

	bs.auditLog.LogEvent(audit.AuditEvent{
		Severity:  audit.SeverityInfo,
		EventType: audit.EventCertIssued,
		Agent:     agentName,
		Target:    req.Target,
		Role:      req.Role,
		Serial:    cert.Serial,
		Duration:  evalResult.ClampedDuration.String(),
	})

	bs.eventHub.Broadcast(Event{
		Type: "cert_issued",
		Data: map[string]interface{}{
			"serial":    cert.Serial,
			"agent":     agentName,
			"target":    req.Target,
			"role":      req.Role,
			"principal": evalResult.Principal,
			"expires":   cert.ExpiresAt,
		},
	})

	// Look up host/port from policy for the response.
	bs.policyMu.RLock()
	respHost := ""
	respPort := 22
	if tgt, exists := bs.policyCfg.Raw.Targets[req.Target]; exists {
		respHost = tgt.Host
		if tgt.Port > 0 {
			respPort = tgt.Port
		}
	}
	bs.policyMu.RUnlock()

	writeJSON(w, http.StatusOK, CertResponse{
		Status:      "granted",
		Certificate: cert.Certificate,
		Serial:      cert.Serial,
		ExpiresAt:   cert.ExpiresAt,
		Principal:   evalResult.Principal,
		Host:        respHost,
		Port:        respPort,
	})
}

// handleListCerts serves GET /v1/certs.
func (bs *BrokerServer) handleListCerts(w http.ResponseWriter, r *http.Request) {
	uid, ok := ContextUID(r)
	if !ok {
		// On TCP dashboard connections there is no Unix peer cred,
		// so return all certs (auth is handled by token middleware).
		certs := bs.state.ListAllCerts()
		if certs == nil {
			certs = []*ActiveCert{}
		}
		writeJSON(w, http.StatusOK, certs)
		return
	}

	var certs []*ActiveCert
	if bs.isAdmin(uid) {
		certs = bs.state.ListAllCerts()
	} else {
		certs = bs.state.ListCertsForAgent(uid)
	}

	// Return empty array instead of null.
	if certs == nil {
		certs = []*ActiveCert{}
	}

	writeJSON(w, http.StatusOK, certs)
}

// handleRevokeCert serves DELETE /v1/certs/{serial}.
func (bs *BrokerServer) handleRevokeCert(w http.ResponseWriter, r *http.Request) {
	uid, ok := ContextUID(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "unable to identify caller")
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

	// Only admins or the cert owner can revoke.
	if cert.AgentUID != uid && !bs.isAdmin(uid) {
		writeError(w, http.StatusForbidden, "you can only revoke your own certificates")
		return
	}

	bs.state.RemoveCert(serial)

	// Also remove from policy engine tracking.
	bs.policyEngine.RemoveCert(parseSerial(serial))

	bs.auditLog.LogEvent(audit.AuditEvent{
		Severity:  audit.SeverityInfo,
		EventType: audit.EventCertRevoked,
		Agent:     cert.AgentName,
		Target:    cert.Target,
		Role:      cert.Role,
		Serial:    serial,
		Details:   map[string]string{"revoked_by_uid": fmt.Sprintf("%d", uid)},
	})

	bs.eventHub.Broadcast(Event{
		Type: "cert_revoked",
		Data: map[string]interface{}{
			"serial": serial,
			"agent":  cert.AgentName,
			"target": cert.Target,
			"role":   cert.Role,
		},
	})

	writeJSON(w, http.StatusOK, map[string]string{
		"status": "revoked",
		"serial": serial,
	})
}

// handleListTargets serves GET /v1/targets.
func (bs *BrokerServer) handleListTargets(w http.ResponseWriter, r *http.Request) {
	uid, hasUID := ContextUID(r)
	if !hasUID {
		// No Unix peer cred (TCP dashboard connection) -- handled by dashboard auth middleware.
		// Fall through.
	} else {
		// Unix socket connection -- require a valid session token.
		token := r.Header.Get("Authorization")
		if token == "" {
			token = r.Header.Get("X-Session-Token")
		}
		if token == "" {
			writeError(w, http.StatusUnauthorized, "missing session token (Authorization or X-Session-Token header)")
			return
		}
		if len(token) > 7 && token[:7] == "Bearer " {
			token = token[7:]
		}

		_, sessUID, valid := bs.sessions.ValidateSession(token)
		if !valid || sessUID != uid {
			writeError(w, http.StatusUnauthorized, "invalid or expired session token")
			return
		}
	}

	bs.policyMu.RLock()
	resolved := bs.policyCfg
	bs.policyMu.RUnlock()

	cfg := resolved.Raw

	targets := make([]TargetInfo, 0, len(cfg.Targets))
	for name, t := range cfg.Targets {
		port := t.Port
		if port == 0 {
			port = 22
		}
		targets = append(targets, TargetInfo{
			Name:         name,
			Host:         t.Host,
			Port:         port,
			AllowedRoles: t.AllowedRoles,
			AutoApprove:  t.AutoApprove,
			Description:  t.Description,
		})
	}

	writeJSON(w, http.StatusOK, targets)
}

// handleApprove serves POST /v1/approve/{request_id}.
func (bs *BrokerServer) handleApprove(w http.ResponseWriter, r *http.Request) {
	uid, ok := ContextUID(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "unable to identify caller")
		return
	}

	if !bs.isAdmin(uid) {
		writeError(w, http.StatusForbidden, "admin access required")
		return
	}

	requestID := r.PathValue("request_id")
	if requestID == "" {
		writeError(w, http.StatusBadRequest, "request_id is required")
		return
	}

	pending, found := bs.state.GetPending(requestID)
	if !found {
		writeError(w, http.StatusNotFound, "pending request not found")
		return
	}

	// Look up the principal from policy for this target/role.
	bs.policyMu.RLock()
	resolved := bs.policyCfg
	bs.policyMu.RUnlock()

	cfg := resolved.Raw
	principal := ""
	if roleDef, exists := cfg.Roles[pending.Role]; exists {
		principal = roleDef.Principal
	}
	if principal == "" {
		principal = pending.Role // fallback to role name
	}

	// Issue the certificate.
	cert, err := bs.issueCert(pending.AgentName, pending.Target, principal, pending.PublicKey, pending.Duration, pending.Role)
	if err != nil {
		log.Printf("[broker] approve sign error for %s -> %s: %v", pending.AgentName, pending.Target, err)
		writeError(w, http.StatusInternalServerError, "signing failed: "+err.Error())
		return
	}

	// Track cert in state.
	activeCert := &ActiveCert{
		Serial:      cert.Serial,
		AgentName:   pending.AgentName,
		AgentUID:    pending.AgentUID,
		Target:      pending.Target,
		Role:        pending.Role,
		Principal:   principal,
		IssuedAt:    time.Now(),
		ExpiresAt:   parseRFC3339(cert.ExpiresAt),
		Certificate: cert.Certificate,
	}
	bs.state.AddCert(activeCert)

	// Track in policy engine.
	bs.policyEngine.TrackCert(parseSerial(cert.Serial), int(pending.AgentUID), pending.Target, pending.Role, parseRFC3339(cert.ExpiresAt))

	// Remove from pending.
	bs.state.RemovePending(requestID)

	atomic.AddUint64(&bs.grantCount, 1)

	bs.auditLog.LogEvent(audit.AuditEvent{
		Severity:  audit.SeverityInfo,
		EventType: audit.EventCertApproved,
		Agent:     pending.AgentName,
		Target:    pending.Target,
		Role:      pending.Role,
		Serial:    cert.Serial,
		Duration:  pending.Duration.String(),
		Details: map[string]string{
			"approved_by_uid": fmt.Sprintf("%d", uid),
			"request_id":      requestID,
		},
	})

	bs.eventHub.Broadcast(Event{
		Type: "cert_issued",
		Data: map[string]interface{}{
			"serial":     cert.Serial,
			"agent":      pending.AgentName,
			"target":     pending.Target,
			"role":       pending.Role,
			"principal":  principal,
			"expires":    cert.ExpiresAt,
			"request_id": requestID,
			"approved":   true,
		},
	})

	// Look up host/port from policy.
	approveHost := ""
	approvePort := 22
	if tgt, exists := cfg.Targets[pending.Target]; exists {
		approveHost = tgt.Host
		if tgt.Port > 0 {
			approvePort = tgt.Port
		}
	}

	writeJSON(w, http.StatusOK, CertResponse{
		Status:      "granted",
		Certificate: cert.Certificate,
		Serial:      cert.Serial,
		ExpiresAt:   cert.ExpiresAt,
		RequestID:   requestID,
		Principal:   principal,
		Host:        approveHost,
		Port:        approvePort,
	})
}

// handleDeny serves POST /v1/deny/{request_id}.
func (bs *BrokerServer) handleDeny(w http.ResponseWriter, r *http.Request) {
	uid, ok := ContextUID(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "unable to identify caller")
		return
	}

	if !bs.isAdmin(uid) {
		writeError(w, http.StatusForbidden, "admin access required")
		return
	}

	requestID := r.PathValue("request_id")
	if requestID == "" {
		writeError(w, http.StatusBadRequest, "request_id is required")
		return
	}

	pending, found := bs.state.GetPending(requestID)
	if !found {
		writeError(w, http.StatusNotFound, "pending request not found")
		return
	}

	bs.state.RemovePending(requestID)

	atomic.AddUint64(&bs.denyCount, 1)

	bs.auditLog.LogEvent(audit.AuditEvent{
		Severity:  audit.SeverityWarn,
		EventType: audit.EventCertDenied,
		Agent:     pending.AgentName,
		Target:    pending.Target,
		Role:      pending.Role,
		Reason:    "admin denied",
		Details: map[string]string{
			"denied_by_uid": fmt.Sprintf("%d", uid),
			"request_id":    requestID,
		},
	})

	bs.eventHub.Broadcast(Event{
		Type: "cert_denied",
		Data: map[string]interface{}{
			"agent":      pending.AgentName,
			"target":     pending.Target,
			"role":       pending.Role,
			"reason":     "admin denied",
			"request_id": requestID,
		},
	})

	writeJSON(w, http.StatusOK, CertResponse{
		Status:    "denied",
		Reason:    "request denied by admin",
		RequestID: requestID,
	})
}

// --- Helper methods ---

// issueCert calls the signer IPC to issue a certificate.
func (bs *BrokerServer) issueCert(agentName, target, principal, publicKey string, duration time.Duration, role string) (*signer.SignResponse, error) {
	if publicKey == "" {
		return nil, fmt.Errorf("public_key is required")
	}

	keyID := fmt.Sprintf("%s@%s/%s", agentName, target, role)

	// Look up force_command from policy.
	bs.policyMu.RLock()
	forceCmd := ""
	if t, exists := bs.policyCfg.Raw.Targets[target]; exists {
		forceCmd = t.ForceCommand
	}
	bs.policyMu.RUnlock()

	resp, err := bs.signerClient.RequestSign(signer.SignRequest{
		PublicKey:    publicKey,
		Principals:  []string{principal},
		Duration:    duration.String(),
		KeyID:       keyID,
		ForceCommand: forceCmd,
	})
	if err != nil {
		return nil, err
	}

	return resp, nil
}

// isKnownAgent checks whether the given agent name and UID match policy.
func (bs *BrokerServer) isKnownAgent(name string, uid uint32) bool {
	bs.policyMu.RLock()
	defer bs.policyMu.RUnlock()

	cfg := bs.policyCfg.Raw
	agent, exists := cfg.Agents[name]
	if !exists {
		return false
	}
	return agent.UID == int(uid)
}

// isAdmin checks whether the UID is in the admin list.
func (bs *BrokerServer) isAdmin(uid uint32) bool {
	for _, adminUID := range bs.adminUIDs {
		if adminUID == uid {
			return true
		}
	}
	return false
}

// resolveAgentByUID looks up the agent name for a UID from the policy config.
func (bs *BrokerServer) resolveAgentByUID(uid uint32) (string, bool) {
	bs.policyMu.RLock()
	defer bs.policyMu.RUnlock()

	cfg := bs.policyCfg.Raw
	for name, agent := range cfg.Agents {
		if agent.UID == int(uid) {
			return name, true
		}
	}
	return auth.ResolveUsername(uid), false
}

// parseRFC3339 parses an RFC3339 timestamp, returning the zero time on failure.
func parseRFC3339(s string) time.Time {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}
	}
	return t
}

// parseSerial converts a hex serial string to uint64.
func parseSerial(s string) uint64 {
	var serial uint64
	fmt.Sscanf(s, "%x", &serial)
	return serial
}


// handleAdminToggleHost serves POST /v1/admin/hosts/{name}/toggle on the Unix socket.
// It requires the caller to be an admin (by UID check).
func (bs *BrokerServer) handleAdminToggleHost(w http.ResponseWriter, r *http.Request) {
	uid, ok := ContextUID(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "unable to identify caller")
		return
	}

	if !bs.isAdmin(uid) {
		writeError(w, http.StatusForbidden, "admin access required")
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

	stateLabel := "enabled"
	if !newState {
		stateLabel = "disabled"
	}

	bs.auditLog.LogEvent(audit.AuditEvent{
		Severity:  audit.SeverityWarn,
		EventType: "host_toggle",
		Target:    name,
		Reason:    fmt.Sprintf("Host %s toggled via admin socket by UID %d", name, uid),
		Details:   map[string]string{"state": stateLabel, "admin_uid": fmt.Sprintf("%d", uid)},
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

// writeJSON marshals v as JSON and writes it to the response.
func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

// writeError writes a JSON error response.
func writeError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}


// handleListServicesAPI serves GET /v1/services.
// Returns proxy service configs (credentials redacted) for agent discovery.
func (bs *BrokerServer) handleListServicesAPI(w http.ResponseWriter, r *http.Request) {
	uid, hasUID := ContextUID(r)
	if hasUID {
		token := r.Header.Get("Authorization")
		if token == "" {
			token = r.Header.Get("X-Session-Token")
		}
		if token == "" {
			writeError(w, http.StatusUnauthorized, "missing session token")
			return
		}
		if len(token) > 7 && token[:7] == "Bearer " {
			token = token[7:]
		}
		_, sessUID, valid := bs.sessions.ValidateSession(token)
		if !valid || sessUID != uid {
			writeError(w, http.StatusUnauthorized, "invalid or expired session token")
			return
		}
	}

	if bs.proxyEngine == nil {
		writeJSON(w, http.StatusOK, []struct{}{})
		return
	}
	services := bs.proxyEngine.ListServices()
	if services == nil {
		services = []*ServiceConfig{}
	}
	// Redact credentials for agent-facing endpoint.
	type safeService struct {
		Name           string   `json:"name"`
		URLPrefix      string   `json:"url_prefix"`
		AuthType       string   `json:"auth_type"`
		Description    string   `json:"description"`
		Enabled        *bool    `json:"enabled,omitempty"`
		AllowedMethods []string `json:"allowed_methods,omitempty"`
	}
	safe := make([]safeService, len(services))
	for i, s := range services {
		safe[i] = safeService{
			Name:           s.Name,
			URLPrefix:      s.URLPrefix,
			AuthType:       s.AuthType,
			Description:    s.Description,
			Enabled:        s.Enabled,
			AllowedMethods: s.AllowedMethods,
		}
	}
	writeJSON(w, http.StatusOK, safe)
}

// handleListRemotesAPI serves GET /v1/remotes.
// Returns federated MCP server states for agent discovery.
func (bs *BrokerServer) handleListRemotesAPI(w http.ResponseWriter, r *http.Request) {
	uid, hasUID := ContextUID(r)
	if hasUID {
		token := r.Header.Get("Authorization")
		if token == "" {
			token = r.Header.Get("X-Session-Token")
		}
		if token == "" {
			writeError(w, http.StatusUnauthorized, "missing session token")
			return
		}
		if len(token) > 7 && token[:7] == "Bearer " {
			token = token[7:]
		}
		_, sessUID, valid := bs.sessions.ValidateSession(token)
		if !valid || sessUID != uid {
			writeError(w, http.StatusUnauthorized, "invalid or expired session token")
			return
		}
	}

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
