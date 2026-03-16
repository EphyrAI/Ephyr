package broker

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/EphyrAI/Ephyr/internal/audit"
	"github.com/EphyrAI/Ephyr/internal/signer"
	"golang.org/x/crypto/ssh"
)

// ExecRequest is the input for a single command execution.
type ExecRequest struct {
	Target    string `json:"target"`
	Role      string `json:"role"`
	Command   string `json:"command"`
	Timeout   int    `json:"timeout,omitempty"`    // seconds, default 30
	SessionID string `json:"session_id,omitempty"` // if set, reuse existing SSH connection
}

// ExecTimings holds latency breakdown for each phase of an exec operation.
type ExecTimings struct {
	PolicyMs int64 `json:"policy_ms,omitempty"` // policy evaluation
	CertMs   int64 `json:"cert_ms,omitempty"`   // certificate signing (signer IPC)
	SSHMs    int64 `json:"ssh_ms,omitempty"`     // SSH connection + command execution
	TotalMs  int64 `json:"total_ms,omitempty"`   // end-to-end
	Session  bool  `json:"session,omitempty"`    // true if exec used an existing session
}

// ExecResult is the output of a command execution.
type ExecResult struct {
	Stdout     string      `json:"stdout"`
	Stderr     string      `json:"stderr"`
	ExitCode   int         `json:"exit_code"`
	Target     string      `json:"target"`
	Role       string      `json:"role"`
	DurationMs int64       `json:"duration_ms"`
	Timings    *ExecTimings `json:"timings,omitempty"`
}

// ExecSession is a persistent SSH connection for multi-command workflows.
type ExecSession struct {
	ID         string
	AgentName  string
	Target     string
	Role       string
	Principal  string
	CertSerial string // serial of the SSH cert, used to deregister from CertState on close
	SSHClient  *ssh.Client
	CreatedAt  time.Time
	LastUsed   time.Time
	mu         sync.Mutex
}

// signResult bundles the SSH client with certificate metadata returned by
// signAndConnect so callers can register the cert in CertState.
type signResult struct {
	Client      *ssh.Client
	Serial      string
	ExpiresAt   string // RFC3339 from signer
	Certificate string // base64-encoded cert from signer
	Principal   string
}

// ExecSessionInfo is a safe subset of ExecSession for API responses (no ssh.Client).
type ExecSessionInfo struct {
	ID        string    `json:"id"`
	Target    string    `json:"target"`
	Role      string    `json:"role"`
	CreatedAt time.Time `json:"created_at"`
	LastUsed  time.Time `json:"last_used"`
}

// ExecSessionPool manages persistent SSH sessions.
type ExecSessionPool struct {
	mu             sync.RWMutex
	sessions       map[string]*ExecSession
	broker         *BrokerServer
	maxPerAgent    int // max concurrent sessions per agent
	hostKeyWarned  sync.Map // tracks targets that have already emitted an unpinned-key warning
}

// NewExecSessionPool creates a new session pool and starts the idle-session
// cleanup goroutine. maxPerAgent limits the number of concurrent persistent
// sessions a single agent may hold.
func NewExecSessionPool(broker *BrokerServer, maxPerAgent int) *ExecSessionPool {
	if maxPerAgent <= 0 {
		maxPerAgent = 5
	}
	p := &ExecSessionPool{
		sessions:    make(map[string]*ExecSession),
		broker:      broker,
		maxPerAgent: maxPerAgent,
	}
	go p.cleanup()
	return p
}

// generateSessionID creates a cryptographically random 16-byte hex session ID.
func generateSessionID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate session id: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// signAndConnect generates an ephemeral Ed25519 keypair, signs it via the
// signer IPC to obtain an SSH certificate, and dials the target host.
// Returns a signResult containing the connected SSH client and certificate
// metadata (serial, expiry, principal), or an error.
func (p *ExecSessionPool) signAndConnect(agentName, target, role string) (*signResult, error) {
	// 1. Look up target and role in policy.
	p.broker.policyMu.RLock()
	targetCfg, targetExists := p.broker.policyCfg.Raw.Targets[target]
	roleCfg, roleExists := p.broker.policyCfg.Raw.Roles[role]
	defaultTTL := p.broker.policyCfg.GlobalDefaultTTL
	p.broker.policyMu.RUnlock()

	if !targetExists {
		return nil, fmt.Errorf("unknown target %q", target)
	}
	if !roleExists {
		return nil, fmt.Errorf("unknown role %q", role)
	}

	principal := roleCfg.Principal

	// Determine cert duration: use a short-lived cert for exec operations.
	// Cap at 5 minutes or the global default TTL, whichever is shorter.
	certDuration := 5 * time.Minute
	if defaultTTL < certDuration {
		certDuration = defaultTTL
	}

	// 2. Generate ephemeral Ed25519 keypair (never written to disk).
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate ephemeral keypair: %w", err)
	}

	sshPubKey, err := ssh.NewPublicKey(pubKey)
	if err != nil {
		return nil, fmt.Errorf("convert ed25519 to ssh public key: %w", err)
	}
	pubKeyStr := string(ssh.MarshalAuthorizedKey(sshPubKey))

	// 3. Sign via signer IPC.
	resp, err := p.broker.signerClient.RequestSign(signer.SignRequest{
		PublicKey:  pubKeyStr,
		Principals: []string{principal},
		Duration:   certDuration.String(),
		KeyID:      fmt.Sprintf("mcp-%s@%s/%s", agentName, target, role),
	})
	if err != nil {
		return nil, fmt.Errorf("signer request: %w", err)
	}

	// 4. Parse the certificate (returned as base64-encoded authorized_key format).
	certAK, err := base64.StdEncoding.DecodeString(resp.Certificate)
	if err != nil {
		return nil, fmt.Errorf("decode certificate base64: %w", err)
	}
	certParsed, _, _, _, err := ssh.ParseAuthorizedKey(certAK)
	if err != nil {
		return nil, fmt.Errorf("parse signed certificate: %w", err)
	}
	cert, ok := certParsed.(*ssh.Certificate)
	if !ok {
		return nil, fmt.Errorf("signer returned non-certificate key type %T", certParsed)
	}

	// 5. Build certificate signer from ephemeral private key + signed cert.
	sshSigner, err := ssh.NewSignerFromKey(privKey)
	if err != nil {
		return nil, fmt.Errorf("create signer from private key: %w", err)
	}
	certSigner, err := ssh.NewCertSigner(cert, sshSigner)
	if err != nil {
		return nil, fmt.Errorf("create cert signer: %w", err)
	}

	// 6. Resolve host key for this target (T6).
	var pinnedKey ssh.PublicKey
	var pinnedFP string
	p.broker.policyMu.RLock()
	if p.broker.policyCfg.TargetHostKeys != nil {
		pinnedKey = p.broker.policyCfg.TargetHostKeys[target]
	}
	if tgt, ok := p.broker.policyCfg.Raw.Targets[target]; ok && pinnedKey == nil {
		pinnedFP = tgt.HostKeyFingerprint
	}
	hostKeyStrict := false
	if p.broker.policyCfg.Raw != nil {
		hostKeyStrict = p.broker.policyCfg.Raw.Global.HostKeyStrict
	}
	p.broker.policyMu.RUnlock()

	if hostKeyStrict && pinnedKey == nil && pinnedFP == "" {
		return nil, fmt.Errorf("host key verification required (host_key_strict=true) but target %q has no pinned host key", target)
	}

	// Build SSH client config with certificate authentication and host key verification.
	sshConfig := &ssh.ClientConfig{
		User:            principal,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(certSigner)},
		HostKeyCallback: hostKeyCallback(target, pinnedKey, pinnedFP, p.broker.auditLog, &p.hostKeyWarned),
		Timeout:         10 * time.Second,
	}

	// 7. Dial SSH to the target.
	port := targetCfg.Port
	if port == 0 {
		port = 22
	}
	addr := net.JoinHostPort(targetCfg.Host, fmt.Sprintf("%d", port))
	client, err := ssh.Dial("tcp", addr, sshConfig)
	if err != nil {
		return nil, fmt.Errorf("ssh dial %s: %w", addr, err)
	}

	return &signResult{
		Client:      client,
		Serial:      resp.Serial,
		ExpiresAt:   resp.ExpiresAt,
		Certificate: resp.Certificate,
		Principal:   principal,
	}, nil
}

// CreateSession establishes a persistent SSH connection to the target host
// for multi-command workflows. The session is reusable via its returned ID.
func (p *ExecSessionPool) CreateSession(agentName, target, role string) (*ExecSession, error) {
	// Enforce per-agent session limit.
	p.mu.RLock()
	count := 0
	for _, s := range p.sessions {
		if s.AgentName == agentName {
			count++
		}
	}
	p.mu.RUnlock()

	if count >= p.maxPerAgent {
		return nil, fmt.Errorf("agent %q has reached max concurrent sessions (%d)", agentName, p.maxPerAgent)
	}

	// Look up principal for logging.
	p.broker.policyMu.RLock()
	roleCfg, roleExists := p.broker.policyCfg.Raw.Roles[role]
	p.broker.policyMu.RUnlock()
	if !roleExists {
		return nil, fmt.Errorf("unknown role %q", role)
	}
	principal := roleCfg.Principal

	// Sign and connect.
	sr, err := p.signAndConnect(agentName, target, role)
	if err != nil {
		p.broker.auditLog.LogEvent(audit.AuditEvent{
			Severity:  audit.SeverityWarn,
			EventType: "mcp_exec_error",
			Agent:     agentName,
			Target:    target,
			Role:      role,
			Details: map[string]string{
				"operation": "create_session",
				"error":     err.Error(),
			},
		})
		return nil, fmt.Errorf("sign and connect: %w", err)
	}

	// Register the certificate in CertState so it appears in the dashboard.
	p.broker.state.AddCert(&ActiveCert{
		Serial:      sr.Serial,
		AgentName:   agentName,
		Target:      target,
		Role:        role,
		Principal:   sr.Principal,
		IssuedAt:    time.Now(),
		ExpiresAt:   parseRFC3339(sr.ExpiresAt),
		Certificate: sr.Certificate,
	})

	// Generate session ID.
	sessionID, err := generateSessionID()
	if err != nil {
		sr.Client.Close()
		p.broker.state.RemoveCert(sr.Serial)
		return nil, err
	}

	now := time.Now()
	session := &ExecSession{
		ID:         sessionID,
		AgentName:  agentName,
		Target:     target,
		Role:       role,
		Principal:  principal,
		CertSerial: sr.Serial,
		SSHClient:  sr.Client,
		CreatedAt:  now,
		LastUsed:   now,
	}

	p.mu.Lock()
	p.sessions[sessionID] = session
	p.mu.Unlock()

	// Audit log.
	p.broker.auditLog.LogEvent(audit.AuditEvent{
		Severity:  audit.SeverityInfo,
		EventType: "mcp_session_create",
		Agent:     agentName,
		Target:    target,
		Role:      role,
		Serial:    sr.Serial,
		Details: map[string]string{
			"session_id": sessionID,
			"principal":  principal,
		},
	})

	p.broker.eventHub.Broadcast(Event{
		Type: "mcp_session_create",
		Data: map[string]string{
			"session_id": sessionID,
			"agent":      agentName,
			"target":     target,
			"role":       role,
		},
	})

	if p.broker.activityStore != nil {
		p.broker.activityStore.Record(&ActivityEntry{
			Agent:   agentName,
			Type:    ActivitySessionOpen,
			Target:  target,
			Role:    role,
			Success: true,
			Details: map[string]string{"session_id": sessionID},
		})
	}

	log.Printf("[mcp-exec] session %s created: agent=%s target=%s role=%s", sessionID, agentName, target, role)

	return session, nil
}

// execCommand runs a command on the given SSH client, capturing stdout and
// stderr. It respects the provided timeout in seconds (0 means default 30s).
// Returns the ExecResult with exit code, output, and duration.
func (p *ExecSessionPool) execCommand(client *ssh.Client, target, role, command string, timeout int) (*ExecResult, error) {
	if timeout <= 0 {
		timeout = 30
	}

	start := time.Now()

	// Open a new SSH session on the existing connection.
	session, err := client.NewSession()
	if err != nil {
		return nil, fmt.Errorf("open ssh session: %w", err)
	}
	defer session.Close()

	// Capture stdout and stderr.
	var stdoutBuf, stderrBuf bytes.Buffer
	session.Stdout = &stdoutBuf
	session.Stderr = &stderrBuf

	// Run the command with a timeout. We use a done channel since
	// ssh.Session.Run blocks and there is no context-aware variant.
	type runResult struct {
		err error
	}
	done := make(chan runResult, 1)
	go func() {
		done <- runResult{err: session.Run(command)}
	}()

	timer := time.NewTimer(time.Duration(timeout) * time.Second)
	defer timer.Stop()

	var exitCode int
	var runErr error

	select {
	case res := <-done:
		runErr = res.err
	case <-timer.C:
		// Timeout: signal the session to close, which will unblock Run.
		_ = session.Signal(ssh.SIGKILL)
		session.Close()
		elapsed := time.Since(start)
		return &ExecResult{
			Stdout:     stdoutBuf.String(),
			Stderr:     stderrBuf.String() + fmt.Sprintf("\n[timeout after %ds]", timeout),
			ExitCode:   -1,
			Target:     target,
			Role:       role,
			DurationMs: elapsed.Milliseconds(),
		}, nil
	}

	elapsed := time.Since(start)

	if runErr != nil {
		var exitErr *ssh.ExitError
		if errors.As(runErr, &exitErr) {
			exitCode = exitErr.ExitStatus()
		} else {
			// Non-exit error (e.g., connection issue).
			return &ExecResult{
				Stdout:     stdoutBuf.String(),
				Stderr:     stderrBuf.String() + "\n" + runErr.Error(),
				ExitCode:   -1,
				Target:     target,
				Role:       role,
				DurationMs: elapsed.Milliseconds(),
			}, nil
		}
	}

	return &ExecResult{
		Stdout:     stdoutBuf.String(),
		Stderr:     stderrBuf.String(),
		ExitCode:   exitCode,
		Target:     target,
		Role:       role,
		DurationMs: elapsed.Milliseconds(),
	}, nil
}

// ExecInSession runs a command on an existing persistent SSH session.
// The session is looked up by ID and must not be closed. A new ssh.Session
// is opened on the existing SSH client (SSH multiplexing).
// policyMs is the time spent on policy evaluation in the caller (toolExec).
func (p *ExecSessionPool) ExecInSession(agentName, sessionID, command string, timeout int, policyMs int64) (*ExecResult, error) {
	p.mu.RLock()
	session, exists := p.sessions[sessionID]
	p.mu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("session %q not found", sessionID)
	}

	// Verify the calling agent owns this session.
	if session.AgentName != agentName {
		return nil, fmt.Errorf("session %q is owned by a different agent", sessionID)
	}

	session.mu.Lock()
	if session.SSHClient == nil {
		session.mu.Unlock()
		return nil, fmt.Errorf("session %q is closed", sessionID)
	}
	client := session.SSHClient
	target := session.Target
	role := session.Role
	session.mu.Unlock()

	// Time the SSH command execution phase.
	sshStart := time.Now()
	result, err := p.execCommand(client, target, role, command, timeout)
	sshMs := time.Since(sshStart).Milliseconds()

	// Update last-used timestamp regardless of outcome.
	session.mu.Lock()
	session.LastUsed = time.Now()
	session.mu.Unlock()

	// Audit log.
	if err != nil {
		p.broker.auditLog.LogEvent(audit.AuditEvent{
			Severity:  audit.SeverityWarn,
			EventType: "mcp_exec_error",
			Agent:     agentName,
			Target:    target,
			Role:      role,
			Details: map[string]string{
				"session_id": sessionID,
				"command":    truncate(command, 200),
				"error":      err.Error(),
			},
		})
		return nil, err
	}

	// Populate latency breakdown for session-based exec (no cert phase).
	totalMs := result.DurationMs
	if policyMs > 0 {
		totalMs = policyMs + sshMs
	}
	result.Timings = &ExecTimings{
		PolicyMs: policyMs,
		CertMs:   0,
		SSHMs:    sshMs,
		TotalMs:  totalMs,
		Session:  true,
	}

	p.broker.auditLog.LogEvent(audit.AuditEvent{
		Severity:  audit.SeverityInfo,
		EventType: "mcp_exec",
		Agent:     agentName,
		Target:    target,
		Role:      role,
		Details: map[string]string{
			"session_id":  sessionID,
			"command":     truncate(command, 200),
			"exit_code":   fmt.Sprintf("%d", result.ExitCode),
			"duration_ms": fmt.Sprintf("%d", result.DurationMs),
			"policy_ms":   fmt.Sprintf("%d", policyMs),
			"ssh_ms":      fmt.Sprintf("%d", sshMs),
			"total_ms":    fmt.Sprintf("%d", totalMs),
			"session":     "true",
		},
	})

	p.broker.eventHub.Broadcast(Event{
		Type: "mcp_exec",
		Data: map[string]string{
			"agent":      agentName,
			"target":     target,
			"role":       role,
			"session_id": sessionID,
			"exit_code":  fmt.Sprintf("%d", result.ExitCode),
		},
	})

	if p.broker.activityStore != nil {
		p.broker.activityStore.Record(&ActivityEntry{
			Agent:      session.AgentName,
			Type:       ActivityExec,
			Target:     session.Target,
			Role:       session.Role,
			Command:    truncate(command, 200),
			StatusCode: result.ExitCode,
			DurationMs: result.DurationMs,
			Success:    result.ExitCode == 0,
		})
	}

	return result, nil
}

// ExecOneShot establishes a temporary SSH connection, runs a single command,
// and tears down the connection. Use this for isolated one-off commands.
// policyMs is the time spent on policy evaluation in the caller (toolExec).
func (p *ExecSessionPool) ExecOneShot(agentName, target, role, command string, timeout int, policyMs int64) (*ExecResult, error) {
	// Sign and connect (time the cert signing + SSH dial phase).
	certStart := time.Now()
	sr, err := p.signAndConnect(agentName, target, role)
	certMs := time.Since(certStart).Milliseconds()
	if err != nil {
		p.broker.auditLog.LogEvent(audit.AuditEvent{
			Severity:  audit.SeverityWarn,
			EventType: "mcp_exec_error",
			Agent:     agentName,
			Target:    target,
			Role:      role,
			Details: map[string]string{
				"operation": "exec_oneshot",
				"command":   truncate(command, 200),
				"error":     err.Error(),
			},
		})
		return nil, fmt.Errorf("sign and connect: %w", err)
	}
	defer sr.Client.Close()

	// Register the certificate in CertState so it appears in the dashboard
	// for the lifetime of this one-shot execution.
	p.broker.state.AddCert(&ActiveCert{
		Serial:      sr.Serial,
		AgentName:   agentName,
		Target:      target,
		Role:        role,
		Principal:   sr.Principal,
		IssuedAt:    time.Now(),
		ExpiresAt:   parseRFC3339(sr.ExpiresAt),
		Certificate: sr.Certificate,
	})
	defer p.broker.state.RemoveCert(sr.Serial)

	// Time the SSH command execution phase.
	sshStart := time.Now()
	result, err := p.execCommand(sr.Client, target, role, command, timeout)
	sshMs := time.Since(sshStart).Milliseconds()
	if err != nil {
		p.broker.auditLog.LogEvent(audit.AuditEvent{
			Severity:  audit.SeverityWarn,
			EventType: "mcp_exec_error",
			Agent:     agentName,
			Target:    target,
			Role:      role,
			Serial:    sr.Serial,
			Details: map[string]string{
				"operation": "exec_oneshot",
				"command":   truncate(command, 200),
				"error":     err.Error(),
			},
		})
		return nil, err
	}

	// Populate latency breakdown for one-shot exec.
	totalMs := policyMs + certMs + sshMs
	result.Timings = &ExecTimings{
		PolicyMs: policyMs,
		CertMs:   certMs,
		SSHMs:    sshMs,
		TotalMs:  totalMs,
		Session:  false,
	}

	// Audit log.
	p.broker.auditLog.LogEvent(audit.AuditEvent{
		Severity:  audit.SeverityInfo,
		EventType: "mcp_exec",
		Agent:     agentName,
		Target:    target,
		Role:      role,
		Serial:    sr.Serial,
		Details: map[string]string{
			"operation":   "oneshot",
			"command":     truncate(command, 200),
			"exit_code":   fmt.Sprintf("%d", result.ExitCode),
			"duration_ms": fmt.Sprintf("%d", result.DurationMs),
			"policy_ms":   fmt.Sprintf("%d", policyMs),
			"cert_ms":     fmt.Sprintf("%d", certMs),
			"ssh_ms":      fmt.Sprintf("%d", sshMs),
			"total_ms":    fmt.Sprintf("%d", totalMs),
		},
	})

	p.broker.eventHub.Broadcast(Event{
		Type: "mcp_exec",
		Data: map[string]string{
			"agent":     agentName,
			"target":    target,
			"role":      role,
			"operation": "oneshot",
			"exit_code": fmt.Sprintf("%d", result.ExitCode),
		},
	})

	// Record in activity store.
	if p.broker.activityStore != nil {
		p.broker.activityStore.Record(&ActivityEntry{
			Agent:      agentName,
			Type:       ActivityExec,
			Target:     target,
			Role:       role,
			Command:    truncate(command, 200),
			StatusCode: result.ExitCode,
			DurationMs: result.DurationMs,
			Success:    result.ExitCode == 0,
		})
	}

	return result, nil
}

// CloseSession tears down a persistent SSH session and removes it from the pool.
func (p *ExecSessionPool) CloseSession(agentName, sessionID string) error {
	p.mu.Lock()
	session, exists := p.sessions[sessionID]
	if !exists {
		p.mu.Unlock()
		return fmt.Errorf("session %q not found", sessionID)
	}
	// Verify the calling agent owns this session.
	if session.AgentName != agentName {
		p.mu.Unlock()
		return fmt.Errorf("session %q is owned by a different agent", sessionID)
	}
	delete(p.sessions, sessionID)
	p.mu.Unlock()

	session.mu.Lock()
	client := session.SSHClient
	session.SSHClient = nil
	target := session.Target
	role := session.Role
	certSerial := session.CertSerial
	created := session.CreatedAt
	session.mu.Unlock()

	if client != nil {
		client.Close()
	}

	// Remove the certificate from CertState so it no longer appears in the dashboard.
	if certSerial != "" {
		p.broker.state.RemoveCert(certSerial)
	}

	duration := time.Since(created)

	p.broker.auditLog.LogEvent(audit.AuditEvent{
		Severity:  audit.SeverityInfo,
		EventType: "mcp_session_close",
		Agent:     agentName,
		Target:    target,
		Role:      role,
		Duration:  duration.Round(time.Second).String(),
		Details: map[string]string{
			"session_id": sessionID,
		},
	})

	p.broker.eventHub.Broadcast(Event{
		Type: "mcp_session_close",
		Data: map[string]string{
			"session_id": sessionID,
			"agent":      agentName,
			"target":     target,
		},
	})

	if p.broker.activityStore != nil {
		p.broker.activityStore.Record(&ActivityEntry{
			Agent:   session.AgentName,
			Type:    ActivitySessionClose,
			Target:  session.Target,
			Role:    session.Role,
			Success: true,
			Details: map[string]string{"session_id": sessionID},
		})
	}

	log.Printf("[mcp-exec] session %s closed: agent=%s target=%s duration=%s", sessionID, agentName, target, duration.Round(time.Second))

	return nil
}

// ListSessions returns a safe subset of session information for the given
// agent. If agentName is empty, all sessions are returned.
func (p *ExecSessionPool) ListSessions(agentName string) []*ExecSessionInfo {
	p.mu.RLock()
	defer p.mu.RUnlock()

	result := make([]*ExecSessionInfo, 0, len(p.sessions))
	for _, s := range p.sessions {
		if agentName != "" && s.AgentName != agentName {
			continue
		}
		result = append(result, &ExecSessionInfo{
			ID:        s.ID,
			Target:    s.Target,
			Role:      s.Role,
			CreatedAt: s.CreatedAt,
			LastUsed:  s.LastUsed,
		})
	}
	return result
}

// cleanup runs in a background goroutine, closing sessions that have been
// idle for more than 5 minutes. It checks every 60 seconds.
func (p *ExecSessionPool) cleanup() {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	const maxIdleDuration = 5 * time.Minute

	for range ticker.C {
		p.mu.RLock()
		type expiredSession struct {
			id        string
			agentName string
		}
		var expired []expiredSession
		for id, s := range p.sessions {
			s.mu.Lock()
			idle := time.Since(s.LastUsed)
			agent := s.AgentName
			s.mu.Unlock()
			if idle > maxIdleDuration {
				expired = append(expired, expiredSession{id: id, agentName: agent})
			}
		}
		p.mu.RUnlock()

		for _, es := range expired {
			log.Printf("[mcp-exec] closing idle session %s (idle > %s)", es.id, maxIdleDuration)
			if err := p.CloseSession(es.agentName, es.id); err != nil {
				log.Printf("[mcp-exec] error closing idle session %s: %v", es.id, err)
			}
		}
	}
}

// truncate shortens a string to the given maximum length, appending "..."
// if truncation occurs. Used for audit log entries to avoid huge payloads.
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	if maxLen <= 3 {
		return s[:maxLen]
	}
	return s[:maxLen-3] + "..."
}
