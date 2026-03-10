package policy

import (
	"fmt"
	"sync"
	"time"
)

// Engine is the thread-safe policy evaluation engine. It holds the current
// resolved policy configuration and tracks active certificates for
// concurrency and deduplication checks.
type Engine struct {
	mu       sync.RWMutex
	resolved *ResolvedConfig
	loader   *Loader

	// certsMu guards the active certificate maps independently of the
	// policy config lock so cert tracking never blocks evaluation reads.
	certsMu     sync.Mutex
	certs       map[uint64]*TrackedCert            // serial -> cert
	agentCounts map[int]int                        // agentUID -> active count
	activeSigs  map[string]uint64                  // "uid:target:role" -> serial
}

// NewEngine creates a policy engine from a Loader and its initial resolved config.
func NewEngine(loader *Loader, resolved *ResolvedConfig) *Engine {
	return &Engine{
		resolved:    resolved,
		loader:      loader,
		certs:       make(map[uint64]*TrackedCert),
		agentCounts: make(map[int]int),
		activeSigs:  make(map[string]uint64),
	}
}

// Reload triggers a hot-reload of the policy file via the Loader.
// If the new config is invalid the engine keeps the previous config.
func (e *Engine) Reload() error {
	rc, err := e.loader.Reload()
	if err != nil {
		return err
	}
	e.mu.Lock()
	e.resolved = rc
	e.mu.Unlock()
	return nil
}

// Config returns the current resolved configuration (safe for concurrent reads).
func (e *Engine) Config() *ResolvedConfig {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.resolved
}

// Evaluate runs the full policy pipeline against a certificate request.
//
// Pipeline:
//  1. Agent exists (by UID)
//  2. Target exists
//  3. Role is in target's allowed_roles
//  4. Duration clamped to min(requested, target.max_ttl, global.max_ttl)
//  5. Agent concurrent cert count < limit
//  6. No duplicate active cert for same agent+target+role
//  7. Global active cert count < limit
//  8. Auto-approve check -> Approve or Pending
func (e *Engine) Evaluate(req EvalRequest) EvalResult {
	// Purge expired certs before evaluating so stale entries don't block new requests.
	e.CleanExpired()

	e.mu.RLock()
	rc := e.resolved
	e.mu.RUnlock()

	cfg := rc.Raw

	// 1. Agent exists by UID.
	agentName, agent, ok := findAgentByUID(cfg.Agents, req.AgentUID)
	if !ok {
		return EvalResult{
			Decision: Deny,
			Reason:   fmt.Sprintf("unknown agent UID %d", req.AgentUID),
		}
	}
	_ = agentName // used only for lookup

	// 2. Target exists.
	target, ok := cfg.Targets[req.TargetName]
	if !ok {
		return EvalResult{
			Decision: Deny,
			Reason:   fmt.Sprintf("unknown target %q", req.TargetName),
		}
	}

	// 3. Role allowed for target.
	if !roleAllowed(target.AllowedRoles, req.RoleName) {
		return EvalResult{
			Decision: Deny,
			Reason:   fmt.Sprintf("role %q not allowed on target %q", req.RoleName, req.TargetName),
		}
	}

	// Look up the role definition for the principal.
	roleDef, ok := cfg.Roles[req.RoleName]
	if !ok {
		return EvalResult{
			Decision: Deny,
			Reason:   fmt.Sprintf("role %q not defined in policy", req.RoleName),
		}
	}

	// 4. Clamp duration.
	dur := req.Duration
	if dur <= 0 {
		dur = rc.GlobalDefaultTTL
	}
	targetMax := rc.TargetMaxTTLs[req.TargetName]
	if dur > targetMax {
		dur = targetMax
	}
	if dur > rc.GlobalMaxTTL {
		dur = rc.GlobalMaxTTL
	}

	// Steps 5-7 require the cert tracking lock.
	e.certsMu.Lock()
	defer e.certsMu.Unlock()

	// 5. Agent concurrent cert count.
	if e.agentCounts[req.AgentUID] >= agent.MaxConcurrentCerts {
		return EvalResult{
			Decision: Deny,
			Reason: fmt.Sprintf("agent UID %d at concurrent cert limit (%d)",
				req.AgentUID, agent.MaxConcurrentCerts),
		}
	}

	// 6. Duplicate active cert for same agent+target+role: auto-revoke the old one.
	// The agent clearly wants a fresh cert, so the stale one is no longer needed.
	sig := certSig(req.AgentUID, req.TargetName, req.RoleName)
	if oldSerial, dup := e.activeSigs[sig]; dup {
		e.removeCertLocked(oldSerial)
	}

	// 7. Global active cert count.
	if len(e.certs) >= cfg.Global.MaxActiveCerts {
		return EvalResult{
			Decision: Deny,
			Reason: fmt.Sprintf("global active cert limit reached (%d)",
				cfg.Global.MaxActiveCerts),
		}
	}

	// 8. Auto-approve or pending.
	decision := Pending
	reason := "awaiting manual approval"
	if target.AutoApprove {
		decision = Approve
		reason = "auto-approved"
	}

	return EvalResult{
		Decision:        decision,
		Reason:          reason,
		ClampedDuration: dur,
		Principal:       roleDef.Principal,
	}
}

// TrackCert registers an issued certificate for concurrency tracking.
func (e *Engine) TrackCert(serial uint64, agentUID int, target string, role string, expiresAt time.Time) {
	e.certsMu.Lock()
	defer e.certsMu.Unlock()

	tc := &TrackedCert{
		Serial:    serial,
		AgentUID:  agentUID,
		Target:    target,
		Role:      role,
		ExpiresAt: expiresAt,
	}

	e.certs[serial] = tc
	e.agentCounts[agentUID]++
	e.activeSigs[certSig(agentUID, target, role)] = serial
}

// RemoveCert unregisters a certificate by serial number.
func (e *Engine) RemoveCert(serial uint64) {
	e.certsMu.Lock()
	defer e.certsMu.Unlock()

	e.removeCertLocked(serial)
}

// CleanExpired removes all certificates whose expiry is before time.Now().
func (e *Engine) CleanExpired() int {
	now := time.Now()
	e.certsMu.Lock()
	defer e.certsMu.Unlock()

	removed := 0
	for serial, tc := range e.certs {
		if tc.ExpiresAt.Before(now) {
			e.removeCertLocked(serial)
			removed++
		}
	}
	return removed
}

// ActiveCertsForAgent returns the number of active certs for the given agent UID.
func (e *Engine) ActiveCertsForAgent(uid int) int {
	e.certsMu.Lock()
	defer e.certsMu.Unlock()
	return e.agentCounts[uid]
}

// ActiveCertsTotal returns the total number of active certs across all agents.
func (e *Engine) ActiveCertsTotal() int {
	e.certsMu.Lock()
	defer e.certsMu.Unlock()
	return len(e.certs)
}

// removeCertLocked removes a cert from all tracking structures.
// Caller must hold e.certsMu.
func (e *Engine) removeCertLocked(serial uint64) {
	tc, ok := e.certs[serial]
	if !ok {
		return
	}

	delete(e.certs, serial)

	if e.agentCounts[tc.AgentUID] > 0 {
		e.agentCounts[tc.AgentUID]--
	}
	if e.agentCounts[tc.AgentUID] == 0 {
		delete(e.agentCounts, tc.AgentUID)
	}

	sig := certSig(tc.AgentUID, tc.Target, tc.Role)
	if e.activeSigs[sig] == serial {
		delete(e.activeSigs, sig)
	}
}

// findAgentByUID scans the agents map for a matching UID. Returns the agent
// name and policy if found.
func findAgentByUID(agents map[string]AgentPolicy, uid int) (string, AgentPolicy, bool) {
	for name, agent := range agents {
		if agent.UID == uid {
			return name, agent, true
		}
	}
	return "", AgentPolicy{}, false
}

// roleAllowed checks whether a role name appears in a target's allowed list.
func roleAllowed(allowed []string, role string) bool {
	for _, r := range allowed {
		if r == role {
			return true
		}
	}
	return false
}

// certSig produces a deduplication key for agent+target+role combinations.
func certSig(agentUID int, target, role string) string {
	return fmt.Sprintf("%d:%s:%s", agentUID, target, role)
}
