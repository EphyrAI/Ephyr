package broker

import (
	"crypto/rand"
	"encoding/hex"
	"log"
	"sync"
	"time"
)

// GrantType distinguishes SSH certificates from service/MCP access grants.
type GrantType string

const (
	GrantTypeSSHCert GrantType = "ssh_cert"
	GrantTypeService GrantType = "service"
	GrantTypeMCP     GrantType = "mcp"
)

// GrantMode controls whether TTL grants are required or skipped.
type GrantMode string

const (
	// GrantModeTTL requires a valid time-limited grant (default).
	GrantModeTTL GrantMode = "ttl"
	// GrantModePassthrough skips grant issuance entirely (fire-and-forget).
	GrantModePassthrough GrantMode = "passthrough"
)

// AccessGrant represents a time-limited access grant for any resource type.
// SSH certificates are tracked separately in CertState; service and MCP
// grants live here.
type AccessGrant struct {
	ID        string            `json:"id"`
	Type      GrantType         `json:"type"`
	Agent     string            `json:"agent"`
	Target    string            `json:"target"` // service name or remote name
	IssuedAt  time.Time         `json:"issued_at"`
	ExpiresAt time.Time         `json:"expires_at"`
	Status    string            `json:"status"` // "active", "expired", "revoked"
	Details   map[string]string `json:"details,omitempty"`
}

// GrantStore is an in-memory store for service and MCP access grants.
// It mirrors the pattern of CertState but for non-SSH access types.
type GrantStore struct {
	mu     sync.RWMutex
	grants map[string]*AccessGrant // id -> grant
	stopCh chan struct{}

	// Default TTL for service and MCP grants.
	DefaultServiceTTL time.Duration
	DefaultMCPTTL     time.Duration

	// Global grant mode (can be overridden per-service or per-remote).
	Mode GrantMode
}

// NewGrantStore creates a new grant store and starts the background
// cleanup goroutine. Default TTLs are 5 minutes for both types.
func NewGrantStore() *GrantStore {
	gs := &GrantStore{
		grants:            make(map[string]*AccessGrant),
		stopCh:            make(chan struct{}),
		DefaultServiceTTL: 5 * time.Minute,
		DefaultMCPTTL:     5 * time.Minute,
		Mode:              GrantModeTTL,
	}
	go gs.cleanupLoop()
	return gs
}

// Stop halts the background cleanup goroutine.
func (gs *GrantStore) Stop() {
	close(gs.stopCh)
}

// cleanupLoop removes expired grants every 30 seconds.
func (gs *GrantStore) cleanupLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			gs.cleanExpired()
		case <-gs.stopCh:
			return
		}
	}
}

// cleanExpired marks expired grants and removes very old ones.
func (gs *GrantStore) cleanExpired() {
	gs.mu.Lock()
	defer gs.mu.Unlock()
	now := time.Now()
	for id, g := range gs.grants {
		if g.Status == "active" && g.ExpiresAt.Before(now) {
			g.Status = "expired"
		}
		// Remove grants expired more than 10 minutes ago.
		if g.Status != "active" && g.ExpiresAt.Add(10*time.Minute).Before(now) {
			delete(gs.grants, id)
		}
	}
}

// Issue creates a new access grant for an agent+target pair.
// If a valid grant already exists for this agent+type+target, it is returned
// instead of creating a new one.
func (gs *GrantStore) Issue(grantType GrantType, agent, target string, ttl time.Duration, details map[string]string) *AccessGrant {
	gs.mu.Lock()
	defer gs.mu.Unlock()

	now := time.Now()

	// Check for existing valid grant.
	for _, g := range gs.grants {
		if g.Type == grantType && g.Agent == agent && g.Target == target && g.Status == "active" && g.ExpiresAt.After(now) {
			return g
		}
	}

	// Set default TTL if not specified.
	if ttl <= 0 {
		switch grantType {
		case GrantTypeService:
			ttl = gs.DefaultServiceTTL
		case GrantTypeMCP:
			ttl = gs.DefaultMCPTTL
		default:
			ttl = 5 * time.Minute
		}
	}

	grant := &AccessGrant{
		ID:        generateGrantID(),
		Type:      grantType,
		Agent:     agent,
		Target:    target,
		IssuedAt:  now,
		ExpiresAt: now.Add(ttl),
		Status:    "active",
		Details:   details,
	}

	gs.grants[grant.ID] = grant
	log.Printf("[grants] issued %s grant %s: agent=%s target=%s ttl=%s", grantType, grant.ID[:12], agent, target, ttl)
	return grant
}

// Validate checks whether an agent has a valid (non-expired, non-revoked)
// grant for the given type and target. Returns the grant if valid, nil otherwise.
func (gs *GrantStore) Validate(grantType GrantType, agent, target string) *AccessGrant {
	gs.mu.RLock()
	defer gs.mu.RUnlock()

	now := time.Now()
	for _, g := range gs.grants {
		if g.Type == grantType && g.Agent == agent && g.Target == target && g.Status == "active" && g.ExpiresAt.After(now) {
			return g
		}
	}
	return nil
}

// Revoke invalidates a grant by ID. Returns true if found and revoked,
// or false with a reason string ("not found" or "already revoked").
func (gs *GrantStore) Revoke(id string) (bool, string) {
	gs.mu.Lock()
	defer gs.mu.Unlock()
	g, ok := gs.grants[id]
	if !ok {
		return false, "grant not found"
	}
	if g.Status == "revoked" {
		return false, "grant already revoked"
	}
	g.Status = "revoked"
	log.Printf("[grants] revoked %s grant %s: agent=%s target=%s", g.Type, id[:12], g.Agent, g.Target)
	return true, ""
}

// Get retrieves a grant by ID.
func (gs *GrantStore) Get(id string) (*AccessGrant, bool) {
	gs.mu.RLock()
	defer gs.mu.RUnlock()
	g, ok := gs.grants[id]
	if !ok {
		return nil, false
	}
	c := *g
	return &c, true
}

// ListAll returns all grants (including expired/revoked recent ones).
func (gs *GrantStore) ListAll() []*AccessGrant {
	gs.mu.RLock()
	defer gs.mu.RUnlock()
	result := make([]*AccessGrant, 0, len(gs.grants))
	for _, g := range gs.grants {
		c := *g
		result = append(result, &c)
	}
	return result
}

// ListActive returns only active (non-expired, non-revoked) grants.
func (gs *GrantStore) ListActive() []*AccessGrant {
	gs.mu.RLock()
	defer gs.mu.RUnlock()
	now := time.Now()
	result := make([]*AccessGrant, 0)
	for _, g := range gs.grants {
		if g.Status == "active" && g.ExpiresAt.After(now) {
			c := *g
			result = append(result, &c)
		}
	}
	return result
}

// ListByAgent returns all active grants for a specific agent.
func (gs *GrantStore) ListByAgent(agent string) []*AccessGrant {
	gs.mu.RLock()
	defer gs.mu.RUnlock()
	now := time.Now()
	result := make([]*AccessGrant, 0)
	for _, g := range gs.grants {
		if g.Agent == agent && g.Status == "active" && g.ExpiresAt.After(now) {
			c := *g
			result = append(result, &c)
		}
	}
	return result
}

// ActiveCount returns the number of currently active grants.
func (gs *GrantStore) ActiveCount() int {
	gs.mu.RLock()
	defer gs.mu.RUnlock()
	now := time.Now()
	count := 0
	for _, g := range gs.grants {
		if g.Status == "active" && g.ExpiresAt.After(now) {
			count++
		}
	}
	return count
}

// generateGrantID creates a random 16-byte hex string for grant IDs.
func generateGrantID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
