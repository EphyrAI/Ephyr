package broker

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sprawl/clauth/internal/policy"
	"golang.org/x/crypto/bcrypt"
)

// MCPAuthenticator manages API key authentication for MCP agents.
// Agents are registered with bcrypt-hashed API keys and validated
// using constant-time comparison (inherent in bcrypt).
//
// An in-memory auth cache avoids repeated bcrypt comparisons for the
// same API key. Cache entries are keyed on SHA-256(apiKey) and expire
// after a configurable TTL (default 60s).
type MCPAuthenticator struct {
	mu     sync.RWMutex
	agents map[string]*MCPAgentConfig // keyed by agent name

	// Auth result cache: SHA-256(apiKey) -> cached result.
	cacheMu  sync.RWMutex
	cache    map[string]*authCacheEntry
	cacheTTL time.Duration

	// Observable counters.
	cacheHits   atomic.Int64
	cacheMisses atomic.Int64
}

// authCacheEntry stores a successful authentication result with expiry.
type authCacheEntry struct {
	agent   *MCPAgent
	expires time.Time
}

// MCPAgentConfig holds the configuration for a single MCP agent,
// including the bcrypt hash of its API key.
type MCPAgentConfig struct {
	Name          string   // agent identifier (matches policy agent name)
	APIKeyHash    string   // bcrypt hash of the API key
	Roles         []string // allowed roles for this agent
	MaxConcurrent int      // maximum concurrent certificates
	AutoApprove   bool     // whether requests are auto-approved
	Perms         *policy.ResolvedAgentPerms // RBAC permissions (nil = use legacy behavior)
}

const defaultAuthCacheTTL = 60 * time.Second

// NewMCPAuthenticator creates an MCPAuthenticator with an empty agent registry.
// Use AddAgent to register agents before handling requests.
func NewMCPAuthenticator() *MCPAuthenticator {
	return &MCPAuthenticator{
		agents:   make(map[string]*MCPAgentConfig),
		cache:    make(map[string]*authCacheEntry),
		cacheTTL: defaultAuthCacheTTL,
	}
}

// SetCacheTTL configures the auth cache TTL. Set to 0 to disable caching.
func (a *MCPAuthenticator) SetCacheTTL(ttl time.Duration) {
	a.cacheMu.Lock()
	defer a.cacheMu.Unlock()
	a.cacheTTL = ttl
}

// CacheStats returns the number of cache hits and misses.
func (a *MCPAuthenticator) CacheStats() (hits, misses int64) {
	return a.cacheHits.Load(), a.cacheMisses.Load()
}

// AddAgent registers an agent configuration for API key authentication.
// If an agent with the same name already exists, it is replaced.
// Adding/removing agents invalidates the cache.
func (a *MCPAuthenticator) AddAgent(cfg MCPAgentConfig) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.agents[cfg.Name] = &cfg
	a.invalidateCache()
}

// RemoveAgent unregisters an agent by name.
func (a *MCPAuthenticator) RemoveAgent(name string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.agents, name)
	a.invalidateCache()
}

// invalidateCache clears the auth cache. Caller must hold a.mu.
func (a *MCPAuthenticator) invalidateCache() {
	a.cacheMu.Lock()
	defer a.cacheMu.Unlock()
	a.cache = make(map[string]*authCacheEntry)
}

// apiKeyFingerprint returns a hex-encoded SHA-256 hash of the API key.
// Used as cache key — never store the raw API key.
func apiKeyFingerprint(apiKey string) string {
	h := sha256.Sum256([]byte(apiKey))
	return hex.EncodeToString(h[:])
}

// Authenticate validates an API key against all registered agents.
// It first checks the auth cache for a recent successful match.
// On cache miss, it iterates through all agents and uses
// bcrypt.CompareHashAndPassword for comparison, then caches the result.
func (a *MCPAuthenticator) Authenticate(apiKey string) (*MCPAgent, error) {
	fp := apiKeyFingerprint(apiKey)

	// Fast path: check cache.
	a.cacheMu.RLock()
	if entry, ok := a.cache[fp]; ok && time.Now().Before(entry.expires) {
		agent := entry.agent
		a.cacheMu.RUnlock()
		a.cacheHits.Add(1)
		return agent, nil
	}
	a.cacheMu.RUnlock()

	a.cacheMisses.Add(1)

	// Slow path: bcrypt comparison.
	a.mu.RLock()
	defer a.mu.RUnlock()

	if len(a.agents) == 0 {
		return nil, fmt.Errorf("no agents registered")
	}

	apiKeyBytes := []byte(apiKey)

	for _, cfg := range a.agents {
		if cfg.APIKeyHash == "" {
			continue
		}
		err := bcrypt.CompareHashAndPassword([]byte(cfg.APIKeyHash), apiKeyBytes)
		if err == nil {
			// Match found — build agent and cache it.
			agent := &MCPAgent{
				Name:          cfg.Name,
				Roles:         cfg.Roles,
				MaxConcurrent: cfg.MaxConcurrent,
				AutoApprove:   cfg.AutoApprove,
				Perms:         cfg.Perms,
			}
			a.cacheResult(fp, agent)
			return agent, nil
		}
	}

	return nil, fmt.Errorf("invalid API key")
}

// cacheResult stores a successful auth result in the cache.
func (a *MCPAuthenticator) cacheResult(fingerprint string, agent *MCPAgent) {
	a.cacheMu.Lock()
	defer a.cacheMu.Unlock()
	if a.cacheTTL <= 0 {
		return
	}
	a.cache[fingerprint] = &authCacheEntry{
		agent:   agent,
		expires: time.Now().Add(a.cacheTTL),
	}
}

// GenerateKeyHash creates a bcrypt hash from a plaintext API key.
// Uses the default bcrypt cost (10). This is a helper for provisioning
// new agent API keys.
func (a *MCPAuthenticator) GenerateKeyHash(plaintext string) (string, error) {
	if plaintext == "" {
		return "", fmt.Errorf("plaintext key must not be empty")
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(plaintext), bcrypt.DefaultCost)
	if err != nil {
		return "", fmt.Errorf("bcrypt hash generation failed: %w", err)
	}

	return string(hash), nil
}

// AgentCount returns the number of registered agents.
func (a *MCPAuthenticator) AgentCount() int {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return len(a.agents)
}

// ListAgentNames returns the names of all registered agents.
func (a *MCPAuthenticator) ListAgentNames() []string {
	a.mu.RLock()
	defer a.mu.RUnlock()

	names := make([]string, 0, len(a.agents))
	for name := range a.agents {
		names = append(names, name)
	}
	return names
}
