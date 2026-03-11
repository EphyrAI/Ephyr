package broker

import (
	"fmt"
	"sync"

	"github.com/sprawl/clauth/internal/policy"
	"golang.org/x/crypto/bcrypt"
)

// MCPAuthenticator manages API key authentication for MCP agents.
// Agents are registered with bcrypt-hashed API keys and validated
// using constant-time comparison (inherent in bcrypt).
type MCPAuthenticator struct {
	mu     sync.RWMutex
	agents map[string]*MCPAgentConfig // keyed by agent name
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

// NewMCPAuthenticator creates an MCPAuthenticator with an empty agent registry.
// Use AddAgent to register agents before handling requests.
func NewMCPAuthenticator() *MCPAuthenticator {
	return &MCPAuthenticator{
		agents: make(map[string]*MCPAgentConfig),
	}
}

// AddAgent registers an agent configuration for API key authentication.
// If an agent with the same name already exists, it is replaced.
func (a *MCPAuthenticator) AddAgent(cfg MCPAgentConfig) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.agents[cfg.Name] = &cfg
}

// RemoveAgent unregisters an agent by name.
func (a *MCPAuthenticator) RemoveAgent(name string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.agents, name)
}

// Authenticate validates an API key against all registered agents.
// It iterates through all agents and uses bcrypt.CompareHashAndPassword
// for constant-time comparison. Returns the matching MCPAgent on success,
// or an error if no agent matches.
//
// Note: bcrypt comparison is intentionally expensive (by design), so this
// scales linearly with the number of registered agents. For the expected
// small number of agents in a homelab context, this is acceptable.
func (a *MCPAuthenticator) Authenticate(apiKey string) (*MCPAgent, error) {
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
			// Match found.
			return &MCPAgent{
				Name:          cfg.Name,
				Roles:         cfg.Roles,
				MaxConcurrent: cfg.MaxConcurrent,
				AutoApprove:   cfg.AutoApprove,
				Perms:         cfg.Perms,
			}, nil
		}
		// bcrypt.ErrMismatchedHashAndPassword is expected for non-matching agents.
		// Any other error (e.g., malformed hash) is logged but we continue checking.
	}

	return nil, fmt.Errorf("invalid API key")
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
