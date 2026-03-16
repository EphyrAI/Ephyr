package policy

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
	"gopkg.in/yaml.v3"
)

// Loader manages loading and hot-reloading policy configuration from a YAML file.
type Loader struct {
	mu       sync.RWMutex
	path     string
	resolved *ResolvedConfig
}

// LoadFromFile reads the YAML policy file at path, validates it, and returns
// both a Loader (for hot-reload) and the initial ResolvedConfig.
func LoadFromFile(path string) (*Loader, *ResolvedConfig, error) {
	l := &Loader{path: path}
	rc, err := l.load()
	if err != nil {
		return nil, nil, fmt.Errorf("loading policy from %s: %w", path, err)
	}
	l.resolved = rc
	return l, rc, nil
}

// Resolved returns the current resolved configuration (thread-safe).
func (l *Loader) Resolved() *ResolvedConfig {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.resolved
}

// Reload re-reads the policy file from the original path and replaces the
// current configuration atomically. If the new file is invalid, the existing
// config is preserved and an error is returned.
func (l *Loader) Reload() (*ResolvedConfig, error) {
	rc, err := l.load()
	if err != nil {
		return nil, fmt.Errorf("reloading policy from %s: %w", l.path, err)
	}
	l.mu.Lock()
	l.resolved = rc
	l.mu.Unlock()
	return rc, nil
}

// load does the actual read-parse-validate cycle.
func (l *Loader) load() (*ResolvedConfig, error) {
	data, err := os.ReadFile(l.path)
	if err != nil {
		return nil, fmt.Errorf("reading file: %w", err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing YAML: %w", err)
	}

	applyDefaults(&cfg)

	rc, err := validate(&cfg)
	if err != nil {
		return nil, fmt.Errorf("validation: %w", err)
	}

	return rc, nil
}

// applyDefaults fills in zero-value fields with sensible defaults.
func applyDefaults(cfg *Config) {
	if cfg.Global.MaxActiveCerts == 0 {
		cfg.Global.MaxActiveCerts = 10
	}
	if cfg.Global.DefaultTTL == "" {
		cfg.Global.DefaultTTL = "5m"
	}
	if cfg.Global.MaxTTL == "" {
		cfg.Global.MaxTTL = "30m"
	}
	if cfg.Global.RateLimit.RequestsPerWindow == 0 {
		cfg.Global.RateLimit.RequestsPerWindow = 10
	}
	if cfg.Global.RateLimit.WindowSeconds == 0 {
		cfg.Global.RateLimit.WindowSeconds = 60
	}

	for name, agent := range cfg.Agents {
		if agent.MaxConcurrentCerts == 0 {
			agent.MaxConcurrentCerts = 3
		}
		cfg.Agents[name] = agent
	}

	for name, target := range cfg.Targets {
		if target.Port == 0 {
			target.Port = 22
		}
		cfg.Targets[name] = target
	}
}

// validate checks the config for internal consistency and parses all duration
// strings. Returns a ResolvedConfig on success.
func validate(cfg *Config) (*ResolvedConfig, error) {
	// Parse global durations.
	globalDefaultTTL, err := time.ParseDuration(cfg.Global.DefaultTTL)
	if err != nil {
		return nil, fmt.Errorf("invalid global default_ttl %q: %w", cfg.Global.DefaultTTL, err)
	}
	globalMaxTTL, err := time.ParseDuration(cfg.Global.MaxTTL)
	if err != nil {
		return nil, fmt.Errorf("invalid global max_ttl %q: %w", cfg.Global.MaxTTL, err)
	}
	if globalDefaultTTL > globalMaxTTL {
		return nil, fmt.Errorf("global default_ttl (%s) exceeds max_ttl (%s)", globalDefaultTTL, globalMaxTTL)
	}

	// Check that we have at least one agent.
	if len(cfg.Agents) == 0 {
		return nil, fmt.Errorf("no agents defined")
	}

	// Check for duplicate agent UIDs.
	uidSeen := make(map[int]string)
	for name, agent := range cfg.Agents {
		if prev, ok := uidSeen[agent.UID]; ok {
			return nil, fmt.Errorf("duplicate UID %d: agents %q and %q", agent.UID, prev, name)
		}
		uidSeen[agent.UID] = name
	}

	// Validate template references: check that all inherits references exist.
	for name, agent := range cfg.Agents {
		for _, tmplName := range agent.Inherits {
			if _, ok := cfg.Templates[tmplName]; !ok {
				return nil, fmt.Errorf("agent %q inherits undefined template %q", name, tmplName)
			}
		}
	}

	// Check that all roles referenced by targets are defined.
	targetMaxTTLs := make(map[string]time.Duration, len(cfg.Targets))

	// Track hosts to detect duplicate target definitions pointing at the same host:port.
	hostSeen := make(map[string]string)

	for name, target := range cfg.Targets {
		// Duplicate host:port check.
		key := fmt.Sprintf("%s:%d", target.Host, target.Port)
		if prev, ok := hostSeen[key]; ok {
			return nil, fmt.Errorf("duplicate target host %s: targets %q and %q", key, prev, name)
		}
		hostSeen[key] = name

		// Validate allowed_roles reference defined roles.
		for _, role := range target.AllowedRoles {
			if _, ok := cfg.Roles[role]; !ok {
				return nil, fmt.Errorf("target %q references undefined role %q", name, role)
			}
		}

		// Parse target max_ttl if set.
		if target.MaxTTL != "" {
			ttl, err := time.ParseDuration(target.MaxTTL)
			if err != nil {
				return nil, fmt.Errorf("target %q has invalid max_ttl %q: %w", name, target.MaxTTL, err)
			}
			if ttl > globalMaxTTL {
				return nil, fmt.Errorf("target %q max_ttl (%s) exceeds global max_ttl (%s)", name, ttl, globalMaxTTL)
			}
			targetMaxTTLs[name] = ttl
		} else {
			targetMaxTTLs[name] = globalMaxTTL
		}

		// Validate host is non-empty.
		if target.Host == "" {
			return nil, fmt.Errorf("target %q has empty host", name)
		}
	}

	// Validate role definitions have principals.
	for name, role := range cfg.Roles {
		if role.Principal == "" {
			return nil, fmt.Errorf("role %q has empty principal", name)
		}
	}

	// Parse and validate host keys for targets (T6).
	targetHostKeys := make(map[string]ssh.PublicKey)
	for name, target := range cfg.Targets {
		if target.HostKey != "" {
			parsedKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(target.HostKey))
			if err != nil {
				return nil, fmt.Errorf("target %q has invalid host_key: %w", name, err)
			}
			targetHostKeys[name] = parsedKey

			// Cross-validate fingerprint if both are set.
			if target.HostKeyFingerprint != "" {
				hash := sha256.Sum256(parsedKey.Marshal())
				computedFP := "SHA256:" + base64.RawStdEncoding.EncodeToString(hash[:])
				if computedFP != target.HostKeyFingerprint {
					return nil, fmt.Errorf("target %q host_key_fingerprint %q does not match host_key (computed %s)",
						name, target.HostKeyFingerprint, computedFP)
				}
			}
		} else if target.HostKeyFingerprint != "" {
			// Validate fingerprint format.
			if !strings.HasPrefix(target.HostKeyFingerprint, "SHA256:") {
				return nil, fmt.Errorf("target %q host_key_fingerprint must start with \"SHA256:\", got %q",
					name, target.HostKeyFingerprint)
			}
		}
	}

	// If host_key_strict is set, ensure every target has at least one host key field.
	if cfg.Global.HostKeyStrict {
		for name, target := range cfg.Targets {
			if target.HostKey == "" && target.HostKeyFingerprint == "" {
				return nil, fmt.Errorf("host_key_strict is enabled but target %q has no host_key or host_key_fingerprint", name)
			}
		}
	}

	rc := &ResolvedConfig{
		Raw:              cfg,
		GlobalDefaultTTL: globalDefaultTTL,
		GlobalMaxTTL:     globalMaxTTL,
		TargetMaxTTLs:    targetMaxTTLs,
		TargetHostKeys:   targetHostKeys,
	}

	// Resolve RBAC permissions for all agents.
	rc.AgentPerms = ResolveAgentPerms(cfg)

	return rc, nil
}
