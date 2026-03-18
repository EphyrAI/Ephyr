package policy

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// Severity indicates the severity of a validation finding.
type Severity int

const (
	// SeverityOK indicates a check passed.
	SeverityOK Severity = iota
	// SeverityWarn indicates a non-fatal issue.
	SeverityWarn
	// SeverityError indicates a fatal policy error.
	SeverityError
)

// String returns a human-readable severity label.
func (s Severity) String() string {
	switch s {
	case SeverityOK:
		return "OK"
	case SeverityWarn:
		return "WARN"
	case SeverityError:
		return "ERROR"
	default:
		return "UNKNOWN"
	}
}

// ValidationResult is a single finding from policy validation.
type ValidationResult struct {
	Section  string   // e.g. "global", "roles", "targets", "agents"
	Severity Severity // OK, WARN, or ERROR
	Code     string   // machine-readable code, e.g. "E1", "W3"
	Message  string   // human-readable description
}

// ValidationReport collects all findings from policy validation.
type ValidationReport struct {
	Results  []ValidationResult
	Errors   int
	Warnings int
}

// add appends a result and updates counters.
func (r *ValidationReport) add(section string, sev Severity, code, msg string) {
	r.Results = append(r.Results, ValidationResult{
		Section:  section,
		Severity: sev,
		Code:     code,
		Message:  msg,
	})
	switch sev {
	case SeverityWarn:
		r.Warnings++
	case SeverityError:
		r.Errors++
	}
}

// ok adds a passing result.
func (r *ValidationReport) ok(section, msg string) {
	r.add(section, SeverityOK, "", msg)
}

// warn adds a warning result.
func (r *ValidationReport) warn(section, code, msg string) {
	r.add(section, SeverityWarn, code, msg)
}

// err adds an error result.
func (r *ValidationReport) err(section, code, msg string) {
	r.add(section, SeverityError, code, msg)
}

// ExitCode returns the appropriate process exit code:
// 0 = clean, 1 = warnings only, 2 = errors present.
func (r *ValidationReport) ExitCode() int {
	if r.Errors > 0 {
		return 2
	}
	if r.Warnings > 0 {
		return 1
	}
	return 0
}

// ValidatePolicy performs comprehensive validation of a parsed policy Config
// and returns structured results. Unlike the loader's validate(), this does
// not fail-fast -- it collects all findings so the operator can fix everything
// in one pass.
func ValidatePolicy(cfg *Config) *ValidationReport {
	rpt := &ValidationReport{}

	validateGlobal(cfg, rpt)
	validateRoles(cfg, rpt)
	validateTargets(cfg, rpt)
	validateAgents(cfg, rpt)
	validateUnusedRoles(cfg, rpt)

	return rpt
}

// validateGlobal checks global policy settings.
func validateGlobal(cfg *Config, rpt *ValidationReport) {
	section := "global"

	// E6: invalid default_ttl
	defaultTTL, err := time.ParseDuration(cfg.Global.DefaultTTL)
	if err != nil {
		rpt.err(section, "E6", fmt.Sprintf("invalid default_ttl %q: %v", cfg.Global.DefaultTTL, err))
		return
	}

	// E6: invalid max_ttl
	maxTTL, err := time.ParseDuration(cfg.Global.MaxTTL)
	if err != nil {
		rpt.err(section, "E6", fmt.Sprintf("invalid max_ttl %q: %v", cfg.Global.MaxTTL, err))
		return
	}

	// E7: default_ttl exceeds max_ttl
	if defaultTTL > maxTTL {
		rpt.err(section, "E7", fmt.Sprintf("default_ttl (%s) exceeds max_ttl (%s)", defaultTTL, maxTTL))
	} else {
		rpt.ok(section, fmt.Sprintf("default_ttl %q, max_ttl %q", cfg.Global.DefaultTTL, cfg.Global.MaxTTL))
	}
}

// validateRoles checks role definitions.
func validateRoles(cfg *Config, rpt *ValidationReport) {
	section := "roles"

	// Sort role names for deterministic output.
	names := sortedKeys(cfg.Roles)
	for _, name := range names {
		role := cfg.Roles[name]

		// E4: empty principal
		if role.Principal == "" {
			rpt.err(section, "E4", fmt.Sprintf("role %q has empty principal", name))
			continue
		}

		rpt.ok(section, fmt.Sprintf("%s -> %s", name, role.Principal))
	}
}

// validateTargets checks target definitions.
func validateTargets(cfg *Config, rpt *ValidationReport) {
	section := "targets"

	// W1: no targets defined
	if len(cfg.Targets) == 0 {
		rpt.warn(section, "W1", "no targets defined")
		return
	}

	// Parse global max_ttl for comparison (may be invalid, handled in validateGlobal).
	globalMaxTTL, globalErr := time.ParseDuration(cfg.Global.MaxTTL)

	// Sort target names for deterministic output.
	names := sortedKeys(cfg.Targets)
	for _, name := range names {
		target := cfg.Targets[name]

		// E5: empty host
		if target.Host == "" {
			rpt.err(section, "E5", fmt.Sprintf("target %q has empty host", name))
			continue
		}

		// E9: port out of range
		if target.Port != 0 && (target.Port < 1 || target.Port > 65535) {
			rpt.err(section, "E9", fmt.Sprintf("target %q port %d out of range (1-65535)", name, target.Port))
		}

		// E3: target references undefined role
		for _, role := range target.AllowedRoles {
			if _, ok := cfg.Roles[role]; !ok {
				rpt.err(section, "E3", fmt.Sprintf("target %q references undefined role %q", name, role))
			}
		}

		// E6/E8: target max_ttl
		if target.MaxTTL != "" {
			ttl, err := time.ParseDuration(target.MaxTTL)
			if err != nil {
				rpt.err(section, "E6", fmt.Sprintf("target %q has invalid max_ttl %q: %v", name, target.MaxTTL, err))
			} else if globalErr == nil && ttl > globalMaxTTL {
				rpt.err(section, "E8", fmt.Sprintf("target %q max_ttl (%s) exceeds global max_ttl (%s)", name, ttl, globalMaxTTL))
			}
		}

		// E10: host_key_strict enabled but no host key fields
		if cfg.Global.HostKeyStrict && target.HostKey == "" && target.HostKeyFingerprint == "" {
			rpt.err(section, "E10", fmt.Sprintf("host_key_strict enabled but target %q has no host_key or host_key_fingerprint", name))
		}

		// E11: host_key_fingerprint format
		if target.HostKeyFingerprint != "" && !strings.HasPrefix(target.HostKeyFingerprint, "SHA256:") {
			rpt.err(section, "E11", fmt.Sprintf("target %q host_key_fingerprint %q does not start with \"SHA256:\"", name, target.HostKeyFingerprint))
		}

		// Build display port.
		port := target.Port
		if port == 0 {
			port = 22
		}

		// OK line with roles.
		rpt.ok(section, fmt.Sprintf("%s: %s:%d, roles %v", name, target.Host, port, target.AllowedRoles))

		// W2: no host_key pinned
		if target.HostKey == "" && target.HostKeyFingerprint == "" {
			rpt.warn(section, "W2", fmt.Sprintf("target %q: no host_key pinned", name))
		}
	}
}

// validateAgents checks agent definitions.
func validateAgents(cfg *Config, rpt *ValidationReport) {
	section := "agents"

	// E1: no agents defined
	if len(cfg.Agents) == 0 {
		rpt.err(section, "E1", "no agents defined")
		return
	}

	// E13: duplicate agent names (map keys are inherently unique, so this
	// can't actually happen with YAML parsing into map[string], but we
	// keep the check for completeness if Config is built programmatically).
	// We check for duplicate UIDs instead as a practical equivalent.
	uidSeen := make(map[int]string)

	// Sort agent names for deterministic output.
	names := sortedKeys(cfg.Agents)
	for _, name := range names {
		agent := cfg.Agents[name]

		// E2: references undefined template
		for _, tmpl := range agent.Inherits {
			if _, ok := cfg.Templates[tmpl]; !ok {
				rpt.err(section, "E2", fmt.Sprintf("agent %q inherits undefined template %q", name, tmpl))
			}
		}

		// E12: invalid bcrypt hash
		if agent.APIKeyHash != "" && !strings.HasPrefix(agent.APIKeyHash, "$2") {
			rpt.err(section, "E12", fmt.Sprintf("agent %q api_key_hash is not valid bcrypt (must start with \"$2\")", name))
		}

		// E13: duplicate UID (practical duplicate agent check).
		if prev, ok := uidSeen[agent.UID]; ok {
			rpt.err(section, "E13", fmt.Sprintf("duplicate UID %d: agents %q and %q", agent.UID, prev, name))
		}
		uidSeen[agent.UID] = name

		// OK line.
		rpt.ok(section, fmt.Sprintf("%s (uid=%d)", name, agent.UID))

		// W3: wildcard SSH targets
		if _, ok := agent.SSH["*"]; ok {
			rpt.warn(section, "W3", fmt.Sprintf("agent %q: wildcard \"*\" for SSH targets", name))
		}
		// Also check inherited templates for wildcard SSH.
		for _, tmpl := range agent.Inherits {
			if t, ok := cfg.Templates[tmpl]; ok {
				if _, ok := t.SSH["*"]; ok {
					rpt.warn(section, "W3", fmt.Sprintf("agent %q: wildcard \"*\" for SSH targets (via template %q)", name, tmpl))
				}
			}
		}

		// W4: wildcard services
		if _, ok := agent.Services["*"]; ok {
			rpt.warn(section, "W4", fmt.Sprintf("agent %q: wildcard \"*\" for services", name))
		}
		for _, tmpl := range agent.Inherits {
			if t, ok := cfg.Templates[tmpl]; ok {
				if _, ok := t.Services["*"]; ok {
					rpt.warn(section, "W4", fmt.Sprintf("agent %q: wildcard \"*\" for services (via template %q)", name, tmpl))
				}
			}
		}

		// W5: wildcard remotes
		if _, ok := agent.Remotes["*"]; ok {
			rpt.warn(section, "W5", fmt.Sprintf("agent %q: wildcard \"*\" for remotes", name))
		}
		for _, tmpl := range agent.Inherits {
			if t, ok := cfg.Templates[tmpl]; ok {
				if _, ok := t.Remotes["*"]; ok {
					rpt.warn(section, "W5", fmt.Sprintf("agent %q: wildcard \"*\" for remotes (via template %q)", name, tmpl))
				}
			}
		}

		// W6: UID 0 (root)
		if agent.UID == 0 {
			rpt.warn(section, "W6", fmt.Sprintf("agent %q: UID is 0 (root)", name))
		}

		// W8: no api_key_hash
		if agent.APIKeyHash == "" {
			rpt.warn(section, "W8", fmt.Sprintf("agent %q: no api_key_hash set", name))
		}
	}
}

// validateUnusedRoles checks for roles defined but never referenced by any target.
func validateUnusedRoles(cfg *Config, rpt *ValidationReport) {
	if len(cfg.Roles) == 0 || len(cfg.Targets) == 0 {
		return
	}

	referenced := make(map[string]bool)
	for _, target := range cfg.Targets {
		for _, role := range target.AllowedRoles {
			referenced[role] = true
		}
	}

	names := sortedKeys(cfg.Roles)
	for _, name := range names {
		if !referenced[name] {
			rpt.warn("roles", "W7", fmt.Sprintf("role %q is defined but never referenced by any target", name))
		}
	}
}

// sortedKeys returns the sorted keys of a map. It works with any map
// type that has string keys via a type switch.
func sortedKeys[M ~map[string]V, V any](m M) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
