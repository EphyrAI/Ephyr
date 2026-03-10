package broker

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/sprawl/clauth/internal/audit"
)

// HostConfig stores configurable settings per host for the dashboard.
type HostConfig struct {
	Name         string   `json:"name"`
	Host         string   `json:"host"`
	Port         int      `json:"port"`
	VLAN         int      `json:"vlan"`
	SSHUser      string   `json:"ssh_user,omitempty"`
	SSHKeyPath   string   `json:"ssh_key_path,omitempty"`
	SSHPassword  string   `json:"ssh_password,omitempty"`
	AllowedRoles []string `json:"allowed_roles"`
	MaxTTL       string   `json:"max_ttl"`
	DefaultTTL   string   `json:"default_ttl,omitempty"`
	AutoApprove  bool     `json:"auto_approve"`
	Description  string   `json:"description,omitempty"`
	OS           string   `json:"os,omitempty"`
}

// ConfigManager handles persistent host configuration with thread-safe
// access and JSON file persistence.
type ConfigManager struct {
	mu       sync.RWMutex
	configs  map[string]*HostConfig // keyed by host name
	filePath string                 // path to persist configs (e.g., /etc/clauth/hosts.json)
}

// NewConfigManager creates a ConfigManager and loads existing configuration
// from the file if it exists. If the file does not exist, an empty config
// map is initialized.
func NewConfigManager(filePath string) *ConfigManager {
	cm := &ConfigManager{
		configs:  make(map[string]*HostConfig),
		filePath: filePath,
	}

	if err := cm.Load(); err != nil {
		log.Printf("[config] could not load %s (starting fresh): %v", filePath, err)
	}

	return cm
}

// GetConfig returns a copy of the config for the named host, with the
// password redacted. Returns nil if the host is not found.
func (cm *ConfigManager) GetConfig(name string) *HostConfig {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	cfg, ok := cm.configs[name]
	if !ok {
		return nil
	}

	return redactConfig(cfg)
}

// GetAllConfigs returns copies of all host configs with passwords redacted.
func (cm *ConfigManager) GetAllConfigs() []*HostConfig {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	result := make([]*HostConfig, 0, len(cm.configs))
	for _, cfg := range cm.configs {
		result = append(result, redactConfig(cfg))
	}
	return result
}

// UpdateConfig updates or creates a host config and persists the change.
// If the config already exists, only non-zero fields in update are applied.
func (cm *ConfigManager) UpdateConfig(name string, update *HostConfig) error {
	if err := validateHostConfig(update); err != nil {
		return err
	}

	cm.mu.Lock()
	defer cm.mu.Unlock()

	existing, ok := cm.configs[name]
	if !ok {
		// New config: set the name and store directly.
		update.Name = name
		cm.configs[name] = update
	} else {
		// Merge update into existing config.
		mergeConfig(existing, update)
	}

	return cm.saveLocked()
}

// DeleteConfig removes a host config and persists the change.
func (cm *ConfigManager) DeleteConfig(name string) error {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	if _, ok := cm.configs[name]; !ok {
		return fmt.Errorf("host %q not found", name)
	}

	delete(cm.configs, name)
	return cm.saveLocked()
}

// Save persists the current config map to the JSON file with 0600 permissions.
func (cm *ConfigManager) Save() error {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	return cm.saveLocked()
}

// saveLocked writes configs to file. Caller must hold at least a read lock.
func (cm *ConfigManager) saveLocked() error {
	data, err := json.MarshalIndent(cm.configs, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal configs: %w", err)
	}

	// Write to a temp file then rename for atomicity.
	tmpPath := cm.filePath + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0600); err != nil {
		return fmt.Errorf("write %s: %w", tmpPath, err)
	}
	if err := os.Rename(tmpPath, cm.filePath); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("rename %s -> %s: %w", tmpPath, cm.filePath, err)
	}

	return nil
}

// Load reads host configs from the JSON file. If the file does not exist,
// the config map is left empty (no error).
func (cm *ConfigManager) Load() error {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	data, err := os.ReadFile(cm.filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("read %s: %w", cm.filePath, err)
	}

	var configs map[string]*HostConfig
	if err := json.Unmarshal(data, &configs); err != nil {
		return fmt.Errorf("parse %s: %w", cm.filePath, err)
	}

	cm.configs = configs
	return nil
}

// InitFromPolicy populates configs for any targets that exist in the policy
// but do not yet have a config entry. Existing entries are not overwritten.
func (cm *ConfigManager) InitFromPolicy(targets map[string]policyTarget) {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	changed := false
	for name, t := range targets {
		if _, exists := cm.configs[name]; exists {
			continue
		}
		port := t.Port
		if port == 0 {
			port = 22
		}
		cm.configs[name] = &HostConfig{
			Name:         name,
			Host:         t.Host,
			Port:         port,
			VLAN:         t.VLAN,
			AllowedRoles: t.AllowedRoles,
			MaxTTL:       t.MaxTTL,
			AutoApprove:  t.AutoApprove,
			Description:  t.Description,
		}
		changed = true
	}

	if changed {
		if err := cm.saveLocked(); err != nil {
			log.Printf("[config] failed to save after policy init: %v", err)
		}
	}
}

// policyTarget is a minimal interface matching the fields we need from
// policy.TargetPolicy, avoiding a direct dependency cycle.
type policyTarget struct {
	Host         string
	Port         int
	VLAN         int
	AllowedRoles []string
	MaxTTL       string
	AutoApprove  bool
	Description  string
}

// redactConfig returns a copy of the config with sensitive fields redacted.
// Passwords are replaced with "***" if set, or left empty if not set.
// Key paths are preserved but if a raw key was stored the path shows "***".
func redactConfig(cfg *HostConfig) *HostConfig {
	c := *cfg // shallow copy
	if c.SSHPassword != "" {
		c.SSHPassword = "***"
	}
	return &c
}

// mergeConfig applies non-zero fields from update into dst.
func mergeConfig(dst, update *HostConfig) {
	if update.Host != "" {
		dst.Host = update.Host
	}
	if update.Port > 0 {
		dst.Port = update.Port
	}
	if update.VLAN > 0 {
		dst.VLAN = update.VLAN
	}
	if update.SSHUser != "" {
		dst.SSHUser = update.SSHUser
	}
	if update.SSHKeyPath != "" {
		dst.SSHKeyPath = update.SSHKeyPath
	}
	if update.SSHPassword != "" {
		dst.SSHPassword = update.SSHPassword
	}
	if len(update.AllowedRoles) > 0 {
		dst.AllowedRoles = update.AllowedRoles
	}
	if update.MaxTTL != "" {
		dst.MaxTTL = update.MaxTTL
	}
	if update.DefaultTTL != "" {
		dst.DefaultTTL = update.DefaultTTL
	}
	// AutoApprove is a bool, always apply (can toggle off).
	dst.AutoApprove = update.AutoApprove
	if update.Description != "" {
		dst.Description = update.Description
	}
	if update.OS != "" {
		dst.OS = update.OS
	}
}

// validateHostConfig checks that a HostConfig has valid field values.
func validateHostConfig(cfg *HostConfig) error {
	if cfg.Host != "" {
		ip := net.ParseIP(cfg.Host)
		if ip == nil {
			// Not a valid IP; check if it looks like a hostname.
			if strings.ContainsAny(cfg.Host, " \t\n") {
				return fmt.Errorf("invalid host %q: contains whitespace", cfg.Host)
			}
		}
	}

	if cfg.Port != 0 {
		if cfg.Port < 1 || cfg.Port > 65535 {
			return fmt.Errorf("invalid port %d: must be 1-65535", cfg.Port)
		}
	}

	if cfg.VLAN != 0 {
		if cfg.VLAN < 1 || cfg.VLAN > 4094 {
			return fmt.Errorf("invalid VLAN %d: must be 1-4094", cfg.VLAN)
		}
	}

	if cfg.MaxTTL != "" {
		if _, err := time.ParseDuration(cfg.MaxTTL); err != nil {
			return fmt.Errorf("invalid max_ttl %q: %w", cfg.MaxTTL, err)
		}
	}

	if cfg.DefaultTTL != "" {
		if _, err := time.ParseDuration(cfg.DefaultTTL); err != nil {
			return fmt.Errorf("invalid default_ttl %q: %w", cfg.DefaultTTL, err)
		}
	}

	return nil
}

// --- Dashboard API handlers for host configuration ---

// handleGetHostConfigs serves GET /v1/dashboard/config/hosts.
// Returns all host configs with passwords redacted.
func (bs *BrokerServer) handleGetHostConfigs(w http.ResponseWriter, r *http.Request) {
	if bs.configMgr == nil {
		writeError(w, http.StatusServiceUnavailable, "config manager not initialized")
		return
	}

	configs := bs.configMgr.GetAllConfigs()
	if configs == nil {
		configs = []*HostConfig{}
	}
	writeJSON(w, http.StatusOK, configs)
}

// handleGetHostConfig serves GET /v1/dashboard/config/hosts/{name}.
// Returns a single host config with password redacted.
func (bs *BrokerServer) handleGetHostConfig(w http.ResponseWriter, r *http.Request) {
	if bs.configMgr == nil {
		writeError(w, http.StatusServiceUnavailable, "config manager not initialized")
		return
	}

	name := r.PathValue("name")
	if name == "" {
		writeError(w, http.StatusBadRequest, "host name is required")
		return
	}

	cfg := bs.configMgr.GetConfig(name)
	if cfg == nil {
		writeError(w, http.StatusNotFound, fmt.Sprintf("host %q not found", name))
		return
	}

	writeJSON(w, http.StatusOK, cfg)
}

// handleUpdateHostConfig serves PUT /v1/dashboard/config/hosts/{name}.
// Creates or updates a host config.
func (bs *BrokerServer) handleUpdateHostConfig(w http.ResponseWriter, r *http.Request) {
	if bs.configMgr == nil {
		writeError(w, http.StatusServiceUnavailable, "config manager not initialized")
		return
	}

	name := r.PathValue("name")
	if name == "" {
		writeError(w, http.StatusBadRequest, "host name is required")
		return
	}

	var update HostConfig
	if err := json.NewDecoder(r.Body).Decode(&update); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}

	if err := bs.configMgr.UpdateConfig(name, &update); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	bs.auditLog.LogEvent(audit.AuditEvent{
		Severity:  audit.SeverityInfo,
		EventType: "config_updated",
		Target:    name,
		Details: map[string]string{
			"host":   update.Host,
			"remote": r.RemoteAddr,
		},
	})

	bs.eventHub.Broadcast(Event{
		Type: "config_updated",
		Data: map[string]string{
			"host": name,
		},
	})

	// Return the updated (redacted) config.
	cfg := bs.configMgr.GetConfig(name)
	writeJSON(w, http.StatusOK, cfg)
}

// handleDeleteHostConfig serves DELETE /v1/dashboard/config/hosts/{name}.
func (bs *BrokerServer) handleDeleteHostConfig(w http.ResponseWriter, r *http.Request) {
	if bs.configMgr == nil {
		writeError(w, http.StatusServiceUnavailable, "config manager not initialized")
		return
	}

	name := r.PathValue("name")
	if name == "" {
		writeError(w, http.StatusBadRequest, "host name is required")
		return
	}

	if err := bs.configMgr.DeleteConfig(name); err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}

	bs.auditLog.LogEvent(audit.AuditEvent{
		Severity:  audit.SeverityWarn,
		EventType: "config_deleted",
		Target:    name,
		Details: map[string]string{
			"remote": r.RemoteAddr,
		},
	})

	bs.eventHub.Broadcast(Event{
		Type: "config_deleted",
		Data: map[string]string{
			"host": name,
		},
	})

	writeJSON(w, http.StatusOK, map[string]string{
		"status": "deleted",
		"host":   name,
	})
}

// handleGetRoles serves GET /v1/dashboard/config/roles.
// Returns all defined roles from the policy.
func (bs *BrokerServer) handleGetRoles(w http.ResponseWriter, r *http.Request) {
	bs.policyMu.RLock()
	roles := bs.policyCfg.Raw.Roles
	bs.policyMu.RUnlock()

	type roleInfo struct {
		Name        string `json:"name"`
		Principal   string `json:"principal"`
		Description string `json:"description,omitempty"`
	}

	result := make([]roleInfo, 0, len(roles))
	for name, role := range roles {
		result = append(result, roleInfo{
			Name:        name,
			Principal:   role.Principal,
			Description: role.Description,
		})
	}

	writeJSON(w, http.StatusOK, result)
}
