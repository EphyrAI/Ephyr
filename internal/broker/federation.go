package broker

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"regexp"
	"sync"
	"time"
)

// RemoteMCPConfig defines a remote MCP server to federate.
type RemoteMCPConfig struct {
	Name           string            `json:"name"`
	URL            string            `json:"url"`
	AuthType       string            `json:"auth_type"`                 // bearer, basic, header, query, none
	TokenHeader    string            `json:"token_header,omitempty"`    // custom header name for header/query auth
	TokenPrefix    string            `json:"token_prefix,omitempty"`    // prefix for header auth value
	Username       string            `json:"username,omitempty"`        // for basic auth
	Credential     string            `json:"credential,omitempty"`      // token/password (redacted in API responses)
	Headers        map[string]string `json:"headers,omitempty"`         // extra static headers
	Description    string            `json:"description,omitempty"`
	Enabled        bool              `json:"enabled"`
	GrantMode      string            `json:"grant_mode,omitempty"` // "ttl" or "passthrough"
	Timeout        int               `json:"timeout,omitempty"`         // seconds, default 30
	RefreshSeconds int               `json:"refresh_seconds,omitempty"` // discovery refresh interval, default 60
	MaxResponseKB  int               `json:"max_response_kb,omitempty"` // max response body in KB, default 1024
	ToolPrefix     string            `json:"tool_prefix,omitempty"`     // override namespace prefix for tools
}

// RemoteStatus represents the connection state of a remote MCP server.
type RemoteStatus string

const (
	RemoteStatusConnected    RemoteStatus = "connected"
	RemoteStatusDisconnected RemoteStatus = "disconnected"
	RemoteStatusError        RemoteStatus = "error"
	RemoteStatusInitializing RemoteStatus = "initializing"
)

// RemoteMCPState holds runtime state for a connected remote MCP server.
type RemoteMCPState struct {
	mu              sync.RWMutex
	Config          RemoteMCPConfig
	Status          RemoteStatus
	StatusMessage   string
	ProtocolVersion string
	ServerInfo      MCPServerInfo
	Tools           []MCPToolDefinition
	Resources       []MCPResource
	LastRefresh     time.Time
	LastError       time.Time
	LastErrorMsg    string
	ErrorCount      int // consecutive errors for backoff
	httpClient      *http.Client
}

// RemoteStateInfo is the JSON-serializable view of RemoteMCPState for the dashboard.
type RemoteStateInfo struct {
	Name            string       `json:"name"`
	URL             string       `json:"url"`
	Description     string       `json:"description"`
	Enabled         bool         `json:"enabled"`
	Status          RemoteStatus `json:"status"`
	StatusMessage   string       `json:"status_message,omitempty"`
	ProtocolVersion string       `json:"protocol_version,omitempty"`
	ServerName      string       `json:"server_name,omitempty"`
	ServerVersion   string       `json:"server_version,omitempty"`
	ToolCount       int          `json:"tool_count"`
	ResourceCount   int          `json:"resource_count"`
	LastRefresh     *time.Time   `json:"last_refresh,omitempty"`
	LastError       *time.Time   `json:"last_error,omitempty"`
	LastErrorMsg    string       `json:"last_error_msg,omitempty"`
	AuthType        string       `json:"auth_type"`
}

// nameRegexp validates remote MCP server names: alphanumeric and hyphens only.
var nameRegexp = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9-]*$`)

const (
	federationDefaultTimeout        = 30
	federationMaxTimeout            = 120
	federationDefaultRefreshSeconds = 60
	federationMinRefreshSeconds     = 10
	federationDefaultMaxResponseKB  = 1024
	federationMaxNameLen            = 50
)

// MCPFederator manages connections to remote MCP servers and aggregates their
// tools and resources into the local broker's namespace.
type MCPFederator struct {
	mu       sync.RWMutex
	remotes  map[string]*RemoteMCPState
	filePath string
	broker   *BrokerServer
	stopCh   chan struct{}
}

// NewMCPFederator creates a federator, loads any persisted remote configs from
// filePath, and starts the background refresh loop.
func NewMCPFederator(broker *BrokerServer, filePath string) *MCPFederator {
	f := &MCPFederator{
		remotes:  make(map[string]*RemoteMCPState),
		filePath: filePath,
		broker:   broker,
		stopCh:   make(chan struct{}),
	}

	if err := f.load(); err != nil {
		log.Printf("[federation] could not load remotes from %s (starting fresh): %v", filePath, err)
	}

	go f.refreshLoop()

	return f
}

// Stop signals the background refresh loop to exit.
func (f *MCPFederator) Stop() {
	select {
	case <-f.stopCh:
		// already stopped
	default:
		close(f.stopCh)
	}
}

// AddRemote validates a remote MCP config, stores it, persists to disk, and
// triggers an asynchronous discovery handshake.
func (f *MCPFederator) AddRemote(cfg RemoteMCPConfig) error {
	if err := f.validateConfig(&cfg); err != nil {
		return fmt.Errorf("invalid config: %w", err)
	}

	f.mu.Lock()
	if _, exists := f.remotes[cfg.Name]; exists {
		f.mu.Unlock()
		return fmt.Errorf("remote %q already exists", cfg.Name)
	}

	state := &RemoteMCPState{
		Config:     cfg,
		Status:     RemoteStatusInitializing,
		httpClient: f.buildHTTPClient(&cfg),
	}
	f.remotes[cfg.Name] = state
	f.mu.Unlock()

	if err := f.save(); err != nil {
		// Roll back the in-memory addition on persist failure.
		f.mu.Lock()
		delete(f.remotes, cfg.Name)
		f.mu.Unlock()
		return fmt.Errorf("persist remote %s: %w", cfg.Name, err)
	}

	log.Printf("[federation] added remote %s (%s)", cfg.Name, cfg.URL)

	// Trigger initial discovery in background so AddRemote returns quickly.
	go func() {
		if err := f.discoverRemote(state); err != nil {
			log.Printf("[federation] initial discovery of %s failed: %v", cfg.Name, err)
		}
	}()

	return nil
}

// RemoveRemote removes a remote MCP server by name and persists the change.
func (f *MCPFederator) RemoveRemote(name string) error {
	f.mu.Lock()
	if _, exists := f.remotes[name]; !exists {
		f.mu.Unlock()
		return fmt.Errorf("remote %q not found", name)
	}
	delete(f.remotes, name)
	f.mu.Unlock()

	if err := f.save(); err != nil {
		return fmt.Errorf("persist after removing remote %s: %w", name, err)
	}

	log.Printf("[federation] removed remote %s", name)
	return nil
}

// GetRemote returns a redacted copy of the config for a named remote.
func (f *MCPFederator) GetRemote(name string) (*RemoteMCPConfig, bool) {
	f.mu.RLock()
	defer f.mu.RUnlock()

	state, ok := f.remotes[name]
	if !ok {
		return nil, false
	}

	state.mu.RLock()
	redacted := f.redactConfig(state.Config)
	state.mu.RUnlock()

	return &redacted, true
}

// ListRemotes returns all remote configs with credentials redacted.
func (f *MCPFederator) ListRemotes() []RemoteMCPConfig {
	f.mu.RLock()
	defer f.mu.RUnlock()

	result := make([]RemoteMCPConfig, 0, len(f.remotes))
	for _, state := range f.remotes {
		state.mu.RLock()
		result = append(result, f.redactConfig(state.Config))
		state.mu.RUnlock()
	}
	return result
}

// GetRemoteState returns a dashboard-safe snapshot of a remote's runtime state.
func (f *MCPFederator) GetRemoteState(name string) *RemoteStateInfo {
	f.mu.RLock()
	state, ok := f.remotes[name]
	f.mu.RUnlock()

	if !ok {
		return nil
	}

	state.mu.RLock()
	defer state.mu.RUnlock()

	info := &RemoteStateInfo{
		Name:            state.Config.Name,
		URL:             state.Config.URL,
		Description:     state.Config.Description,
		Enabled:         state.Config.Enabled,
		Status:          state.Status,
		StatusMessage:   state.StatusMessage,
		ProtocolVersion: state.ProtocolVersion,
		ServerName:      state.ServerInfo.Name,
		ServerVersion:   state.ServerInfo.Version,
		ToolCount:       len(state.Tools),
		ResourceCount:   len(state.Resources),
		LastErrorMsg:    state.LastErrorMsg,
		AuthType:        state.Config.AuthType,
	}

	if !state.LastRefresh.IsZero() {
		t := state.LastRefresh
		info.LastRefresh = &t
	}
	if !state.LastError.IsZero() {
		t := state.LastError
		info.LastError = &t
	}

	return info
}

// ListRemoteStates returns dashboard-safe snapshots for all remotes.
func (f *MCPFederator) ListRemoteStates() []RemoteStateInfo {
	f.mu.RLock()
	states := make([]*RemoteMCPState, 0, len(f.remotes))
	for _, state := range f.remotes {
		states = append(states, state)
	}
	f.mu.RUnlock()

	result := make([]RemoteStateInfo, 0, len(states))
	for _, state := range states {
		state.mu.RLock()
		info := RemoteStateInfo{
			Name:            state.Config.Name,
			URL:             state.Config.URL,
			Description:     state.Config.Description,
			Enabled:         state.Config.Enabled,
			Status:          state.Status,
			StatusMessage:   state.StatusMessage,
			ProtocolVersion: state.ProtocolVersion,
			ServerName:      state.ServerInfo.Name,
			ServerVersion:   state.ServerInfo.Version,
			ToolCount:       len(state.Tools),
			ResourceCount:   len(state.Resources),
			LastErrorMsg:    state.LastErrorMsg,
			AuthType:        state.Config.AuthType,
		}
		if !state.LastRefresh.IsZero() {
			t := state.LastRefresh
			info.LastRefresh = &t
		}
		if !state.LastError.IsZero() {
			t := state.LastError
			info.LastError = &t
		}
		state.mu.RUnlock()
		result = append(result, info)
	}
	return result
}

// load reads persisted remote configs from disk and creates initial states.
func (f *MCPFederator) load() error {
	data, err := os.ReadFile(f.filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("read %s: %w", f.filePath, err)
	}

	var configs map[string]*RemoteMCPConfig
	if err := json.Unmarshal(data, &configs); err != nil {
		return fmt.Errorf("parse %s: %w", f.filePath, err)
	}

	f.mu.Lock()
	defer f.mu.Unlock()

	for name, cfg := range configs {
		cfg.Name = name // ensure consistency
		state := &RemoteMCPState{
			Config:     *cfg,
			Status:     RemoteStatusDisconnected,
			httpClient: f.buildHTTPClient(cfg),
		}
		f.remotes[name] = state
	}

	log.Printf("[federation] loaded %d remotes from %s", len(configs), f.filePath)
	return nil
}

// save persists all remote configs to disk using atomic write (tmp + rename).
func (f *MCPFederator) save() error {
	f.mu.RLock()
	configs := make(map[string]*RemoteMCPConfig, len(f.remotes))
	for name, state := range f.remotes {
		state.mu.RLock()
		cfg := state.Config
		state.mu.RUnlock()
		configs[name] = &cfg
	}
	f.mu.RUnlock()

	data, err := json.MarshalIndent(configs, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal remotes: %w", err)
	}

	tmpPath := f.filePath + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0600); err != nil {
		return fmt.Errorf("write %s: %w", tmpPath, err)
	}
	if err := os.Rename(tmpPath, f.filePath); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("rename %s -> %s: %w", tmpPath, f.filePath, err)
	}

	return nil
}

// redactConfig returns a copy of the config with the credential field masked.
func (f *MCPFederator) redactConfig(cfg RemoteMCPConfig) RemoteMCPConfig {
	c := cfg
	if c.Credential != "" {
		c.Credential = "***"
	}
	return c
}

// validateConfig checks that all required fields are set and applies defaults.
func (f *MCPFederator) validateConfig(cfg *RemoteMCPConfig) error {
	if cfg.Name == "" {
		return fmt.Errorf("name is required")
	}
	if len(cfg.Name) > federationMaxNameLen {
		return fmt.Errorf("name must be at most %d characters", federationMaxNameLen)
	}
	if !nameRegexp.MatchString(cfg.Name) {
		return fmt.Errorf("name must be alphanumeric with hyphens only (got %q)", cfg.Name)
	}

	if cfg.URL == "" {
		return fmt.Errorf("url is required")
	}
	if !(len(cfg.URL) >= 7 && cfg.URL[:7] == "http://") &&
		!(len(cfg.URL) >= 8 && cfg.URL[:8] == "https://") {
		return fmt.Errorf("url must start with http:// or https://")
	}

	// Normalize and validate auth type.
	if cfg.AuthType == "" {
		cfg.AuthType = "none"
	}
	validAuthTypes := map[string]bool{
		"bearer": true, "basic": true, "header": true, "query": true, "none": true,
	}
	if !validAuthTypes[cfg.AuthType] {
		return fmt.Errorf("invalid auth_type %q (must be bearer, basic, header, query, or none)", cfg.AuthType)
	}

	// Apply defaults.
	if cfg.Timeout <= 0 {
		cfg.Timeout = federationDefaultTimeout
	}
	if cfg.Timeout > federationMaxTimeout {
		cfg.Timeout = federationMaxTimeout
	}

	if cfg.RefreshSeconds <= 0 {
		cfg.RefreshSeconds = federationDefaultRefreshSeconds
	}
	if cfg.RefreshSeconds < federationMinRefreshSeconds {
		cfg.RefreshSeconds = federationMinRefreshSeconds
	}

	if cfg.MaxResponseKB <= 0 {
		cfg.MaxResponseKB = federationDefaultMaxResponseKB
	}

	return nil
}

// refreshLoop runs in a background goroutine, periodically checking each
// remote and re-discovering tools/resources if stale or in error state.
func (f *MCPFederator) refreshLoop() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-f.stopCh:
			log.Printf("[federation] refresh loop stopped")
			return
		case <-ticker.C:
			f.mu.RLock()
			remotes := make([]*RemoteMCPState, 0, len(f.remotes))
			for _, state := range f.remotes {
				remotes = append(remotes, state)
			}
			f.mu.RUnlock()

			for _, state := range remotes {
				state.mu.RLock()
				enabled := state.Config.Enabled
				refreshInterval := time.Duration(state.Config.RefreshSeconds) * time.Second
				lastRefresh := state.LastRefresh
				status := state.Status
				errorCount := state.ErrorCount
				state.mu.RUnlock()

				if !enabled {
					continue
				}

				// Determine if we should refresh this remote.
				shouldRefresh := false

				switch status {
				case RemoteStatusDisconnected, RemoteStatusInitializing:
					shouldRefresh = true
				case RemoteStatusError:
					// Use backoff for errored remotes.
					backoff := f.backoffDuration(errorCount)
					if time.Since(lastRefresh) >= backoff {
						shouldRefresh = true
					}
				case RemoteStatusConnected:
					// Refresh if stale.
					if time.Since(lastRefresh) >= refreshInterval {
						shouldRefresh = true
					}
				}

				if shouldRefresh {
					if err := f.discoverRemote(state); err != nil {
						log.Printf("[federation] refresh of %s failed: %v", state.Config.Name, err)
					}
				}
			}
		}
	}
}

// backoffDuration returns an exponential backoff duration based on consecutive
// error count: 10s, 30s, 60s, 120s, 300s (capped).
func (f *MCPFederator) backoffDuration(errorCount int) time.Duration {
	backoffs := []time.Duration{
		10 * time.Second,
		30 * time.Second,
		60 * time.Second,
		120 * time.Second,
		300 * time.Second,
	}

	if errorCount <= 0 {
		return backoffs[0]
	}
	idx := errorCount - 1
	if idx >= len(backoffs) {
		idx = len(backoffs) - 1
	}
	return backoffs[idx]
}

// buildHTTPClient creates an http.Client configured for the given remote,
// with the specified timeout and TLS skip verify for homelab self-signed certs.
func (f *MCPFederator) buildHTTPClient(cfg *RemoteMCPConfig) *http.Client {
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = federationDefaultTimeout
	}

	return &http.Client{
		Timeout: time.Duration(timeout) * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			MaxIdleConns:    2,
			IdleConnTimeout: 90 * time.Second,
		},
	}
}

// prefix returns the namespace prefix for a remote's tools and resources.
// Uses ToolPrefix if set, otherwise falls back to the remote's Name.
func (f *MCPFederator) prefix(state *RemoteMCPState) string {
	if state.Config.ToolPrefix != "" {
		return state.Config.ToolPrefix
	}
	return state.Config.Name
}
