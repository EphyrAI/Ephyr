package broker

import "sync"

// HostController manages per-host access toggles. When a host is disabled,
// new certificate requests targeting it are denied and active certs may be
// revoked. All methods are safe for concurrent use.
type HostController struct {
	mu     sync.RWMutex
	states map[string]bool // host name -> enabled (true = enabled)
}

// NewHostController creates a HostController with no overrides (all hosts
// default to enabled).
func NewHostController() *HostController {
	return &HostController{
		states: make(map[string]bool),
	}
}

// IsEnabled returns whether the given host is enabled. Hosts that have never
// been explicitly disabled default to true.
func (hc *HostController) IsEnabled(hostName string) bool {
	hc.mu.RLock()
	defer hc.mu.RUnlock()
	enabled, exists := hc.states[hostName]
	if !exists {
		return true // default enabled
	}
	return enabled
}

// Toggle flips the enabled state of a host and returns the new state.
// A host that has never been toggled is treated as enabled, so the first
// toggle disables it.
func (hc *HostController) Toggle(hostName string) bool {
	hc.mu.Lock()
	defer hc.mu.Unlock()
	current, exists := hc.states[hostName]
	if !exists {
		current = true // default enabled
	}
	hc.states[hostName] = !current
	return !current
}

// SetEnabled explicitly sets the enabled state of a host.
func (hc *HostController) SetEnabled(hostName string, enabled bool) {
	hc.mu.Lock()
	defer hc.mu.Unlock()
	hc.states[hostName] = enabled
}

// ListStates returns a snapshot of all hosts that have an explicit state.
func (hc *HostController) ListStates() map[string]bool {
	hc.mu.RLock()
	defer hc.mu.RUnlock()
	out := make(map[string]bool, len(hc.states))
	for k, v := range hc.states {
		out[k] = v
	}
	return out
}
