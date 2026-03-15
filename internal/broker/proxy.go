package broker

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/EphyrAI/Ephyr/internal/audit"
)

// ProxyEngine handles HTTP proxying with credential injection and policy enforcement.
type ProxyEngine struct {
	mu         sync.RWMutex
	services   map[string]*ServiceConfig // keyed by service name
	filePath   string                    // persistent storage path
	httpClient *http.Client
	broker     *BrokerServer
	policy     *NetworkPolicy
}

// ServiceConfig defines a configured service with its credentials and access rules.
type ServiceConfig struct {
	Name           string            `json:"name"`
	URLPrefix      string            `json:"url_prefix"`       // e.g. "http://gitea.internal:3000"
	AuthType       string            `json:"auth_type"`        // "bearer", "basic", "header", "query", "none"
	TokenHeader    string            `json:"token_header"`     // custom header name (default: "Authorization")
	TokenPrefix    string            `json:"token_prefix"`     // e.g. "token ", "Bearer "
	Username       string            `json:"username"`         // for basic auth
	Credential     string            `json:"credential"`       // token/password (redacted in API responses)
	AllowedPaths   []string          `json:"allowed_paths"`    // optional glob patterns for path restrictions
	AllowedMethods []string          `json:"allowed_methods"`  // optional method restrictions (empty = all)
	MaxResponseKB  int               `json:"max_response_kb"`  // max response size in KB (default 1024 = 1MB)
	Timeout        int               `json:"timeout"`          // seconds, default 30
	Description    string            `json:"description"`
	Enabled        *bool             `json:"enabled,omitempty"` // nil or true = enabled, false = disabled
	GrantMode      string            `json:"grant_mode,omitempty"` // "ttl" or "passthrough"
	Headers        map[string]string `json:"headers"`          // extra headers to inject
}

// NetworkPolicy controls which hosts/networks the proxy may reach.
type NetworkPolicy struct {
	AllowCIDRs    []string `json:"allow_cidrs"`     // e.g. ["10.0.0.0/8"]
	DenyCIDRs     []string `json:"deny_cidrs"`      // e.g. ["192.168.10.0/24"]
	External      string   `json:"external"`         // "open", "restricted", "deny"
	ExternalAllow []string `json:"external_allow"`   // hostname glob patterns for restricted mode
}

// ProxyRequest is the input for making a proxied HTTP request.
type ProxyRequest struct {
	URL     string            `json:"url"`
	Method  string            `json:"method"`
	Headers map[string]string `json:"headers,omitempty"`
	Body    string            `json:"body,omitempty"`
	Timeout int               `json:"timeout,omitempty"` // override default, max 120s
}

// ProxyResult is the output of a proxied HTTP request.
type ProxyResult struct {
	StatusCode int               `json:"status_code"`
	Headers    map[string]string `json:"headers"`
	Body       string            `json:"body"`
	Service    string            `json:"service,omitempty"`  // matched service name, empty if direct
	URL        string            `json:"url"`
	Method     string            `json:"method"`
	DurationMs int64             `json:"duration_ms"`
	BytesRead  int               `json:"bytes_read"`
	Truncated  bool              `json:"truncated,omitempty"` // true if response was truncated
}

// DefaultNetworkPolicy allows all RFC 1918 ranges and denies external access.
var DefaultNetworkPolicy = &NetworkPolicy{
	AllowCIDRs:    []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"},
	DenyCIDRs:     []string{},
	External:      "deny",
	ExternalAllow: []string{},
}

const (
	maxTimeoutSeconds      = 120
	defaultTimeoutSeconds  = 30
	defaultMaxResponseKB   = 1024 // 1 MB
	dnsResolveTimeout      = 2 * time.Second
)

// RFC 1918 private address ranges.
var privateRanges []*net.IPNet

func init() {
	for _, cidr := range []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"} {
		_, network, _ := net.ParseCIDR(cidr)
		privateRanges = append(privateRanges, network)
	}
}

// NewProxyEngine creates a proxy engine with service configs loaded from disk.
func NewProxyEngine(broker *BrokerServer, filePath string, pol *NetworkPolicy) *ProxyEngine {
	if pol == nil {
		pol = DefaultNetworkPolicy
	}

	p := &ProxyEngine{
		services: make(map[string]*ServiceConfig),
		filePath: filePath,
		broker:   broker,
		policy:   pol,
		httpClient: &http.Client{
			Timeout: time.Duration(defaultTimeoutSeconds) * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
		},
	}

	if err := p.load(); err != nil {
		log.Printf("[proxy] could not load services from %s (starting fresh): %v", filePath, err)
	}

	return p
}

// Do executes a proxied HTTP request with credential injection and policy enforcement.
func (p *ProxyEngine) Do(agentName string, req *ProxyRequest) (*ProxyResult, error) {
	// 1. Validate the URL.
	if req.URL == "" {
		return nil, fmt.Errorf("proxy: url is required")
	}
	parsed, err := url.Parse(req.URL)
	if err != nil {
		return nil, fmt.Errorf("proxy: invalid url: %w", err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return nil, fmt.Errorf("proxy: unsupported scheme %q (must be http or https)", parsed.Scheme)
	}

	// Validate method.
	method := strings.ToUpper(req.Method)
	if method == "" {
		method = "GET"
	}

	// 2-3. Evaluate network policy.
	if err := p.evaluatePolicy(req.URL); err != nil {
		p.broker.auditLog.LogEvent(audit.AuditEvent{
			Severity:  audit.SeverityWarn,
			EventType: "http_proxy_denied",
			Agent:     agentName,
			Details: map[string]string{
				"url":    req.URL,
				"method": method,
				"reason": err.Error(),
			},
		})
		return nil, fmt.Errorf("proxy: policy denied: %w", err)
	}

	// 4. Match against configured services.
	svc := p.matchService(req.URL)


	// Check if the matched service is disabled.
	if svc != nil && svc.Enabled != nil && !*svc.Enabled {
		return nil, fmt.Errorf("proxy: service %q is disabled", svc.Name)
	}
	// Check service-level method restrictions.
	if svc != nil && len(svc.AllowedMethods) > 0 {
		allowed := false
		for _, m := range svc.AllowedMethods {
			if strings.EqualFold(m, method) {
				allowed = true
				break
			}
		}
		if !allowed {
			return nil, fmt.Errorf("proxy: method %s not allowed for service %s", method, svc.Name)
		}
	}

	// Check service-level path restrictions.
	if svc != nil && len(svc.AllowedPaths) > 0 {
		reqPath := parsed.Path
		pathAllowed := false
		for _, pattern := range svc.AllowedPaths {
			if matched, _ := path.Match(pattern, reqPath); matched {
				pathAllowed = true
				break
			}
		}
		if !pathAllowed {
			return nil, fmt.Errorf("proxy: path %s not allowed for service %s", reqPath, svc.Name)
		}
	}

	// Check/issue access grant (unless passthrough mode).
	if p.broker.grantStore != nil {
		grantMode := p.broker.grantStore.Mode
		if svc != nil && svc.GrantMode != "" {
			grantMode = GrantMode(svc.GrantMode)
		}
		if svc != nil && grantMode == GrantModeTTL {
			existing := p.broker.grantStore.Validate(GrantTypeService, agentName, svc.Name)
			if existing == nil {
				// Auto-issue a new grant.
				p.broker.grantStore.Issue(GrantTypeService, agentName, svc.Name, 0, map[string]string{
					"url_prefix": svc.URLPrefix,
					"auth_type":  svc.AuthType,
				})
				// Broadcast event.
				p.broker.eventHub.Broadcast(Event{
					Type: "grant_issued",
					Data: map[string]string{
						"type":   "service",
						"agent":  agentName,
						"target": svc.Name,
					},
				})
			}
		}
	}

	// 5. Build http.Request.
	var bodyReader io.Reader
	if req.Body != "" {
		bodyReader = strings.NewReader(req.Body)
	}

	httpReq, err := http.NewRequest(method, req.URL, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("proxy: build request: %w", err)
	}

	// 6. Inject credentials if a service matched.
	if svc != nil {
		p.injectCredentials(httpReq, svc)
	}

	// 7. Add agent's custom headers (but never override injected auth headers).
	if req.Headers != nil {
		for k, v := range req.Headers {
			// Do not let agent override the Authorization header if credentials were injected.
			if svc != nil && strings.EqualFold(k, "Authorization") {
				continue
			}
			// Do not let agent override the custom auth header if set by service.
			if svc != nil && svc.AuthType == "header" && svc.TokenHeader != "" &&
				strings.EqualFold(k, svc.TokenHeader) {
				continue
			}
			httpReq.Header.Set(k, v)
		}
	}

	// 8. Determine timeout.
	timeout := defaultTimeoutSeconds
	if svc != nil && svc.Timeout > 0 {
		timeout = svc.Timeout
	}
	if req.Timeout > 0 && req.Timeout < timeout {
		timeout = req.Timeout
	}
	if timeout > maxTimeoutSeconds {
		timeout = maxTimeoutSeconds
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
	defer cancel()
	httpReq = httpReq.WithContext(ctx)

	// 9. Execute the request.
	start := time.Now()
	resp, err := p.httpClient.Do(httpReq)
	durationMs := time.Since(start).Milliseconds()

	if err != nil {
		p.broker.auditLog.LogEvent(audit.AuditEvent{
			Severity:  audit.SeverityError,
			EventType: "http_proxy",
			Agent:     agentName,
			Details: map[string]string{
				"url":         req.URL,
				"method":      method,
				"service":     serviceName(svc),
				"error":       err.Error(),
				"duration_ms": strconv.FormatInt(durationMs, 10),
			},
		})
		return nil, fmt.Errorf("proxy: request failed: %w", err)
	}
	defer resp.Body.Close()

	// 10. Read response body with size cap.
	maxBytes := defaultMaxResponseKB * 1024
	if svc != nil && svc.MaxResponseKB > 0 {
		maxBytes = svc.MaxResponseKB * 1024
	}

	bodyBytes := make([]byte, 0, 4096)
	truncated := false
	buf := make([]byte, 4096)
	totalRead := 0
	for {
		n, readErr := resp.Body.Read(buf)
		if n > 0 {
			remaining := maxBytes - totalRead
			if n > remaining {
				bodyBytes = append(bodyBytes, buf[:remaining]...)
				totalRead += remaining
				truncated = true
				break
			}
			bodyBytes = append(bodyBytes, buf[:n]...)
			totalRead += n
		}
		if readErr != nil {
			break
		}
	}

	// 11. Build ProxyResult.
	respHeaders := make(map[string]string, len(resp.Header))
	for k := range resp.Header {
		respHeaders[k] = resp.Header.Get(k)
	}

	result := &ProxyResult{
		StatusCode: resp.StatusCode,
		Headers:    respHeaders,
		Body:       string(bodyBytes),
		Service:    serviceName(svc),
		URL:        req.URL,
		Method:     method,
		DurationMs: durationMs,
		BytesRead:  totalRead,
		Truncated:  truncated,
	}

	// 12. Audit log the request.
	p.broker.auditLog.LogEvent(audit.AuditEvent{
		Severity:  audit.SeverityInfo,
		EventType: "http_proxy",
		Agent:     agentName,
		Details: map[string]string{
			"url":         req.URL,
			"method":      method,
			"service":     serviceName(svc),
			"status_code": strconv.Itoa(result.StatusCode),
			"duration_ms": strconv.FormatInt(result.DurationMs, 10),
			"bytes":       strconv.Itoa(result.BytesRead),
		},
	})

	// Broadcast event for real-time dashboard.
	p.broker.eventHub.Broadcast(Event{
		Type: "http_proxy",
		Data: map[string]interface{}{
			"agent":       agentName,
			"url":         req.URL,
			"method":      method,
			"service":     serviceName(svc),
			"status_code": result.StatusCode,
			"duration_ms": result.DurationMs,
			"bytes":       result.BytesRead,
		},
	})

	// 13. Return result.
	return result, nil
}

// matchService finds the service config whose URLPrefix matches the request URL.
// Returns nil if no service matches (request goes through as direct proxy).
// Longest prefix match wins if multiple services match.
func (p *ProxyEngine) matchService(rawURL string) *ServiceConfig {
	p.mu.RLock()
	defer p.mu.RUnlock()

	var best *ServiceConfig
	bestLen := 0
	for _, svc := range p.services {
		if strings.HasPrefix(rawURL, svc.URLPrefix) && len(svc.URLPrefix) > bestLen {
			best = svc
			bestLen = len(svc.URLPrefix)
		}
	}
	return best
}

// evaluatePolicy checks if the request URL is allowed by network policy.
// Returns nil if allowed, error with reason if denied.
func (p *ProxyEngine) evaluatePolicy(rawURL string) error {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid url: %w", err)
	}

	hostname := parsed.Hostname()

	// Resolve hostname to IP(s).
	ips, err := resolveHost(hostname)
	if err != nil {
		return fmt.Errorf("dns resolution failed for %s: %w", hostname, err)
	}
	if len(ips) == 0 {
		return fmt.Errorf("no IP addresses found for %s", hostname)
	}

	// We check all resolved IPs; all must pass policy.
	for _, ip := range ips {
		if err := p.evaluateIPPolicy(ip, hostname); err != nil {
			return err
		}
	}

	return nil
}

// evaluateIPPolicy checks a single IP against the network policy.
func (p *ProxyEngine) evaluateIPPolicy(ip net.IP, hostname string) error {
	pol := p.policy

	// Check deny CIDRs first -- any match means deny.
	for _, cidrStr := range pol.DenyCIDRs {
		_, cidr, err := net.ParseCIDR(cidrStr)
		if err != nil {
			continue
		}
		if cidr.Contains(ip) {
			return fmt.Errorf("destination %s (%s) is in denied network %s", hostname, ip, cidrStr)
		}
	}

	// Determine if IP is private (RFC 1918).
	private := isPrivateIP(ip)

	if private {
		// If allow CIDRs are configured, IP must match at least one.
		if len(pol.AllowCIDRs) > 0 {
			allowed := false
			for _, cidrStr := range pol.AllowCIDRs {
				_, cidr, err := net.ParseCIDR(cidrStr)
				if err != nil {
					continue
				}
				if cidr.Contains(ip) {
					allowed = true
					break
				}
			}
			if !allowed {
				return fmt.Errorf("destination %s (%s) not in any allowed network", hostname, ip)
			}
		}
		// If no allow CIDRs, all private IPs are allowed.
		return nil
	}

	// External (public) IP.
	switch pol.External {
	case "open":
		return nil
	case "deny", "":
		return fmt.Errorf("external access denied for %s (%s)", hostname, ip)
	case "restricted":
		for _, pattern := range pol.ExternalAllow {
			if matched, _ := path.Match(pattern, hostname); matched {
				return nil
			}
		}
		return fmt.Errorf("external host %s not in allowed patterns", hostname)
	default:
		return fmt.Errorf("unknown external policy %q", pol.External)
	}
}

// injectCredentials modifies the http.Request to add service credentials.
func (p *ProxyEngine) injectCredentials(req *http.Request, svc *ServiceConfig) {
	switch svc.AuthType {
	case "bearer":
		req.Header.Set("Authorization", "Bearer "+svc.Credential)
	case "basic":
		req.SetBasicAuth(svc.Username, svc.Credential)
	case "header":
		header := svc.TokenHeader
		if header == "" {
			header = "Authorization"
		}
		value := svc.Credential
		if svc.TokenPrefix != "" {
			value = svc.TokenPrefix + svc.Credential
		}
		req.Header.Set(header, value)
	case "query":
		q := req.URL.Query()
		q.Set(svc.TokenHeader, svc.Credential)
		req.URL.RawQuery = q.Encode()
	case "none":
		// No credentials injected.
	}

	// Add any extra static headers from service config.
	for k, v := range svc.Headers {
		req.Header.Set(k, v)
	}
}

// AddService registers or updates a service configuration.
func (p *ProxyEngine) AddService(svc *ServiceConfig) error {
	if svc.Name == "" {
		return fmt.Errorf("service name is required")
	}
	if svc.URLPrefix == "" {
		return fmt.Errorf("url_prefix is required for service %s", svc.Name)
	}
	if svc.AuthType == "" {
		svc.AuthType = "none"
	}
	validAuthTypes := map[string]bool{
		"bearer": true, "basic": true, "header": true, "query": true, "none": true,
	}
	if !validAuthTypes[svc.AuthType] {
		return fmt.Errorf("invalid auth_type %q for service %s", svc.AuthType, svc.Name)
	}
	if svc.MaxResponseKB <= 0 {
		svc.MaxResponseKB = defaultMaxResponseKB
	}
	if svc.Timeout <= 0 {
		svc.Timeout = defaultTimeoutSeconds
	}

	p.mu.Lock()
	p.services[svc.Name] = svc
	p.mu.Unlock()

	if err := p.save(); err != nil {
		return fmt.Errorf("persist service %s: %w", svc.Name, err)
	}
	return nil
}

// RemoveService removes a service by name.
func (p *ProxyEngine) RemoveService(name string) error {
	p.mu.Lock()
	if _, ok := p.services[name]; !ok {
		p.mu.Unlock()
		return fmt.Errorf("service %q not found", name)
	}
	delete(p.services, name)
	p.mu.Unlock()

	if err := p.save(); err != nil {
		return fmt.Errorf("persist after removing service %s: %w", name, err)
	}
	return nil
}

// GetService returns a service config by name (with credential redacted).
func (p *ProxyEngine) GetService(name string) (*ServiceConfig, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	svc, ok := p.services[name]
	if !ok {
		return nil, false
	}
	return redactService(svc), true
}

// ListServices returns all service configs (with credentials redacted).
func (p *ProxyEngine) ListServices() []*ServiceConfig {
	p.mu.RLock()
	defer p.mu.RUnlock()

	result := make([]*ServiceConfig, 0, len(p.services))
	for _, svc := range p.services {
		result = append(result, redactService(svc))
	}
	return result
}

// save persists services to disk (atomic write: tmp + rename).

// SaveServices persists the current service configs to disk.
func (p *ProxyEngine) SaveServices() error {
	return p.save()
}

// GetServiceDirect returns the actual service config pointer (not redacted) for in-place mutation.
func (p *ProxyEngine) GetServiceDirect(name string) (*ServiceConfig, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	svc, ok := p.services[name]
	return svc, ok
}
func (p *ProxyEngine) save() error {
	p.mu.RLock()
	data, err := json.MarshalIndent(p.services, "", "  ")
	p.mu.RUnlock()
	if err != nil {
		return fmt.Errorf("marshal services: %w", err)
	}

	tmpPath := p.filePath + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0600); err != nil {
		return fmt.Errorf("write %s: %w", tmpPath, err)
	}
	if err := os.Rename(tmpPath, p.filePath); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("rename %s -> %s: %w", tmpPath, p.filePath, err)
	}

	return nil
}

// load reads services from disk.
func (p *ProxyEngine) load() error {
	data, err := os.ReadFile(p.filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("read %s: %w", p.filePath, err)
	}

	var services map[string]*ServiceConfig
	if err := json.Unmarshal(data, &services); err != nil {
		return fmt.Errorf("parse %s: %w", p.filePath, err)
	}

	p.mu.Lock()
	p.services = services
	p.mu.Unlock()

	return nil
}

// redactService returns a copy of the ServiceConfig with the credential field masked.
func redactService(svc *ServiceConfig) *ServiceConfig {
	c := *svc
	if c.Credential != "" {
		c.Credential = "***"
	}
	return &c
}

// serviceName returns the service name or "direct" if no service matched.
func serviceName(svc *ServiceConfig) string {
	if svc != nil {
		return svc.Name
	}
	return "direct"
}

// isPrivateIP returns true if the IP is in RFC 1918 private address space.
func isPrivateIP(ip net.IP) bool {
	for _, network := range privateRanges {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

// resolveHost resolves a hostname to its IP addresses with a short timeout.
// If the input is already an IP address, it returns that directly.
func resolveHost(hostname string) ([]net.IP, error) {
	// Check if it's already an IP address.
	if ip := net.ParseIP(hostname); ip != nil {
		return []net.IP{ip}, nil
	}

	// Resolve with a timeout.
	ctx, cancel := context.WithTimeout(context.Background(), dnsResolveTimeout)
	defer cancel()

	addrs, err := net.DefaultResolver.LookupHost(ctx, hostname)
	if err != nil {
		return nil, err
	}

	ips := make([]net.IP, 0, len(addrs))
	for _, addr := range addrs {
		if ip := net.ParseIP(addr); ip != nil {
			ips = append(ips, ip)
		}
	}
	return ips, nil
}
