package broker

import (
	"errors"
	"net/http"
	"os"
	"testing"
)

func TestStripHopByHopHeaders(t *testing.T) {
	h := make(http.Header)
	// Set all hop-by-hop headers plus a legitimate header that should survive.
	for _, hdr := range hopByHopHeaders {
		h.Set(hdr, "should-be-removed")
	}
	h.Set("Content-Type", "application/json")
	h.Set("X-Custom", "keep-me")

	stripHopByHopHeaders(h)

	for _, hdr := range hopByHopHeaders {
		if v := h.Get(hdr); v != "" {
			t.Errorf("hop-by-hop header %q was not stripped (value: %q)", hdr, v)
		}
	}

	// Verify non-hop-by-hop headers are preserved.
	if v := h.Get("Content-Type"); v != "application/json" {
		t.Errorf("Content-Type was incorrectly stripped or modified: %q", v)
	}
	if v := h.Get("X-Custom"); v != "keep-me" {
		t.Errorf("X-Custom was incorrectly stripped or modified: %q", v)
	}
}

func TestStripSensitiveResponseHeaders(t *testing.T) {
	h := make(http.Header)
	// Set all sensitive response headers plus legitimate headers.
	for _, hdr := range sensitiveResponseHeaders {
		h.Set(hdr, "secret-value")
	}
	h.Set("Content-Type", "text/html")
	h.Set("X-Request-Id", "abc123")

	stripSensitiveResponseHeaders(h)

	for _, hdr := range sensitiveResponseHeaders {
		if v := h.Get(hdr); v != "" {
			t.Errorf("sensitive header %q was not stripped (value: %q)", hdr, v)
		}
	}

	// Verify non-sensitive headers are preserved.
	if v := h.Get("Content-Type"); v != "text/html" {
		t.Errorf("Content-Type was incorrectly stripped or modified: %q", v)
	}
	if v := h.Get("X-Request-Id"); v != "abc123" {
		t.Errorf("X-Request-Id was incorrectly stripped or modified: %q", v)
	}
}

func TestProxyNoRedirectFollow(t *testing.T) {
	// Verify the CheckRedirect pattern used in both NewProxyEngine (shared client)
	// and buildServiceClient (per-service client) returns http.ErrUseLastResponse.
	checkFn := func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	err := checkFn(nil, nil)
	if !errors.Is(err, http.ErrUseLastResponse) {
		t.Fatalf("CheckRedirect returned %v, want http.ErrUseLastResponse", err)
	}

	// Verify buildServiceClient produces a client that blocks redirects.
	// We construct a minimal ProxyEngine to call buildServiceClient.
	pe := &ProxyEngine{}
	svc := &ServiceConfig{
		Name:      "test-redirect",
		URLPrefix: "http://localhost",
		AuthType:  "none",
		Timeout:   5,
	}
	client := pe.buildServiceClient(svc)
	if client.CheckRedirect == nil {
		t.Fatal("buildServiceClient produced a client without CheckRedirect")
	}
	err = client.CheckRedirect(nil, nil)
	if !errors.Is(err, http.ErrUseLastResponse) {
		t.Fatalf("service client CheckRedirect returned %v, want http.ErrUseLastResponse", err)
	}
}

// --- matchesServiceURL tests (P1-1: prevent credential leak via lookalike hostnames) ---

func TestMatchesServiceURL_ExactMatch(t *testing.T) {
	if !matchesServiceURL("http://evil.com", "http://evil.com") {
		t.Error("exact match should return true")
	}
	if !matchesServiceURL("https://api.github.com", "https://api.github.com") {
		t.Error("exact HTTPS match should return true")
	}
}

func TestMatchesServiceURL_PathMatch(t *testing.T) {
	if !matchesServiceURL("http://evil.com/api", "http://evil.com") {
		t.Error("path after prefix should match")
	}
	if !matchesServiceURL("http://evil.com/api/v1/repos", "http://evil.com") {
		t.Error("deep path after prefix should match")
	}
	if !matchesServiceURL("https://api.github.com/repos/owner/repo", "https://api.github.com") {
		t.Error("GitHub API path should match")
	}
}

func TestMatchesServiceURL_LookalikeRejected(t *testing.T) {
	// This is the core security check: a lookalike hostname must NOT match.
	if matchesServiceURL("http://evil.com.attacker.com", "http://evil.com") {
		t.Error("lookalike hostname http://evil.com.attacker.com must NOT match http://evil.com")
	}
	if matchesServiceURL("http://evil.com.attacker.com/path", "http://evil.com") {
		t.Error("lookalike with path must NOT match")
	}
	if matchesServiceURL("https://api.github.com.evil.com/repos", "https://api.github.com") {
		t.Error("GitHub API lookalike must NOT match")
	}
	if matchesServiceURL("http://evil.comedy", "http://evil.com") {
		t.Error("hostname extension must NOT match")
	}
}

func TestMatchesServiceURL_SubpathMatch(t *testing.T) {
	if !matchesServiceURL("http://host.com:3000/api/v1", "http://host.com:3000") {
		t.Error("URL with port and path should match prefix with port")
	}
	if !matchesServiceURL("http://host.com:3000?query=1", "http://host.com:3000") {
		t.Error("query string after prefix should match")
	}
	if !matchesServiceURL("http://host.com:3000#fragment", "http://host.com:3000") {
		t.Error("fragment after prefix should match")
	}
}

func TestMatchesServiceURL_NoMatch(t *testing.T) {
	if matchesServiceURL("http://other.com/api", "http://evil.com") {
		t.Error("completely different host should not match")
	}
	if matchesServiceURL("http://evil.co", "http://evil.com") {
		t.Error("shorter host should not match")
	}
}

func TestClearProxyEnv(t *testing.T) {
	envVars := []string{
		"HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY",
		"http_proxy", "https_proxy", "no_proxy",
	}

	// Set all proxy env vars (t.Setenv will restore originals after test).
	for _, env := range envVars {
		t.Setenv(env, "http://evil-proxy:8080")
	}

	clearProxyEnv()

	for _, env := range envVars {
		if v, ok := os.LookupEnv(env); ok {
			t.Errorf("env %q was not cleared (value: %q)", env, v)
		}
	}
}
