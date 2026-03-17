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
