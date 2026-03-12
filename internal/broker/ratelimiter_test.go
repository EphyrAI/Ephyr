package broker

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestRateLimiterAllowWithinWindow(t *testing.T) {
	rl := newRateLimiter(5, 60) // 5 requests per 60 seconds

	for i := 0; i < 5; i++ {
		allowed, retryAfter := rl.Allow(1000)
		if !allowed {
			t.Errorf("request %d should be allowed", i+1)
		}
		if retryAfter != 0 {
			t.Errorf("request %d retryAfter: got %v, want 0", i+1, retryAfter)
		}
	}
}

func TestRateLimiterRejectExceedingLimit(t *testing.T) {
	rl := newRateLimiter(3, 60) // 3 requests per 60 seconds

	// Use up all 3 allowed requests.
	for i := 0; i < 3; i++ {
		allowed, _ := rl.Allow(1000)
		if !allowed {
			t.Fatalf("request %d should be allowed", i+1)
		}
	}

	// 4th request should be denied.
	allowed, retryAfter := rl.Allow(1000)
	if allowed {
		t.Error("4th request should be rejected")
	}
	if retryAfter <= 0 {
		t.Error("retryAfter should be positive when rate limited")
	}
	if retryAfter > 60*time.Second {
		t.Errorf("retryAfter: got %v, should be <= 60s", retryAfter)
	}
}

func TestRateLimiterPerUIDIsolation(t *testing.T) {
	rl := newRateLimiter(2, 60) // 2 requests per 60 seconds

	// UID 1000 uses both slots.
	rl.Allow(1000)
	rl.Allow(1000)

	// UID 1000 should be denied.
	allowed, _ := rl.Allow(1000)
	if allowed {
		t.Error("UID 1000 should be rate limited")
	}

	// UID 2000 should still have its own window.
	allowed, _ = rl.Allow(2000)
	if !allowed {
		t.Error("UID 2000 should be allowed (separate window)")
	}
}

func TestRateLimiterWindowReset(t *testing.T) {
	// Use a very short window (1 second) to test expiry.
	rl := newRateLimiter(2, 1) // 2 requests per 1 second

	rl.Allow(1000)
	rl.Allow(1000)

	// Should be denied now.
	allowed, _ := rl.Allow(1000)
	if allowed {
		t.Error("should be denied after exceeding limit")
	}

	// Wait for window to expire.
	time.Sleep(1100 * time.Millisecond)

	// Should be allowed again.
	allowed, retryAfter := rl.Allow(1000)
	if !allowed {
		t.Errorf("should be allowed after window reset, retryAfter=%v", retryAfter)
	}
}

func TestRateLimiterDisabledWhenZero(t *testing.T) {
	tests := []struct {
		name        string
		maxRequests int
	}{
		{"zero max", 0},
		{"negative max", -1},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rl := newRateLimiter(tc.maxRequests, 60)

			// Should always be allowed when disabled.
			for i := 0; i < 100; i++ {
				allowed, retryAfter := rl.Allow(1000)
				if !allowed {
					t.Errorf("request %d should be allowed when rate limiting disabled", i+1)
				}
				if retryAfter != 0 {
					t.Errorf("retryAfter should be 0 when disabled, got %v", retryAfter)
				}
			}
		})
	}
}

func TestRateLimiterDefaultWindow(t *testing.T) {
	// windowSeconds <= 0 should default to 60.
	rl := newRateLimiter(5, 0)
	if rl.windowDuration != 60*time.Second {
		t.Errorf("default window: got %v, want 60s", rl.windowDuration)
	}

	rl2 := newRateLimiter(5, -10)
	if rl2.windowDuration != 60*time.Second {
		t.Errorf("negative window: got %v, want 60s", rl2.windowDuration)
	}
}

func TestRateLimiterRetryAfterMinimum(t *testing.T) {
	// With a 1s window, retryAfter should be at least 1 second.
	rl := newRateLimiter(1, 1)
	rl.Allow(1000) // use up the slot

	_, retryAfter := rl.Allow(1000)
	if retryAfter < time.Second {
		t.Errorf("retryAfter minimum: got %v, want >= 1s", retryAfter)
	}
}

func TestRateLimiterSlidingWindowPrune(t *testing.T) {
	// Use a 1s window so old timestamps expire quickly.
	rl := newRateLimiter(2, 1)

	rl.Allow(1000)
	time.Sleep(600 * time.Millisecond)
	rl.Allow(1000)

	// Both slots used.
	allowed, _ := rl.Allow(1000)
	if allowed {
		t.Error("should be denied (2 requests in window)")
	}

	// Wait for the first request to fall out of the window.
	time.Sleep(500 * time.Millisecond)

	// Now the first request should be pruned, freeing a slot.
	allowed, _ = rl.Allow(1000)
	if !allowed {
		t.Error("should be allowed after oldest request pruned from window")
	}
}

func TestRateLimiterContextUIDHelpers(t *testing.T) {
	// Test withUID and ContextUID round-trip via an http.Request.
	ctx := withUID(context.Background(), 42)

	// Verify the context value directly.
	uid, ok := ctx.Value(ctxUID).(uint32)
	if !ok {
		t.Fatal("UID not found in context")
	}
	if uid != 42 {
		t.Errorf("UID: got %d, want 42", uid)
	}

	// Test ContextUID with an http.Request carrying the UID context.
	req := httptest.NewRequest("GET", "/test", nil)
	req = req.WithContext(withUID(req.Context(), 99))
	gotUID, gotOK := ContextUID(req)
	if !gotOK {
		t.Fatal("ContextUID should return true")
	}
	if gotUID != 99 {
		t.Errorf("ContextUID: got %d, want 99", gotUID)
	}

	// Test ContextUID without UID in context.
	plainReq := httptest.NewRequest("GET", "/test", nil)
	_, notOK := ContextUID(plainReq)
	if notOK {
		t.Error("ContextUID should return false for request without UID")
	}
}

func TestRateLimitMiddleware(t *testing.T) {
	rl := newRateLimiter(2, 60)

	handler := RateLimitMiddleware(rl, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	}))

	makeRequest := func(uid uint32) *httptest.ResponseRecorder {
		req := httptest.NewRequest("GET", "/test", nil)
		req = req.WithContext(withUID(req.Context(), uid))
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		return rr
	}

	// First 2 requests should succeed.
	for i := 0; i < 2; i++ {
		rr := makeRequest(1000)
		if rr.Code != http.StatusOK {
			t.Errorf("request %d: got status %d, want 200", i+1, rr.Code)
		}
	}

	// 3rd request should be rate limited.
	rr := makeRequest(1000)
	if rr.Code != http.StatusTooManyRequests {
		t.Errorf("rate limited request: got status %d, want 429", rr.Code)
	}
	if rr.Header().Get("Retry-After") == "" {
		t.Error("rate limited response should have Retry-After header")
	}

	// Request without UID should get 401.
	noUIDReq := httptest.NewRequest("GET", "/test", nil)
	noUIDRR := httptest.NewRecorder()
	handler.ServeHTTP(noUIDRR, noUIDReq)
	if noUIDRR.Code != http.StatusUnauthorized {
		t.Errorf("no-UID request: got status %d, want 401", noUIDRR.Code)
	}
}
