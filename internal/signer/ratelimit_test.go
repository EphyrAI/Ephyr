package signer

import (
	"testing"
	"time"
)

func TestRateLimiterAllows(t *testing.T) {
	rl := NewSignerRateLimiter(5, time.Second)
	for i := 0; i < 5; i++ {
		if !rl.Allow() {
			t.Fatalf("request %d should be allowed", i)
		}
	}
	if rl.Allow() {
		t.Fatal("6th request should be denied")
	}
}

func TestRateLimiterWindowExpiry(t *testing.T) {
	rl := NewSignerRateLimiter(2, 50*time.Millisecond)
	rl.Allow()
	rl.Allow()
	if rl.Allow() {
		t.Fatal("should be denied")
	}
	time.Sleep(60 * time.Millisecond)
	if !rl.Allow() {
		t.Fatal("should be allowed after window expires")
	}
}

func TestRateLimiterZeroMeansNoLimit(t *testing.T) {
	rl := NewSignerRateLimiter(0, time.Second)
	for i := 0; i < 100; i++ {
		if !rl.Allow() {
			t.Fatal("zero limit should allow all")
		}
	}
}

func TestRateLimiterCount(t *testing.T) {
	rl := NewSignerRateLimiter(10, time.Second)
	rl.Allow()
	rl.Allow()
	rl.Allow()
	if c := rl.Count(); c != 3 {
		t.Fatalf("expected 3, got %d", c)
	}
}
