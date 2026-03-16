package broker

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"net"
	"strings"
	"sync"
	"testing"

	"golang.org/x/crypto/ssh"
)

// generateTestKey creates a fresh Ed25519 SSH public key for testing.
func generateTestKey(t *testing.T) ssh.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ed25519 key: %v", err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("convert to ssh public key: %v", err)
	}
	return sshPub
}

// fakeAddr implements net.Addr for testing.
type fakeAddr struct{}

func (fakeAddr) Network() string { return "tcp" }
func (fakeAddr) String() string  { return "10.0.1.10:22" }

func TestSshFingerprint(t *testing.T) {
	key := generateTestKey(t)
	fp := sshFingerprint(key)

	if !strings.HasPrefix(fp, "SHA256:") {
		t.Errorf("fingerprint should start with SHA256:, got %q", fp)
	}

	// Verify the fingerprint matches a manual computation.
	hash := sha256.Sum256(key.Marshal())
	expected := "SHA256:" + base64.RawStdEncoding.EncodeToString(hash[:])
	if fp != expected {
		t.Errorf("fingerprint mismatch: got %q, want %q", fp, expected)
	}

	// Verify no padding characters are present.
	if strings.Contains(fp, "=") {
		t.Errorf("fingerprint should use raw base64 (no padding), got %q", fp)
	}
}

func TestHostKeyCallback_PinnedMatch(t *testing.T) {
	key := generateTestKey(t)
	var warned sync.Map

	cb := hostKeyCallback("test-target", key, "", nil, &warned)

	err := cb("10.0.1.10:22", fakeAddr{}, key)
	if err != nil {
		t.Errorf("expected pinned key match to succeed, got: %v", err)
	}
}

func TestHostKeyCallback_PinnedMismatch(t *testing.T) {
	pinnedKey := generateTestKey(t)
	presentedKey := generateTestKey(t)
	var warned sync.Map

	cb := hostKeyCallback("test-target", pinnedKey, "", nil, &warned)

	err := cb("10.0.1.10:22", fakeAddr{}, presentedKey)
	if err == nil {
		t.Fatal("expected pinned key mismatch to fail, got nil")
	}
	if !strings.Contains(err.Error(), "host key mismatch") {
		t.Errorf("expected 'host key mismatch' in error, got: %v", err)
	}
}

func TestHostKeyCallback_FingerprintMatch(t *testing.T) {
	key := generateTestKey(t)
	fp := sshFingerprint(key)
	var warned sync.Map

	cb := hostKeyCallback("test-target", nil, fp, nil, &warned)

	err := cb("10.0.1.10:22", fakeAddr{}, key)
	if err != nil {
		t.Errorf("expected fingerprint match to succeed, got: %v", err)
	}
}

func TestHostKeyCallback_FingerprintMismatch(t *testing.T) {
	key := generateTestKey(t)
	otherKey := generateTestKey(t)
	fp := sshFingerprint(otherKey) // fingerprint of a different key
	var warned sync.Map

	cb := hostKeyCallback("test-target", nil, fp, nil, &warned)

	err := cb("10.0.1.10:22", fakeAddr{}, key)
	if err == nil {
		t.Fatal("expected fingerprint mismatch to fail, got nil")
	}
	if !strings.Contains(err.Error(), "fingerprint mismatch") {
		t.Errorf("expected 'fingerprint mismatch' in error, got: %v", err)
	}
}

func TestHostKeyCallback_InsecureFallback(t *testing.T) {
	key := generateTestKey(t)
	var warned sync.Map

	cb := hostKeyCallback("test-target", nil, "", nil, &warned)

	// Any key should be accepted.
	err := cb("10.0.1.10:22", fakeAddr{}, key)
	if err != nil {
		t.Errorf("expected insecure fallback to accept any key, got: %v", err)
	}

	// Verify warning was recorded.
	if _, ok := warned.Load("test-target"); !ok {
		t.Error("expected target to be recorded in warned map")
	}

	// Second call should not re-warn (LoadOrStore returns loaded=true).
	// We just verify no panic/error on second call.
	differentKey := generateTestKey(t)
	err = cb("10.0.1.10:22", fakeAddr{}, differentKey)
	if err != nil {
		t.Errorf("expected second insecure fallback call to succeed, got: %v", err)
	}
}

func TestHostKeyCallback_InsecureFallback_NilWarned(t *testing.T) {
	key := generateTestKey(t)

	// nil warned map should not panic.
	cb := hostKeyCallback("test-target", nil, "", nil, nil)

	err := cb("10.0.1.10:22", fakeAddr{}, key)
	if err != nil {
		t.Errorf("expected insecure fallback with nil warned to succeed, got: %v", err)
	}
}

// Verify that fakeAddr satisfies net.Addr at compile time.
var _ net.Addr = fakeAddr{}
