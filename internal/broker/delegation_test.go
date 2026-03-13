package broker

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// mockSigner creates a test signer that uses a consistent root key.
func mockSigner() (SignerFunc, ed25519.PublicKey) {
	rootPub, rootPriv, _ := ed25519.GenerateKey(rand.Reader)
	callCount := int64(0)

	fn := func(pubKey ed25519.PublicKey, brokerID string, ttl time.Duration) (
		string, []byte, time.Time, time.Time, ed25519.PublicKey, error) {
		n := atomic.AddInt64(&callCount, 1)
		now := time.Now()
		sig := ed25519.Sign(rootPriv, pubKey)
		certID := fmt.Sprintf("test-cert-%d", n)
		return certID, sig, now, now.Add(ttl), rootPub, nil
	}

	return fn, rootPub
}

// failingSigner always returns an error.
func failingSigner() SignerFunc {
	return func(pubKey ed25519.PublicKey, brokerID string, ttl time.Duration) (
		string, []byte, time.Time, time.Time, ed25519.PublicKey, error) {
		return "", nil, time.Time{}, time.Time{}, nil, errors.New("signer unavailable")
	}
}

// countingSigner tracks how many times it's been called. After failAfter
// successful calls, it returns errors.
func countingSigner(failAfter int) (SignerFunc, *int64) {
	rootPub, rootPriv, _ := ed25519.GenerateKey(rand.Reader)
	callCount := int64(0)

	fn := func(pubKey ed25519.PublicKey, brokerID string, ttl time.Duration) (
		string, []byte, time.Time, time.Time, ed25519.PublicKey, error) {
		n := atomic.AddInt64(&callCount, 1)
		if failAfter > 0 && int(n) > failAfter {
			return "", nil, time.Time{}, time.Time{}, nil, errors.New("signer unavailable")
		}
		now := time.Now()
		sig := ed25519.Sign(rootPriv, pubKey)
		certID := fmt.Sprintf("test-cert-%d", n)
		return certID, sig, now, now.Add(ttl), rootPub, nil
	}

	return fn, &callCount
}

func TestDelegationDefaults(t *testing.T) {
	signer, _ := mockSigner()
	dm := NewDelegationManager(DelegationConfig{
		BrokerID:   "test-broker",
		SignerFunc: signer,
	})

	if dm.ttl != 1*time.Hour {
		t.Errorf("expected default TTL 1h, got %v", dm.ttl)
	}
	if dm.refreshAt != 50*time.Minute {
		t.Errorf("expected default RefreshAt 50m, got %v", dm.refreshAt)
	}
	if dm.maxTokenTTL != 30*time.Minute {
		t.Errorf("expected default MaxTokenTTL 30m, got %v", dm.maxTokenTTL)
	}
}

func TestDelegationCustomConfig(t *testing.T) {
	signer, _ := mockSigner()
	dm := NewDelegationManager(DelegationConfig{
		BrokerID:    "test-broker",
		TTL:         2 * time.Hour,
		RefreshAt:   90 * time.Minute,
		MaxTokenTTL: 45 * time.Minute,
		SignerFunc:  signer,
	})

	if dm.ttl != 2*time.Hour {
		t.Errorf("expected TTL 2h, got %v", dm.ttl)
	}
	if dm.refreshAt != 90*time.Minute {
		t.Errorf("expected RefreshAt 90m, got %v", dm.refreshAt)
	}
	if dm.maxTokenTTL != 45*time.Minute {
		t.Errorf("expected MaxTokenTTL 45m, got %v", dm.maxTokenTTL)
	}
}

func TestDelegationStartSuccess(t *testing.T) {
	signer, rootPub := mockSigner()
	dm := NewDelegationManager(DelegationConfig{
		BrokerID:   "test-broker",
		SignerFunc: signer,
	})

	err := dm.Start()
	if err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	defer dm.Stop()

	// Should have a keypair.
	if dm.CurrentPublicKey() == nil {
		t.Error("expected non-nil public key after Start")
	}

	// Should have a cert ID.
	if dm.CurrentCertID() == "" {
		t.Error("expected non-empty cert ID after Start")
	}

	// Root public key should match.
	gotRoot := dm.RootPublicKey()
	if !gotRoot.Equal(rootPub) {
		t.Error("root public key mismatch")
	}

	// Signature should be non-nil.
	sig := dm.CertSignature()
	if len(sig) == 0 {
		t.Error("expected non-empty signature")
	}
}

func TestDelegationSignData(t *testing.T) {
	signer, _ := mockSigner()
	dm := NewDelegationManager(DelegationConfig{
		BrokerID:   "test-broker",
		SignerFunc: signer,
	})

	err := dm.Start()
	if err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	defer dm.Stop()

	data := []byte("test-payload-for-signing")
	sig, err := dm.Sign(data)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	// Verify with the public key.
	pub := dm.CurrentPublicKey()
	if !ed25519.Verify(pub, data, sig) {
		t.Error("signature verification failed")
	}
}

func TestDelegationSignBeforeStart(t *testing.T) {
	signer, _ := mockSigner()
	dm := NewDelegationManager(DelegationConfig{
		BrokerID:   "test-broker",
		SignerFunc: signer,
	})

	_, err := dm.Sign([]byte("data"))
	if err == nil {
		t.Error("expected error signing before Start")
	}
}

func TestDelegationCertExpiry(t *testing.T) {
	signer, _ := mockSigner()
	ttl := 2 * time.Hour
	dm := NewDelegationManager(DelegationConfig{
		BrokerID:   "test-broker",
		TTL:        ttl,
		SignerFunc: signer,
	})

	err := dm.Start()
	if err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	defer dm.Stop()

	expiry := dm.CertExpiry()
	expected := time.Now().Add(ttl)
	diff := expiry.Sub(expected)
	if diff < -1*time.Second || diff > 1*time.Second {
		t.Errorf("cert expiry off by %v", diff)
	}
}

func TestDelegationIsReady(t *testing.T) {
	signer, _ := mockSigner()
	dm := NewDelegationManager(DelegationConfig{
		BrokerID:   "test-broker",
		SignerFunc: signer,
	})

	if dm.IsReady() {
		t.Error("should not be ready before Start")
	}

	err := dm.Start()
	if err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	defer dm.Stop()

	if !dm.IsReady() {
		t.Error("should be ready after Start")
	}
}

func TestDelegationRotation(t *testing.T) {
	signer, _ := mockSigner()
	rotationCount := int64(0)

	dm := NewDelegationManager(DelegationConfig{
		BrokerID:   "test-broker",
		TTL:        500 * time.Millisecond,
		RefreshAt:  50 * time.Millisecond,
		SignerFunc: signer,
		OnRotation: func() {
			atomic.AddInt64(&rotationCount, 1)
		},
	})

	err := dm.Start()
	if err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	firstCertID := dm.CurrentCertID()
	firstPub := dm.CurrentPublicKey()

	// Wait for rotation.
	time.Sleep(150 * time.Millisecond)
	dm.Stop()

	secondCertID := dm.CurrentCertID()
	secondPub := dm.CurrentPublicKey()

	if firstCertID == secondCertID {
		t.Error("cert ID should change after rotation")
	}
	if firstPub.Equal(secondPub) {
		t.Error("public key should change after rotation")
	}

	count := atomic.LoadInt64(&rotationCount)
	if count < 1 {
		t.Errorf("expected at least 1 rotation, got %d", count)
	}
}

func TestDelegationRotationSwapsPrev(t *testing.T) {
	// Use a channel to detect when rotation happens.
	rotated := make(chan struct{}, 10)

	signer, _ := mockSigner()

	dm := NewDelegationManager(DelegationConfig{
		BrokerID:   "test-broker",
		TTL:        5 * time.Second,
		RefreshAt:  50 * time.Millisecond,
		SignerFunc: signer,
		OnRotation: func() {
			select {
			case rotated <- struct{}{}:
			default:
			}
		},
	})

	err := dm.Start()
	if err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	defer dm.Stop()

	firstCertID := dm.CurrentCertID()

	// Wait for exactly one rotation.
	select {
	case <-rotated:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for rotation")
	}

	dm.mu.RLock()
	prevCertID := dm.prevCertID
	currentCertID := dm.certID
	dm.mu.RUnlock()

	// The prev should be the first cert.
	if prevCertID != firstCertID {
		t.Errorf("expected prev cert ID %q, got %q", firstCertID, prevCertID)
	}
	// The current should be different from first.
	if currentCertID == firstCertID {
		t.Error("current cert ID should differ from first after rotation")
	}
}

func TestDelegationRotationNewPublicKey(t *testing.T) {
	signer, _ := mockSigner()
	var calledPubKeys []ed25519.PublicKey
	var mu sync.Mutex

	wrappedSigner := func(pubKey ed25519.PublicKey, brokerID string, ttl time.Duration) (
		string, []byte, time.Time, time.Time, ed25519.PublicKey, error) {
		mu.Lock()
		keyCopy := make(ed25519.PublicKey, len(pubKey))
		copy(keyCopy, pubKey)
		calledPubKeys = append(calledPubKeys, keyCopy)
		mu.Unlock()
		return signer(pubKey, brokerID, ttl)
	}

	dm := NewDelegationManager(DelegationConfig{
		BrokerID:   "test-broker",
		TTL:        500 * time.Millisecond,
		RefreshAt:  50 * time.Millisecond,
		SignerFunc: wrappedSigner,
	})

	err := dm.Start()
	if err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	time.Sleep(150 * time.Millisecond)
	dm.Stop()

	mu.Lock()
	keys := calledPubKeys
	mu.Unlock()

	if len(keys) < 2 {
		t.Fatalf("expected at least 2 signer calls, got %d", len(keys))
	}

	// Each call should use a different public key.
	if keys[0].Equal(keys[1]) {
		t.Error("signer should be called with different public keys on rotation")
	}
}

func TestDelegationStartFailure(t *testing.T) {
	dm := NewDelegationManager(DelegationConfig{
		BrokerID:   "test-broker",
		SignerFunc: failingSigner(),
	})

	err := dm.Start()
	if err == nil {
		t.Error("expected error from Start with failing signer")
	}
	defer dm.Stop()

	if dm.IsReady() {
		t.Error("should not be ready after failed Start")
	}
}

func TestDelegationRotationFailureKeepsOldKey(t *testing.T) {
	// First call succeeds, subsequent calls fail.
	signer, callCount := countingSigner(1)

	dm := NewDelegationManager(DelegationConfig{
		BrokerID:   "test-broker",
		TTL:        500 * time.Millisecond,
		RefreshAt:  50 * time.Millisecond,
		SignerFunc: signer,
	})

	err := dm.Start()
	if err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	firstCertID := dm.CurrentCertID()

	// Wait for a rotation attempt (which should fail).
	time.Sleep(150 * time.Millisecond)
	dm.Stop()

	// Signer should have been called more than once.
	count := atomic.LoadInt64(callCount)
	if count < 2 {
		t.Errorf("expected at least 2 signer calls, got %d", count)
	}

	// Cert ID should still be the original (rotation failed, kept old key).
	if dm.CurrentCertID() != firstCertID {
		t.Error("cert ID should be unchanged after failed rotation")
	}

	// Should still be ready (old key valid).
	if !dm.IsReady() {
		t.Error("should still be ready after failed rotation")
	}
}

func TestDelegationCertAge(t *testing.T) {
	signer, _ := mockSigner()
	dm := NewDelegationManager(DelegationConfig{
		BrokerID:   "test-broker",
		SignerFunc: signer,
	})

	// Before Start, age should be 0.
	if dm.CertAge() != 0 {
		t.Error("expected 0 age before Start")
	}

	err := dm.Start()
	if err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	defer dm.Stop()

	time.Sleep(50 * time.Millisecond)

	age := dm.CertAge()
	if age < 50*time.Millisecond {
		t.Errorf("expected cert age >= 50ms, got %v", age)
	}
}

func TestDelegationConcurrentSign(t *testing.T) {
	signer, _ := mockSigner()
	dm := NewDelegationManager(DelegationConfig{
		BrokerID:   "test-broker",
		SignerFunc: signer,
	})

	err := dm.Start()
	if err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	defer dm.Stop()

	var wg sync.WaitGroup
	const numGoroutines = 100

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			data := []byte(fmt.Sprintf("payload-%d", n))
			sig, err := dm.Sign(data)
			if err != nil {
				t.Errorf("Sign failed in goroutine %d: %v", n, err)
				return
			}
			if len(sig) != ed25519.SignatureSize {
				t.Errorf("unexpected signature size in goroutine %d: %d", n, len(sig))
			}
		}(i)
	}

	wg.Wait()
}

func TestDelegationStopIdempotent(t *testing.T) {
	signer, _ := mockSigner()
	dm := NewDelegationManager(DelegationConfig{
		BrokerID:   "test-broker",
		SignerFunc: signer,
	})

	err := dm.Start()
	if err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	// Multiple Stop calls should not panic.
	dm.Stop()
	dm.Stop()
	dm.Stop()
}

func TestDelegationSignatureReturnsCopy(t *testing.T) {
	signer, _ := mockSigner()
	dm := NewDelegationManager(DelegationConfig{
		BrokerID:   "test-broker",
		SignerFunc: signer,
	})

	err := dm.Start()
	if err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	defer dm.Stop()

	sig1 := dm.CertSignature()
	sig2 := dm.CertSignature()

	// Mutating sig1 should not affect sig2.
	if len(sig1) > 0 {
		sig1[0] ^= 0xFF
		if sig1[0] == sig2[0] {
			t.Error("CertSignature should return independent copies")
		}
	}
}

func TestDelegationPanicWithoutSignerFunc(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic when SignerFunc is nil")
		}
	}()

	NewDelegationManager(DelegationConfig{
		BrokerID: "test-broker",
	})
}
