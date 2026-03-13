package broker

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"log"
	"sync"
	"time"
)

// DelegationManager handles the broker's delegated signing authority lifecycle.
// It generates ephemeral Ed25519 keypairs, requests delegation certs from the
// signer, and rotates before expiry.
type DelegationManager struct {
	mu sync.RWMutex

	// Current signing key and cert.
	privateKey ed25519.PrivateKey
	publicKey  ed25519.PublicKey
	certID     string
	certExpiry time.Time
	certIssued time.Time
	signature  []byte // signer's signature over the delegation payload

	// Previous key (kept until all tokens signed with it expire).
	prevPrivateKey ed25519.PrivateKey
	prevCertID     string
	prevExpiry     time.Time

	// Configuration.
	brokerID    string
	ttl         time.Duration // delegation cert lifetime (default 1h)
	refreshAt   time.Duration // when to rotate (default 50min, must be < ttl)
	maxTokenTTL time.Duration // max TTL for tokens signed with this key

	// Root public key (pinned, for token validation).
	rootPublicKey ed25519.PublicKey

	// Signer IPC (interface for testability).
	signerFunc SignerFunc

	stopCh chan struct{}

	// Metrics callback.
	onRotation func()
}

// SignerFunc abstracts the signer IPC for delegation requests.
// Returns: certID, signature, issuedAt, expiresAt, rootPubKey, error.
type SignerFunc func(pubKey ed25519.PublicKey, brokerID string, ttl time.Duration) (
	certID string, signature []byte, issuedAt time.Time, expiresAt time.Time,
	rootPubKey ed25519.PublicKey, err error)

// DelegationConfig configures a DelegationManager.
type DelegationConfig struct {
	BrokerID    string
	TTL         time.Duration // default 1h
	RefreshAt   time.Duration // default 50m
	MaxTokenTTL time.Duration // default 30m
	SignerFunc  SignerFunc
	OnRotation  func() // optional callback for metrics
}

// NewDelegationManager creates a DelegationManager with the given configuration.
// Applies defaults for zero-value TTL (1h), RefreshAt (50m), MaxTokenTTL (30m).
func NewDelegationManager(cfg DelegationConfig) *DelegationManager {
	if cfg.TTL == 0 {
		cfg.TTL = 1 * time.Hour
	}
	if cfg.RefreshAt == 0 {
		cfg.RefreshAt = 50 * time.Minute
	}
	if cfg.MaxTokenTTL == 0 {
		cfg.MaxTokenTTL = 30 * time.Minute
	}
	if cfg.SignerFunc == nil {
		panic("DelegationManager requires a SignerFunc")
	}

	return &DelegationManager{
		brokerID:   cfg.BrokerID,
		ttl:        cfg.TTL,
		refreshAt:  cfg.RefreshAt,
		maxTokenTTL: cfg.MaxTokenTTL,
		signerFunc: cfg.SignerFunc,
		onRotation: cfg.OnRotation,
		stopCh:     make(chan struct{}),
	}
}

// Start performs the initial delegation request and begins the rotation loop.
// Must be called before Sign().
func (dm *DelegationManager) Start() error {
	if err := dm.requestDelegation(); err != nil {
		return fmt.Errorf("initial delegation request failed: %w", err)
	}
	go dm.rotationLoop()
	return nil
}

// Stop halts the rotation loop.
func (dm *DelegationManager) Stop() {
	select {
	case <-dm.stopCh:
		// already stopped
	default:
		close(dm.stopCh)
	}
}

// Sign signs arbitrary data with the current delegated private key.
// Returns an error if the manager has no valid delegation cert.
func (dm *DelegationManager) Sign(data []byte) ([]byte, error) {
	dm.mu.RLock()
	defer dm.mu.RUnlock()

	if dm.privateKey == nil {
		return nil, errors.New("delegation manager not ready: no private key")
	}
	if time.Now().After(dm.certExpiry) {
		return nil, errors.New("delegation cert has expired")
	}

	return ed25519.Sign(dm.privateKey, data), nil
}

// CurrentCertID returns the current delegation cert ID (kid for JWT headers).
func (dm *DelegationManager) CurrentCertID() string {
	dm.mu.RLock()
	defer dm.mu.RUnlock()
	return dm.certID
}

// CurrentPublicKey returns the current delegated public key.
func (dm *DelegationManager) CurrentPublicKey() ed25519.PublicKey {
	dm.mu.RLock()
	defer dm.mu.RUnlock()
	return dm.publicKey
}

// RootPublicKey returns the pinned signer root public key.
func (dm *DelegationManager) RootPublicKey() ed25519.PublicKey {
	dm.mu.RLock()
	defer dm.mu.RUnlock()
	return dm.rootPublicKey
}

// CertExpiry returns when the current delegation cert expires.
func (dm *DelegationManager) CertExpiry() time.Time {
	dm.mu.RLock()
	defer dm.mu.RUnlock()
	return dm.certExpiry
}

// CertAge returns how old the current cert is.
func (dm *DelegationManager) CertAge() time.Duration {
	dm.mu.RLock()
	defer dm.mu.RUnlock()
	if dm.certIssued.IsZero() {
		return 0
	}
	return time.Since(dm.certIssued)
}

// CertSignature returns the signer's signature for the current delegation.
func (dm *DelegationManager) CertSignature() []byte {
	dm.mu.RLock()
	defer dm.mu.RUnlock()
	sig := make([]byte, len(dm.signature))
	copy(sig, dm.signature)
	return sig
}

// IsReady returns true if the manager has a valid, non-expired delegation cert.
func (dm *DelegationManager) IsReady() bool {
	dm.mu.RLock()
	defer dm.mu.RUnlock()
	return dm.privateKey != nil && time.Now().Before(dm.certExpiry)
}

// requestDelegation generates a new Ed25519 keypair, calls the signer to get
// a delegation cert, and stores the result. On rotation, the old key is moved
// to prev.
func (dm *DelegationManager) requestDelegation() error {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("keypair generation failed: %w", err)
	}

	certID, sig, issuedAt, expiresAt, rootPub, err := dm.signerFunc(pub, dm.brokerID, dm.ttl)
	if err != nil {
		return fmt.Errorf("signer IPC failed: %w", err)
	}

	dm.mu.Lock()
	defer dm.mu.Unlock()

	// Move current to previous (for graceful key rollover).
	if dm.privateKey != nil {
		dm.prevPrivateKey = dm.privateKey
		dm.prevCertID = dm.certID
		dm.prevExpiry = dm.certExpiry
	}

	dm.privateKey = priv
	dm.publicKey = pub
	dm.certID = certID
	dm.certIssued = issuedAt
	dm.certExpiry = expiresAt
	dm.signature = sig
	dm.rootPublicKey = rootPub

	return nil
}

// rotate generates a new keypair and requests a new delegation cert.
// The old key is kept as prev for graceful rollover.
func (dm *DelegationManager) rotate() error {
	return dm.requestDelegation()
}

// rotationLoop runs in a goroutine, rotating the delegation cert at
// the configured RefreshAt interval.
func (dm *DelegationManager) rotationLoop() {
	timer := time.NewTimer(dm.refreshAt)
	defer timer.Stop()

	for {
		select {
		case <-timer.C:
			if err := dm.rotate(); err != nil {
				log.Printf("[delegation] rotation failed (keeping old key): %v", err)
			} else {
				log.Printf("[delegation] rotated delegation cert: %s", dm.CurrentCertID())
				if dm.onRotation != nil {
					dm.onRotation()
				}
			}
			timer.Reset(dm.refreshAt)
		case <-dm.stopCh:
			return
		}
	}
}

// CurrentPrivateKey returns the current delegated private key.
// Used by the OnRotation callback to update the token issuer.
func (dm *DelegationManager) CurrentPrivateKey() ed25519.PrivateKey {
	dm.mu.RLock()
	defer dm.mu.RUnlock()
	return dm.privateKey
}

// CertIssuedAt returns when the current delegation cert was issued.
func (dm *DelegationManager) CertIssuedAt() time.Time {
	dm.mu.RLock()
	defer dm.mu.RUnlock()
	return dm.certIssued
}
