package broker

import (
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"
)

// ActiveCert represents an SSH certificate that has been issued and is
// currently active (not expired or revoked).
type ActiveCert struct {
	Serial      string    `json:"serial"`
	AgentName   string    `json:"agent_name"`
	AgentUID    uint32    `json:"agent_uid"`
	Target      string    `json:"target"`
	Role        string    `json:"role"`
	Principal   string    `json:"principal"`
	IssuedAt    time.Time `json:"issued_at"`
	ExpiresAt   time.Time `json:"expires_at"`
	Certificate string    `json:"certificate"`
}

// PendingRequest represents a certificate request that requires manual
// approval from an admin before the cert can be issued.
type PendingRequest struct {
	ID          string        `json:"id"`
	AgentName   string        `json:"agent_name"`
	AgentUID    uint32        `json:"agent_uid"`
	Target      string        `json:"target"`
	Role        string        `json:"role"`
	Duration    time.Duration `json:"duration"`
	RequestedAt time.Time     `json:"requested_at"`
	PublicKey   string        `json:"public_key"`
}

// CertState tracks all active certificates and pending requests.
// All methods are safe for concurrent use.
type CertState struct {
	mu       sync.RWMutex
	certs    map[string]*ActiveCert    // serial -> cert
	pending  map[string]*PendingRequest // request ID -> pending request
	stopCh   chan struct{}
}

// NewCertState creates a new CertState and starts a background goroutine
// that cleans up expired certificates every 60 seconds.
func NewCertState() *CertState {
	cs := &CertState{
		certs:   make(map[string]*ActiveCert),
		pending: make(map[string]*PendingRequest),
		stopCh:  make(chan struct{}),
	}
	go cs.cleanupLoop()
	return cs
}

// Stop halts the background cleanup goroutine.
func (cs *CertState) Stop() {
	close(cs.stopCh)
}

// cleanupLoop removes expired certificates every 60 seconds.
func (cs *CertState) cleanupLoop() {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			cs.CleanExpired()
		case <-cs.stopCh:
			return
		}
	}
}

// AddCert records a newly issued certificate.
func (cs *CertState) AddCert(cert *ActiveCert) {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	cs.certs[cert.Serial] = cert
}

// RemoveCert removes a certificate by serial number. Returns true if found.
func (cs *CertState) RemoveCert(serial string) bool {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	_, ok := cs.certs[serial]
	if ok {
		delete(cs.certs, serial)
	}
	return ok
}

// GetCert retrieves a certificate by serial number.
func (cs *CertState) GetCert(serial string) (*ActiveCert, bool) {
	cs.mu.RLock()
	defer cs.mu.RUnlock()
	cert, ok := cs.certs[serial]
	if !ok {
		return nil, false
	}
	// Return a copy to avoid races on the pointer.
	c := *cert
	return &c, true
}

// ListCertsForAgent returns all active certs owned by the given UID.
func (cs *CertState) ListCertsForAgent(uid uint32) []*ActiveCert {
	cs.mu.RLock()
	defer cs.mu.RUnlock()
	var result []*ActiveCert
	for _, cert := range cs.certs {
		if cert.AgentUID == uid {
			c := *cert
			result = append(result, &c)
		}
	}
	return result
}

// ListAllCerts returns a copy of all active certificates.
func (cs *CertState) ListAllCerts() []*ActiveCert {
	cs.mu.RLock()
	defer cs.mu.RUnlock()
	result := make([]*ActiveCert, 0, len(cs.certs))
	for _, cert := range cs.certs {
		c := *cert
		result = append(result, &c)
	}
	return result
}

// CleanExpired removes certificates that have been expired for longer than
// the grace period. This keeps recently-expired certs visible in the dashboard
// for a short window before cleanup.
func (cs *CertState) CleanExpired() int {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	now := time.Now()
	gracePeriod := 30 * time.Second
	removed := 0
	for serial, cert := range cs.certs {
		if cert.ExpiresAt.Add(gracePeriod).Before(now) {
			delete(cs.certs, serial)
			removed++
		}
	}
	return removed
}

// CertCountForAgent returns the number of active certs for a given UID.
func (cs *CertState) CertCountForAgent(uid uint32) int {
	cs.mu.RLock()
	defer cs.mu.RUnlock()
	count := 0
	for _, cert := range cs.certs {
		if cert.AgentUID == uid {
			count++
		}
	}
	return count
}

// AddPending stores a new pending request. Returns the generated request ID.
func (cs *CertState) AddPending(req *PendingRequest) string {
	if req.ID == "" {
		req.ID = generateRequestID()
	}
	cs.mu.Lock()
	defer cs.mu.Unlock()
	cs.pending[req.ID] = req
	return req.ID
}

// GetPending retrieves a pending request by ID.
func (cs *CertState) GetPending(id string) (*PendingRequest, bool) {
	cs.mu.RLock()
	defer cs.mu.RUnlock()
	req, ok := cs.pending[id]
	if !ok {
		return nil, false
	}
	r := *req
	return &r, true
}

// RemovePending removes a pending request by ID. Returns true if found.
func (cs *CertState) RemovePending(id string) bool {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	_, ok := cs.pending[id]
	if ok {
		delete(cs.pending, id)
	}
	return ok
}

// ListPending returns all pending requests.
func (cs *CertState) ListPending() []*PendingRequest {
	cs.mu.RLock()
	defer cs.mu.RUnlock()
	result := make([]*PendingRequest, 0, len(cs.pending))
	for _, req := range cs.pending {
		r := *req
		result = append(result, &r)
	}
	return result
}

// generateRequestID creates a random 16-byte hex string for request IDs.
func generateRequestID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
