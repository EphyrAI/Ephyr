package macaroon

import (
	"crypto/rand"
	"fmt"
	"sync"
	"time"
)

// RootKeyStore manages HMAC root keys for task trees.
// One 32-byte key per root task. All descendants verify against the same key.
// In-memory only — broker restart invalidates all tokens (Invariant 7).
type RootKeyStore struct {
	mu   sync.RWMutex
	keys map[string]rootKeyEntry // root task ULID -> entry
}

type rootKeyEntry struct {
	key       [32]byte
	createdAt time.Time
	maxExpiry time.Time // latest possible expiry of any token in this tree
}

// NewRootKeyStore creates a new empty root key store.
func NewRootKeyStore() *RootKeyStore {
	return &RootKeyStore{
		keys: make(map[string]rootKeyEntry),
	}
}

// Generate creates a new 32-byte root key for a task tree.
func (s *RootKeyStore) Generate(rootTaskID string, maxExpiry time.Time) ([32]byte, error) {
	var key [32]byte
	if _, err := rand.Read(key[:]); err != nil {
		return key, fmt.Errorf("rootkeys: failed to generate key: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.keys[rootTaskID] = rootKeyEntry{
		key:       key,
		createdAt: time.Now(),
		maxExpiry: maxExpiry,
	}
	return key, nil
}

// Get returns the root key for a task tree, or false if not found.
func (s *RootKeyStore) Get(rootTaskID string) ([32]byte, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	entry, ok := s.keys[rootTaskID]
	if !ok {
		return [32]byte{}, false
	}
	return entry.key, true
}

// ExtendMaxExpiry updates the max expiry if the new value is later.
// Called when delegation creates children with later expiry.
func (s *RootKeyStore) ExtendMaxExpiry(rootTaskID string, expiry time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()

	entry, ok := s.keys[rootTaskID]
	if !ok {
		return
	}
	if expiry.After(entry.maxExpiry) {
		entry.maxExpiry = expiry
		s.keys[rootTaskID] = entry
	}
}

// Delete removes a root key (called on task revocation).
func (s *RootKeyStore) Delete(rootTaskID string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.keys, rootTaskID)
}

// Cleanup removes expired root keys. Call periodically.
func (s *RootKeyStore) Cleanup() {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	for id, entry := range s.keys {
		if now.After(entry.maxExpiry) {
			delete(s.keys, id)
		}
	}
}

// Count returns the number of stored keys.
func (s *RootKeyStore) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return len(s.keys)
}
