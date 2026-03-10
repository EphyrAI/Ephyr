package auth

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"
	"time"
)

// Session represents an authenticated agent session.
type Session struct {
	Token     string    `json:"token"`
	AgentName string    `json:"agent_name"`
	UID       uint32    `json:"uid"`
	CreatedAt time.Time `json:"created_at"`
	LastSeen  time.Time `json:"last_seen"`
}

// SessionManager tracks active agent sessions with thread-safe access.
type SessionManager struct {
	mu sync.RWMutex

	// byToken maps session token -> Session
	byToken map[string]*Session

	// byAgent maps agent name -> token (for fast invalidation on reconnect)
	byAgent map[string]string
}

// NewSessionManager creates a new empty SessionManager.
func NewSessionManager() *SessionManager {
	return &SessionManager{
		byToken: make(map[string]*Session),
		byAgent: make(map[string]string),
	}
}

// CreateSession generates a new session for the given agent. If the agent
// already has an active session, the old token is invalidated first.
// Returns the new session token.
func (sm *SessionManager) CreateSession(agentName string, uid uint32) (string, error) {
	token, err := generateToken()
	if err != nil {
		return "", fmt.Errorf("session: generate token: %w", err)
	}

	now := time.Now()

	sm.mu.Lock()
	defer sm.mu.Unlock()

	// Invalidate any existing session for this agent.
	if oldToken, exists := sm.byAgent[agentName]; exists {
		delete(sm.byToken, oldToken)
	}

	sess := &Session{
		Token:     token,
		AgentName: agentName,
		UID:       uid,
		CreatedAt: now,
		LastSeen:  now,
	}

	sm.byToken[token] = sess
	sm.byAgent[agentName] = token

	return token, nil
}

// ValidateSession checks whether a token is valid and returns the associated
// agent name and UID. It also updates the LastSeen timestamp.
func (sm *SessionManager) ValidateSession(token string) (agentName string, uid uint32, ok bool) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	sess, exists := sm.byToken[token]
	if !exists {
		return "", 0, false
	}

	sess.LastSeen = time.Now()
	return sess.AgentName, sess.UID, true
}

// InvalidateSession removes the session for the given agent name.
func (sm *SessionManager) InvalidateSession(agentName string) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	token, exists := sm.byAgent[agentName]
	if !exists {
		return
	}

	delete(sm.byToken, token)
	delete(sm.byAgent, agentName)
}

// ActiveSessions returns a snapshot of all current sessions.
func (sm *SessionManager) ActiveSessions() []Session {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	sessions := make([]Session, 0, len(sm.byToken))
	for _, s := range sm.byToken {
		sessions = append(sessions, *s)
	}
	return sessions
}

// generateToken produces a 32-byte (64 hex character) cryptographically
// random token.
func generateToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// GetSessionByAgent returns the session for a given agent name, or nil if not found.
func (sm *SessionManager) GetSessionByAgent(agentName string) *Session {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	token, exists := sm.byAgent[agentName]
	if !exists {
		return nil
	}
	return sm.byToken[token]
}
