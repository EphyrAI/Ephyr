package audit

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"time"
)

// Severity levels for audit events.
type Severity = string

const (
	SeverityInfo  Severity = "INFO"
	SeverityWarn  Severity = "WARN"
	SeverityError Severity = "ERROR"
	SeverityAlert Severity = "ALERT"
)

// EventType identifies the kind of auditable action.
type EventType = string

const (
	EventCertIssued      EventType = "cert_issued"
	EventCertDenied      EventType = "cert_denied"
	EventCertPending     EventType = "cert_pending"
	EventCertRevoked     EventType = "cert_revoked"
	EventCertExpired     EventType = "cert_expired"
	EventCertApproved    EventType = "cert_approved"
	EventRateLimited     EventType = "rate_limited"
	EventPolicyReload    EventType = "policy_reload"
	EventSessionStart    EventType = "session_start"
	EventSessionReset    EventType = "session_reset"
	EventAnomalyDetected EventType = "anomaly_detected"
	EventRequestPending  EventType = "request_pending"
	EventRequestApproved EventType = "request_approved"
	EventRequestDenied   EventType = "request_denied"
	EventRateLimit       EventType = "rate_limited"
	EventStartup         EventType = "startup"
	EventShutdown        EventType = "shutdown"
)

// AuditEvent is a single structured audit log entry.
type AuditEvent struct {
	Timestamp     time.Time         `json:"timestamp"`
	Severity      Severity          `json:"severity"`
	EventType     EventType         `json:"event_type"`
	Agent         string            `json:"agent,omitempty"`
	Target        string            `json:"target,omitempty"`
	Role          string            `json:"role,omitempty"`
	Serial        string            `json:"serial,omitempty"`
	Duration      string            `json:"duration,omitempty"`
	Reason        string            `json:"reason,omitempty"`
	PolicyVersion string            `json:"policy_version,omitempty"`
	Details       map[string]string `json:"details,omitempty"`
	TaskID        string            `json:"task_id,omitempty"`
	TaskRootID    string            `json:"task_root_id,omitempty"`
	InitiatedBy   string            `json:"initiated_by,omitempty"`
	PrevHash      string            `json:"prev_hash,omitempty"`
	Hash          string            `json:"hash,omitempty"`
}

// AuditLogger writes structured JSON audit events to a file and optionally
// mirrors them to stdout. Thread-safe.
type AuditLogger struct {
	mu       sync.Mutex
	writers  []io.Writer
	file     *os.File
	prevHash string // hash of the last written entry
}

// NewLogger creates an AuditLogger. If path is non-empty, events are appended
// to that file. If stdout is true, events are also written to os.Stdout.
// The parent directory is created if it does not exist.
func NewLogger(path string, stdout bool) (*AuditLogger, error) {
	l := &AuditLogger{}

	if path != "" {
		// Ensure the parent directory exists.
		if err := os.MkdirAll(dirOf(path), 0750); err != nil {
			return nil, fmt.Errorf("audit: mkdir: %w", err)
		}

		f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0640)
		if err != nil {
			return nil, fmt.Errorf("audit: open %s: %w", path, err)
		}
		l.file = f
		l.writers = append(l.writers, f)
	}

	if stdout {
		l.writers = append(l.writers, os.Stdout)
	}

	// Fallback: if no writers configured, at least write to stdout.
	if len(l.writers) == 0 {
		l.writers = append(l.writers, os.Stdout)
	}

	l.initChain()

	return l, nil
}

// LogEvent writes a single audit event as a JSON line with hash chaining.
// Each entry includes a SHA-256 hash of its contents and the hash of the
// previous entry, forming a tamper-evident chain.
func (l *AuditLogger) LogEvent(event AuditEvent) {
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now().UTC()
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	// Chain: include hash of previous entry
	event.PrevHash = l.prevHash
	event.Hash = "" // clear before computing

	// Marshal without hash to compute digest
	preHash, err := json.Marshal(event)
	if err != nil {
		return
	}

	// Compute SHA-256
	h := sha256.Sum256(preHash)
	event.Hash = hex.EncodeToString(h[:])

	// Marshal final entry with hash
	data, err := json.Marshal(event)
	if err != nil {
		return
	}
	data = append(data, '\n')

	for _, w := range l.writers {
		_, _ = w.Write(data)
	}

	// Update chain
	l.prevHash = event.Hash
}

// Close closes the underlying log file, if any.
func (l *AuditLogger) Close() error {
	if l.file != nil {
		return l.file.Close()
	}
	return nil
}

// Writer returns the underlying file as an io.Writer for integrations
// that need a raw writer (e.g., middleware loggers). Returns nil if no
// file was configured.
func (l *AuditLogger) Writer() io.Writer {
	return l.file
}

// initChain reads the last line of the audit log to seed the hash chain.
func (l *AuditLogger) initChain() {
	if l.file == nil {
		return
	}
	// Seek to end, scan backward for last newline
	fi, err := l.file.Stat()
	if err != nil || fi.Size() == 0 {
		return
	}

	// Read last 4KB (should contain last entry)
	readSize := int64(4096)
	if fi.Size() < readSize {
		readSize = fi.Size()
	}
	buf := make([]byte, readSize)
	f, err := os.Open(l.file.Name())
	if err != nil {
		return
	}
	defer f.Close()

	_, err = f.ReadAt(buf, fi.Size()-readSize)
	if err != nil && !errors.Is(err, io.EOF) {
		return
	}

	// Find last complete JSON line
	lines := bytes.Split(bytes.TrimRight(buf, "\n"), []byte("\n"))
	if len(lines) == 0 {
		return
	}
	lastLine := lines[len(lines)-1]

	var lastEvent AuditEvent
	if err := json.Unmarshal(lastLine, &lastEvent); err != nil {
		return
	}
	if lastEvent.Hash != "" {
		l.prevHash = lastEvent.Hash
	}
}

// VerifyChain reads the audit log and verifies the hash chain integrity.
// Returns the number of verified entries and any error.
func VerifyChain(path string) (int, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024) // 1MB max line

	var prevHash string
	count := 0

	for scanner.Scan() {
		line := scanner.Bytes()
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}

		var event AuditEvent
		if err := json.Unmarshal(line, &event); err != nil {
			return count, fmt.Errorf("line %d: invalid JSON: %w", count+1, err)
		}

		// Skip legacy entries without hashes
		if event.Hash == "" {
			count++
			continue
		}

		// Verify prev_hash chain
		if event.PrevHash != prevHash {
			return count, fmt.Errorf("line %d: chain broken: expected prev_hash %s, got %s", count+1, prevHash, event.PrevHash)
		}

		// Verify self-hash
		savedHash := event.Hash
		event.Hash = ""
		preHash, err := json.Marshal(event)
		if err != nil {
			return count, fmt.Errorf("line %d: marshal error: %w", count+1, err)
		}
		h := sha256.Sum256(preHash)
		computed := hex.EncodeToString(h[:])
		if computed != savedHash {
			return count, fmt.Errorf("line %d: hash mismatch: expected %s, computed %s", count+1, savedHash, computed)
		}

		prevHash = savedHash
		count++
	}

	return count, scanner.Err()
}

// dirOf returns the directory portion of a file path.
func dirOf(path string) string {
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '/' {
			if i == 0 {
				return "/"
			}
			return path[:i]
		}
	}
	return "."
}
