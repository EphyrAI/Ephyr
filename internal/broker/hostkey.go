package broker

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"log"
	"net"
	"sync"

	"github.com/EphyrAI/Ephyr/internal/audit"
	"golang.org/x/crypto/ssh"
)

// sshFingerprint computes the SHA256:base64 fingerprint of an SSH public key,
// matching the format used by ssh-keygen -l.
func sshFingerprint(key ssh.PublicKey) string {
	hash := sha256.Sum256(key.Marshal())
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(hash[:])
}

// hostKeyCallback returns an ssh.HostKeyCallback for a target.
//
// pinnedKey: parsed public key (from policy host_key field).
// pinnedFP: SHA256 fingerprint string (from policy host_key_fingerprint field).
// If both nil/empty, falls back to InsecureIgnoreHostKey with a one-time warning.
func hostKeyCallback(targetName string, pinnedKey ssh.PublicKey, pinnedFP string, auditLog *audit.AuditLogger, warned *sync.Map) ssh.HostKeyCallback {
	// Prefer full key pinning when available.
	if pinnedKey != nil {
		return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			if err := ssh.FixedHostKey(pinnedKey)(hostname, remote, key); err != nil {
				if auditLog != nil {
					auditLog.LogEvent(audit.AuditEvent{
						Severity:  audit.SeverityAlert,
						EventType: "host_key_mismatch",
						Target:    targetName,
						Details: map[string]string{
							"hostname":              hostname,
							"remote_addr":           remote.String(),
							"expected_fingerprint":  sshFingerprint(pinnedKey),
							"presented_fingerprint": sshFingerprint(key),
						},
					})
				}
				return fmt.Errorf("host key mismatch for target %q: expected %s, got %s",
					targetName, sshFingerprint(pinnedKey), sshFingerprint(key))
			}
			return nil
		}
	}

	// Fingerprint-only pinning.
	if pinnedFP != "" {
		return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			presented := sshFingerprint(key)
			if presented != pinnedFP {
				if auditLog != nil {
					auditLog.LogEvent(audit.AuditEvent{
						Severity:  audit.SeverityAlert,
						EventType: "host_key_mismatch",
						Target:    targetName,
						Details: map[string]string{
							"hostname":              hostname,
							"remote_addr":           remote.String(),
							"expected_fingerprint":  pinnedFP,
							"presented_fingerprint": presented,
						},
					})
				}
				return fmt.Errorf("host key fingerprint mismatch for target %q: expected %s, got %s",
					targetName, pinnedFP, presented)
			}
			return nil
		}
	}

	// No key pinned -- insecure fallback with one-time warning per target.
	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		if warned != nil {
			if _, loaded := warned.LoadOrStore(targetName, true); !loaded {
				log.Printf("[exec] WARNING: no host key pinned for target %q -- SSH MITM possible (T6)", targetName)
				if auditLog != nil {
					auditLog.LogEvent(audit.AuditEvent{
						Severity:  audit.SeverityWarn,
						EventType: "host_key_unpinned",
						Target:    targetName,
						Details: map[string]string{
							"hostname":    hostname,
							"remote_addr": remote.String(),
						},
					})
				}
			}
		}
		return nil
	}
}
