package main

import (
	"crypto/sha256"
	"encoding/base64"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// cmdHostKey handles: ephyr host-key --host HOST[:PORT]
// Connects to the target, captures its host key, and prints it in
// authorized_keys format alongside the SHA256 fingerprint.
// This output can be pasted directly into policy.yaml.
func cmdHostKey(args []string) {
	fs := flag.NewFlagSet("host-key", flag.ExitOnError)
	host := fs.String("host", "", "Target host address (HOST or HOST:PORT)")
	hostShort := fs.String("h", "", "Target host address (short)")
	_ = fs.Parse(args)

	addr := coalesce(*host, *hostShort)
	if addr == "" {
		// Also accept positional argument.
		if fs.NArg() > 0 {
			addr = fs.Arg(0)
		}
	}
	if addr == "" {
		fmt.Fprintln(os.Stderr, "error: --host is required")
		fmt.Fprintln(os.Stderr, "Usage: ephyr host-key --host HOST[:PORT]")
		os.Exit(1)
	}

	// Default port to 22 if not specified.
	if !strings.Contains(addr, ":") {
		addr = addr + ":22"
	}

	fmt.Fprintf(os.Stderr, "Scanning host key for %s ...\n", addr)

	key, err := scanHostKey(addr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	// Format as authorized_keys line (no trailing newline).
	authorizedKey := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))

	// Compute fingerprint.
	hash := sha256.Sum256(key.Marshal())
	fingerprint := "SHA256:" + base64.RawStdEncoding.EncodeToString(hash[:])

	fmt.Printf("# Host key for %s\n", addr)
	fmt.Printf("# Type: %s\n", key.Type())
	fmt.Printf("# Fingerprint: %s\n", fingerprint)
	fmt.Printf("#\n")
	fmt.Printf("# Add to policy.yaml target:\n")
	fmt.Printf("#   host_key: \"%s\"\n", authorizedKey)
	fmt.Printf("#   host_key_fingerprint: \"%s\"\n", fingerprint)
	fmt.Printf("\n")
	fmt.Printf("host_key: \"%s\"\n", authorizedKey)
	fmt.Printf("host_key_fingerprint: \"%s\"\n", fingerprint)
}

// scanHostKey connects to an SSH server and captures its host key.
// The connection is closed immediately after the key exchange.
func scanHostKey(addr string) (ssh.PublicKey, error) {
	var hostKey ssh.PublicKey

	config := &ssh.ClientConfig{
		User: "ephyr-keyscan",
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			hostKey = key
			return nil
		},
		Timeout: 5 * time.Second,
	}

	conn, err := ssh.Dial("tcp", addr, config)
	if conn != nil {
		conn.Close()
	}
	if hostKey != nil {
		return hostKey, nil
	}
	return nil, fmt.Errorf("failed to capture host key from %s: %w", addr, err)
}
