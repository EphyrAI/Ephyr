package main

import (
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const (
	defaultSocket     = "/run/ephyr/broker.sock"
	defaultDuration   = "5m"
	pollInterval      = 2 * time.Second
	pollTimeout       = 5 * time.Minute
)

// cmdRequest handles: ephyr request --target HOST --role ROLE [--duration DUR]
func cmdRequest(args []string) {
	fs := flag.NewFlagSet("request", flag.ExitOnError)
	target := fs.String("target", "", "Target host name")
	targetShort := fs.String("t", "", "Target host name (short)")
	role := fs.String("role", "", "Role to request")
	roleShort := fs.String("r", "", "Role to request (short)")
	duration := fs.String("duration", defaultDuration, "Certificate duration")
	durationShort := fs.String("d", defaultDuration, "Certificate duration (short)")
	socket := fs.String("socket", defaultSocket, "Broker socket path")
	configDir := fs.String("config-dir", defaultConfigDir(), "Config directory")
	_ = fs.Parse(args)

	t := coalesce(*target, *targetShort)
	r := coalesce(*role, *roleShort)
	d := firstNonDefault(*duration, *durationShort, defaultDuration)

	if t == "" || r == "" {
		fmt.Fprintln(os.Stderr, "error: --target and --role are required")
		fs.Usage()
		os.Exit(1)
	}

	client := NewBrokerClient(*socket, *configDir)
	result, err := requestCert(client, t, r, d, *configDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Certificate issued:\n")
	fmt.Printf("  Serial:    %s\n", result.Serial)
	fmt.Printf("  Principal: %s\n", result.Principal)
	fmt.Printf("  Host:      %s:%d\n", result.Host, result.Port)
	fmt.Printf("  Expires:   %s\n", result.ExpiresAt)
	fmt.Printf("  Cert file: %s\n", certPath(*configDir, t))
}

// cmdSSH handles: ephyr ssh --target HOST --role ROLE [--duration DUR]
func cmdSSH(args []string) {
	fs := flag.NewFlagSet("ssh", flag.ExitOnError)
	target := fs.String("target", "", "Target host name")
	targetShort := fs.String("t", "", "Target host name (short)")
	role := fs.String("role", "", "Role to request")
	roleShort := fs.String("r", "", "Role to request (short)")
	duration := fs.String("duration", defaultDuration, "Certificate duration")
	durationShort := fs.String("d", defaultDuration, "Certificate duration (short)")
	socket := fs.String("socket", defaultSocket, "Broker socket path")
	configDir := fs.String("config-dir", defaultConfigDir(), "Config directory")
	_ = fs.Parse(args)

	t := coalesce(*target, *targetShort)
	r := coalesce(*role, *roleShort)
	d := firstNonDefault(*duration, *durationShort, defaultDuration)

	if t == "" || r == "" {
		fmt.Fprintln(os.Stderr, "error: --target and --role are required")
		fs.Usage()
		os.Exit(1)
	}

	client := NewBrokerClient(*socket, *configDir)
	result, err := requestCert(client, t, r, d, *configDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	certFile := certPath(*configDir, t)
	defer os.Remove(certFile)

	keyFile := filepath.Join(*configDir, "id_ed25519")

	sshArgs := buildSSHArgs(keyFile, certFile, result.Principal, result.Host, result.Port, nil)

	fmt.Fprintf(os.Stderr, "Connecting to %s@%s:%d ...\n", result.Principal, result.Host, result.Port)

	exitCode := runSSH(sshArgs)
	os.Exit(exitCode)
}

// cmdExec handles: ephyr exec --target HOST --role ROLE [--duration DUR] -- COMMAND...
func cmdExec(args []string) {
	// Find the "--" separator to split flags from the remote command.
	dashIdx := -1
	for i, arg := range args {
		if arg == "--" {
			dashIdx = i
			break
		}
	}

	var flagArgs, cmdArgs []string
	if dashIdx >= 0 {
		flagArgs = args[:dashIdx]
		cmdArgs = args[dashIdx+1:]
	} else {
		flagArgs = args
	}

	if len(cmdArgs) == 0 {
		fmt.Fprintln(os.Stderr, "error: no command specified after '--'")
		fmt.Fprintln(os.Stderr, "Usage: ephyr exec -t HOST -r ROLE -- COMMAND [ARGS...]")
		os.Exit(1)
	}

	fs := flag.NewFlagSet("exec", flag.ExitOnError)
	target := fs.String("target", "", "Target host name")
	targetShort := fs.String("t", "", "Target host name (short)")
	role := fs.String("role", "", "Role to request")
	roleShort := fs.String("r", "", "Role to request (short)")
	duration := fs.String("duration", defaultDuration, "Certificate duration")
	durationShort := fs.String("d", defaultDuration, "Certificate duration (short)")
	socket := fs.String("socket", defaultSocket, "Broker socket path")
	configDir := fs.String("config-dir", defaultConfigDir(), "Config directory")
	_ = fs.Parse(flagArgs)

	t := coalesce(*target, *targetShort)
	r := coalesce(*role, *roleShort)
	d := firstNonDefault(*duration, *durationShort, defaultDuration)

	if t == "" || r == "" {
		fmt.Fprintln(os.Stderr, "error: --target and --role are required")
		fs.Usage()
		os.Exit(1)
	}

	client := NewBrokerClient(*socket, *configDir)
	result, err := requestCert(client, t, r, d, *configDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	certFile := certPath(*configDir, t)
	defer os.Remove(certFile)

	keyFile := filepath.Join(*configDir, "id_ed25519")

	sshArgs := buildSSHArgs(keyFile, certFile, result.Principal, result.Host, result.Port, cmdArgs)

	exitCode := runSSH(sshArgs)
	os.Exit(exitCode)
}

// cmdCerts handles: ephyr certs (list active certificates)
func cmdCerts(args []string) {
	fs := flag.NewFlagSet("certs", flag.ExitOnError)
	socket := fs.String("socket", defaultSocket, "Broker socket path")
	configDir := fs.String("config-dir", defaultConfigDir(), "Config directory")
	_ = fs.Parse(args)

	client := NewBrokerClient(*socket, *configDir)
	certs, err := client.ListCerts()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	if len(certs) == 0 {
		fmt.Println("No active certificates.")
		return
	}

	fmt.Printf("%-18s %-16s %-14s %-14s %s\n", "SERIAL", "TARGET", "ROLE", "PRINCIPAL", "TTL REMAINING")
	fmt.Printf("%-18s %-16s %-14s %-14s %s\n", "------", "------", "----", "---------", "-------------")

	now := time.Now()
	for _, cert := range certs {
		ttl := "expired"
		if expires, err := time.Parse(time.RFC3339, cert.ExpiresAt); err == nil {
			remaining := expires.Sub(now)
			if remaining > 0 {
				ttl = formatDuration(remaining)
			}
		}
		fmt.Printf("%-18s %-16s %-14s %-14s %s\n", cert.Serial, cert.Target, cert.Role, cert.Principal, ttl)
	}
}

// cmdTargets handles: ephyr targets
func cmdTargets(args []string) {
	fs := flag.NewFlagSet("targets", flag.ExitOnError)
	socket := fs.String("socket", defaultSocket, "Broker socket path")
	configDir := fs.String("config-dir", defaultConfigDir(), "Config directory")
	_ = fs.Parse(args)

	client := NewBrokerClient(*socket, *configDir)
	targets, err := client.ListTargets()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	if len(targets) == 0 {
		fmt.Println("No targets available.")
		return
	}

	fmt.Printf("%-20s %-22s %-6s %-6s %-8s %s\n", "NAME", "HOST", "PORT", "VLAN", "APPROVE", "ROLES")
	fmt.Printf("%-20s %-22s %-6s %-6s %-8s %s\n", "----", "----", "----", "----", "-------", "-----")

	for _, t := range targets {
		approve := "manual"
		if t.AutoApprove {
			approve = "auto"
		}
		roles := strings.Join(t.AllowedRoles, ", ")
		fmt.Printf("%-20s %-22s %-6d %-6d %-8s %s\n", t.Name, t.Host, t.Port, t.VLAN, approve, roles)
	}
}

// cmdWhoami handles: ephyr whoami
func cmdWhoami(args []string) {
	fs := flag.NewFlagSet("whoami", flag.ExitOnError)
	socket := fs.String("socket", defaultSocket, "Broker socket path")
	configDir := fs.String("config-dir", defaultConfigDir(), "Config directory")
	_ = fs.Parse(args)

	client := NewBrokerClient(*socket, *configDir)
	info, err := client.Whoami()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Agent:     %s\n", info.AgentName)
	fmt.Printf("UID:       %d\n", info.UID)
	fmt.Printf("Session:   %s...%s\n", info.Token[:8], info.Token[len(info.Token)-8:])
	fmt.Printf("Created:   %s\n", info.CreatedAt)
	fmt.Printf("Last seen: %s\n", info.LastSeen)
}

// requestCert requests a certificate from the broker, handling pending/polling.
func requestCert(client *BrokerClient, target, role, duration, configDir string) (*RequestResponse, error) {
	result, err := client.Request(target, role, duration)
	if err != nil {
		return nil, err
	}

	switch result.Status {
	case "granted", "approved":
		// Save certificate to disk.
		if err := saveCert(configDir, target, result.Certificate); err != nil {
			return nil, fmt.Errorf("save cert: %w", err)
		}
		return result, nil

	case "denied":
		reason := result.Reason
		if reason == "" {
			reason = "no reason given"
		}
		return nil, fmt.Errorf("request denied: %s", reason)

	case "pending":
		fmt.Fprintf(os.Stderr, "Request pending approval (ID: %s)\n", result.RequestID)
		return pollForApproval(client, result.RequestID, configDir, target)

	default:
		return nil, fmt.Errorf("unexpected response status: %s", result.Status)
	}
}

// pollForApproval polls the broker for a pending request until approved, denied, or timeout.
func pollForApproval(client *BrokerClient, requestID, configDir, target string) (*RequestResponse, error) {
	deadline := time.Now().Add(pollTimeout)
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if time.Now().After(deadline) {
				return nil, fmt.Errorf("timed out waiting for approval after %s", pollTimeout)
			}

			fmt.Fprintf(os.Stderr, "Waiting for approval...\n")

			result, err := client.PollRequest(requestID)
			if err != nil {
				return nil, err
			}

			switch result.Status {
			case "granted", "approved":
				fmt.Fprintf(os.Stderr, "Request approved!\n")
				if err := saveCert(configDir, target, result.Certificate); err != nil {
					return nil, fmt.Errorf("save cert: %w", err)
				}
				return result, nil
			case "denied":
				reason := result.Reason
				if reason == "" {
					reason = "no reason given"
				}
				return nil, fmt.Errorf("request denied: %s", reason)
			case "pending":
				// Continue polling.
			default:
				return nil, fmt.Errorf("unexpected status: %s", result.Status)
			}
		}
	}
}

// saveCert writes a base64-encoded certificate to ~/.ephyr/certs/<target>.cert
func saveCert(configDir, target, certB64 string) error {
	certsDir := filepath.Join(configDir, "certs")
	if err := os.MkdirAll(certsDir, 0700); err != nil {
		return err
	}

	// Decode base64 certificate.
	certBytes, err := base64.StdEncoding.DecodeString(certB64)
	if err != nil {
		// Maybe it's already in authorized_key format (not base64-wrapped).
		certBytes = []byte(certB64)
	}

	certFile := certPath(configDir, target)
	return os.WriteFile(certFile, certBytes, 0600)
}

// certPath returns the path for a target's certificate file.
func certPath(configDir, target string) string {
	return filepath.Join(configDir, "certs", target+"-cert.pub")
}

// buildSSHArgs constructs the ssh command arguments.
func buildSSHArgs(keyFile, certFile, principal, host string, port int, command []string) []string {
	args := []string{
		"-i", keyFile,
		"-o", "CertificateFile=" + certFile,
		"-o", "StrictHostKeyChecking=no",
		"-o", "UserKnownHostsFile=/dev/null",
		"-o", "LogLevel=ERROR",
		"-p", fmt.Sprintf("%d", port),
		fmt.Sprintf("%s@%s", principal, host),
	}

	if len(command) > 0 {
		// For exec mode, join command parts and append as a single arg
		// if there are spaces; otherwise append individually.
		args = append(args, "--")
		args = append(args, command...)
	}

	return args
}

// runSSH executes ssh with the given arguments, passing through stdio.
func runSSH(args []string) int {
	cmd := exec.Command("ssh", args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return exitErr.ExitCode()
		}
		fmt.Fprintf(os.Stderr, "ssh error: %v\n", err)
		return 1
	}
	return 0
}

// formatDuration formats a duration in a human-readable way.
func formatDuration(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
	if d < time.Hour {
		m := int(d.Minutes())
		s := int(d.Seconds()) % 60
		if s > 0 {
			return fmt.Sprintf("%dm%ds", m, s)
		}
		return fmt.Sprintf("%dm", m)
	}
	h := int(d.Hours())
	m := int(d.Minutes()) % 60
	if m > 0 {
		return fmt.Sprintf("%dh%dm", h, m)
	}
	return fmt.Sprintf("%dh", h)
}

// coalesce returns the first non-empty string.
func coalesce(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

// firstNonDefault returns the first value that differs from the default,
// or the default if all match.
func firstNonDefault(values ...string) string {
	if len(values) < 2 {
		return values[0]
	}
	def := values[len(values)-1]
	for _, v := range values[:len(values)-1] {
		if v != def {
			return v
		}
	}
	return def
}
