package main

import (
	"bufio"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/pem"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/ssh"
)

// cmdSetupInit implements the "ephyr init" setup wizard.
// It configures a complete Ephyr installation: CA key, system user,
// directories, policy, systemd units, and service startup.
func cmdSetupInit(args []string) {
	fs := flag.NewFlagSet("init", flag.ExitOnError)
	dev := fs.Bool("dev", false, "Dev mode: ephemeral keys, temp directory, no systemd")
	nonInteractive := fs.Bool("non-interactive", false, "Use all defaults, no prompts")
	_ = fs.Parse(args)

	if *dev {
		initDev()
		return
	}

	// Full install requires root.
	if os.Getuid() != 0 {
		fmt.Fprintln(os.Stderr, "ephyr init must be run as root (need to create system users and write to /etc)")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "For a non-root dev setup, use: ephyr init --dev")
		os.Exit(1)
	}

	fmt.Println("")
	fmt.Println("=== Ephyr Setup ===")
	fmt.Println("")

	reader := bufio.NewReader(os.Stdin)

	// Step 1: CA Key
	caKeyPath := "/etc/ephyr/ca_key"
	fmt.Println("Step 1/6: CA Key")
	caFingerprint := stepCAKey(caKeyPath)
	fmt.Println("")

	// Step 2: System User
	fmt.Println("Step 2/6: System User")
	stepSystemUser()
	fmt.Println("")

	// Step 3: Directories
	fmt.Println("Step 3/6: Directories")
	stepDirectories()
	fmt.Println("")

	// Step 4: Policy
	fmt.Println("Step 4/6: Policy")
	agentName, apiKey, mcpPort, dashPort, dashToken := stepPolicy(reader, *nonInteractive)
	fmt.Println("")

	// Step 5: Systemd
	fmt.Println("Step 5/6: Systemd")
	stepSystemd(dashToken, mcpPort, dashPort)
	fmt.Println("")

	// Step 6: Start Services
	fmt.Println("Step 6/6: Start")
	stepStart()
	fmt.Println("")

	// Summary
	fmt.Println("=== Ephyr is ready ===")
	fmt.Println("")
	fmt.Printf("  Dashboard:  http://localhost:%s  (token: %s)\n", dashPort, dashToken)
	fmt.Printf("  MCP:        http://localhost:%s/mcp\n", mcpPort)
	fmt.Printf("  API key:    %s\n", apiKey)
	fmt.Printf("  CA key:     %s\n", caKeyPath)
	fmt.Printf("  CA finger:  SHA256:%s\n", caFingerprint)
	fmt.Printf("  Agent:      %s\n", agentName)
	fmt.Println("")
	fmt.Println("  Connect Claude Code:")
	fmt.Printf("    claude mcp add -t http ephyr http://BROKER_IP:%s/mcp \\\n", mcpPort)
	fmt.Printf("      -H \"Authorization: Bearer %s\"\n", apiKey)
	fmt.Println("")
	fmt.Println("  Next steps:")
	fmt.Println("    1. Add targets to /etc/ephyr/policy.yaml")
	fmt.Println("    2. Run provision-target.sh on each target host")
	fmt.Printf("    3. Test: ephyr exec <target> --role read -- hostname\n")
	fmt.Println("")
}

// stepCAKey generates an Ed25519 CA key if it does not already exist.
// Returns the SHA256 fingerprint of the CA public key.
func stepCAKey(caKeyPath string) string {
	caDir := filepath.Dir(caKeyPath)
	if err := os.MkdirAll(caDir, 0750); err != nil {
		fatalf("  Cannot create %s: %v", caDir, err)
	}

	if _, err := os.Stat(caKeyPath); err == nil {
		// Key already exists -- read it and print fingerprint.
		fmt.Printf("  CA key already exists at %s\n", caKeyPath)
		fp, err := caKeyFingerprint(caKeyPath)
		if err != nil {
			fmt.Printf("  [OK] CA key exists (could not read fingerprint: %v)\n", err)
			return "existing"
		}
		fmt.Printf("  Fingerprint: SHA256:%s\n", fp)
		fmt.Println("  [OK] CA key exists (skipping)")
		return fp
	}

	fmt.Println("  Generating Ed25519 CA key...")

	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		fatalf("  CA key generation failed: %v", err)
	}

	// Marshal to OpenSSH PEM.
	privPEM, err := ssh.MarshalPrivateKey(privKey, "ephyr-ca")
	if err != nil {
		fatalf("  Marshal CA private key: %v", err)
	}
	privPEMBytes := pem.EncodeToMemory(privPEM)

	if err := os.WriteFile(caKeyPath, privPEMBytes, 0600); err != nil {
		fatalf("  Write CA key: %v", err)
	}

	// Write public key alongside it.
	sshPub, err := ssh.NewPublicKey(pubKey)
	if err != nil {
		fatalf("  Convert CA public key: %v", err)
	}
	pubBytes := ssh.MarshalAuthorizedKey(sshPub)
	pubKeyPath := caKeyPath + ".pub"
	if err := os.WriteFile(pubKeyPath, pubBytes, 0644); err != nil {
		fatalf("  Write CA public key: %v", err)
	}

	fp := sha256Fingerprint(sshPub)
	fmt.Printf("  Location: %s\n", caKeyPath)
	fmt.Printf("  Fingerprint: SHA256:%s\n", fp)
	fmt.Println("  [OK] CA key generated")
	return fp
}

// caKeyFingerprint reads an existing CA key and returns its SHA256 fingerprint.
func caKeyFingerprint(caKeyPath string) (string, error) {
	data, err := os.ReadFile(caKeyPath)
	if err != nil {
		return "", err
	}
	privKey, err := ssh.ParseRawPrivateKey(data)
	if err != nil {
		return "", fmt.Errorf("parse CA key: %w", err)
	}
	signer, err := ssh.NewSignerFromKey(privKey)
	if err != nil {
		return "", fmt.Errorf("signer from key: %w", err)
	}
	return sha256Fingerprint(signer.PublicKey()), nil
}

// stepSystemUser creates the ephyr-broker system user and ephyr-agents group.
func stepSystemUser() {
	// Detect nologin path.
	nologin := detectNologin()

	// Create group.
	if _, err := user.LookupGroup("ephyr-agents"); err != nil {
		fmt.Println("  Creating ephyr-agents group...")
		if err := runCmd("groupadd", "-f", "ephyr-agents"); err != nil {
			fatalf("  Failed to create group: %v", err)
		}
	} else {
		fmt.Println("  Group ephyr-agents already exists")
	}

	// Create user.
	if _, err := user.Lookup("ephyr-broker"); err != nil {
		fmt.Println("  Creating ephyr-broker user...")
		if err := runCmd("useradd", "-r", "-s", nologin, "-g", "ephyr-agents", "-M", "ephyr-broker"); err != nil {
			fatalf("  Failed to create user: %v", err)
		}
	} else {
		fmt.Println("  User ephyr-broker already exists")
	}

	fmt.Printf("  [OK] User created (shell: %s)\n", nologin)
}

// stepDirectories creates the required directories with correct ownership.
func stepDirectories() {
	dirs := []struct {
		path  string
		mode  os.FileMode
		owner string // "root" or "ephyr-broker"
	}{
		{"/etc/ephyr", 0750, "root"},
		{"/var/log/ephyr", 0750, "ephyr-broker"},
		{"/var/lib/ephyr", 0750, "ephyr-broker"},
		{"/run/ephyr", 0750, "ephyr-broker"},
	}

	fmt.Printf("  Creating")
	for i, d := range dirs {
		if i > 0 {
			fmt.Printf(",")
		}
		fmt.Printf(" %s", d.path)
	}
	fmt.Println("...")

	for _, d := range dirs {
		if err := os.MkdirAll(d.path, d.mode); err != nil {
			fatalf("  Cannot create %s: %v", d.path, err)
		}
		// Set ownership.
		chownArgs := []string{d.owner + ":ephyr-agents", d.path}
		if err := runCmd("chown", chownArgs...); err != nil {
			fatalf("  Cannot chown %s: %v", d.path, err)
		}
		if err := os.Chmod(d.path, d.mode); err != nil {
			fatalf("  Cannot chmod %s: %v", d.path, err)
		}
	}

	fmt.Println("  [OK] Directories created with correct permissions")
}

// stepPolicy prompts for policy configuration and writes /etc/ephyr/policy.yaml.
func stepPolicy(reader *bufio.Reader, nonInteractive bool) (agentName, apiKey, mcpPort, dashPort, dashToken string) {
	policyPath := "/etc/ephyr/policy.yaml"

	if _, err := os.Stat(policyPath); err == nil {
		fmt.Printf("  Policy already exists at %s (skipping)\n", policyPath)
		fmt.Println("  [OK] Policy exists")
		// Return sensible defaults for the summary.
		return "existing", "(see policy.yaml)", "8554", "8553", "(see EPHYR_DASHBOARD_TOKEN)"
	}

	if nonInteractive {
		agentName = "my-agent"
		apiKey = generateAPIKey()
		mcpPort = "8554"
		dashPort = "8553"
		dashToken = generateToken()
	} else {
		agentName = promptValue(reader, "Agent name", "my-agent")
		apiKey = promptValue(reader, "API key (leave blank to generate)", "")
		if apiKey == "" {
			apiKey = generateAPIKey()
			fmt.Printf("  Generated API key: %s\n", apiKey)
		}
		mcpPort = promptValue(reader, "MCP port", "8554")
		dashPort = promptValue(reader, "Dashboard port", "8553")
		dashToken = promptValue(reader, "Dashboard token (leave blank to generate)", "")
		if dashToken == "" {
			dashToken = generateToken()
			fmt.Printf("  Generated token: %s\n", dashToken)
		}
	}

	// Generate bcrypt hash.
	hash, err := bcrypt.GenerateFromPassword([]byte(apiKey), bcrypt.DefaultCost)
	if err != nil {
		fatalf("  bcrypt hash generation failed: %v", err)
	}

	policy := buildPolicyYAML(agentName, string(hash))

	fmt.Printf("  Writing %s...\n", policyPath)
	if err := os.WriteFile(policyPath, []byte(policy), 0640); err != nil {
		fatalf("  Write policy: %v", err)
	}

	// Set ownership.
	if err := runCmd("chown", "ephyr-broker:ephyr-agents", policyPath); err != nil {
		fmt.Fprintf(os.Stderr, "  Warning: could not chown %s: %v\n", policyPath, err)
	}

	fmt.Println("  [OK] Policy written")
	return agentName, apiKey, mcpPort, dashPort, dashToken
}

// stepSystemd writes systemd unit files for ephyr-signer and ephyr-broker.
func stepSystemd(dashToken, mcpPort, dashPort string) {
	fmt.Println("  Installing ephyr-signer.service...")
	signerUnit := buildSignerUnit()
	if err := os.WriteFile("/etc/systemd/system/ephyr-signer.service", []byte(signerUnit), 0644); err != nil {
		fatalf("  Write signer unit: %v", err)
	}

	fmt.Println("  Installing ephyr-broker.service...")
	brokerUnit := buildBrokerUnit(dashToken, mcpPort, dashPort)
	if err := os.WriteFile("/etc/systemd/system/ephyr-broker.service", []byte(brokerUnit), 0644); err != nil {
		fatalf("  Write broker unit: %v", err)
	}

	// tmpfiles.d entry for /run/ephyr.
	tmpfilesConf := "d /run/ephyr 0750 ephyr-broker ephyr-agents -\n"
	if err := os.WriteFile("/etc/tmpfiles.d/ephyr.conf", []byte(tmpfilesConf), 0644); err != nil {
		fmt.Fprintf(os.Stderr, "  Warning: could not write tmpfiles.d/ephyr.conf: %v\n", err)
	}
	_ = runCmd("systemd-tmpfiles", "--create")

	if err := runCmd("systemctl", "daemon-reload"); err != nil {
		fatalf("  systemctl daemon-reload failed: %v", err)
	}

	if err := runCmd("systemctl", "enable", "ephyr-signer", "ephyr-broker"); err != nil {
		fmt.Fprintf(os.Stderr, "  Warning: could not enable services: %v\n", err)
	}

	fmt.Println("  [OK] Services installed")
}

// stepStart starts the signer and broker services.
func stepStart() {
	fmt.Println("  Starting ephyr-signer...")
	if err := runCmd("systemctl", "start", "ephyr-signer"); err != nil {
		fatalf("  Failed to start ephyr-signer: %v", err)
	}

	fmt.Println("  Starting ephyr-broker...")
	if err := runCmd("systemctl", "start", "ephyr-broker"); err != nil {
		fatalf("  Failed to start ephyr-broker: %v", err)
	}

	fmt.Println("  [OK] Services running")
}

// initDev sets up a lightweight dev environment with ephemeral keys and config.
func initDev() {
	tmpDir, err := os.MkdirTemp("", "ephyr-dev-*")
	if err != nil {
		fatalf("Cannot create temp dir: %v", err)
	}

	fmt.Println("")
	fmt.Println("=== Ephyr Dev Mode ===")
	fmt.Println("")

	// Generate ephemeral CA key.
	caKeyPath := filepath.Join(tmpDir, "ca_key")
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		fatalf("  CA key generation failed: %v", err)
	}
	privPEM, err := ssh.MarshalPrivateKey(privKey, "ephyr-ca-dev")
	if err != nil {
		fatalf("  Marshal CA key: %v", err)
	}
	if err := os.WriteFile(caKeyPath, pem.EncodeToMemory(privPEM), 0600); err != nil {
		fatalf("  Write CA key: %v", err)
	}

	// Write public key.
	sshPub, err := ssh.NewPublicKey(pubKey)
	if err != nil {
		fatalf("  Convert CA public key: %v", err)
	}
	pubBytes := ssh.MarshalAuthorizedKey(sshPub)
	if err := os.WriteFile(caKeyPath+".pub", pubBytes, 0644); err != nil {
		fatalf("  Write CA public key: %v", err)
	}

	fp := sha256Fingerprint(sshPub)

	// Generate dev API key and hash.
	devAPIKey := "dev"
	devHash, err := bcrypt.GenerateFromPassword([]byte(devAPIKey), bcrypt.DefaultCost)
	if err != nil {
		fatalf("  bcrypt hash: %v", err)
	}

	// Write dev policy.
	policyPath := filepath.Join(tmpDir, "policy.yaml")
	policy := buildPolicyYAML("dev-agent", string(devHash))
	if err := os.WriteFile(policyPath, []byte(policy), 0644); err != nil {
		fatalf("  Write policy: %v", err)
	}

	// Create required subdirectories.
	for _, sub := range []string{"log", "lib", "run"} {
		if err := os.MkdirAll(filepath.Join(tmpDir, sub), 0750); err != nil {
			fatalf("  Create %s dir: %v", sub, err)
		}
	}

	fmt.Printf("  Base dir:   %s\n", tmpDir)
	fmt.Printf("  CA key:     %s (ephemeral)\n", caKeyPath)
	fmt.Printf("  CA finger:  SHA256:%s\n", fp)
	fmt.Printf("  Policy:     %s\n", policyPath)
	fmt.Println("")
	fmt.Println("  Dashboard:  http://localhost:8553 (token: dev)")
	fmt.Println("  MCP:        http://localhost:8554/mcp (key: dev)")
	fmt.Println("")
	fmt.Println("  To start the signer:")
	fmt.Printf("    ephyr-signer --ca-key %s --socket %s/run/signer.sock\n", caKeyPath, tmpDir)
	fmt.Println("")
	fmt.Println("  To start the broker:")
	fmt.Printf("    EPHYR_SIGNER_SOCKET=%s/run/signer.sock \\\n", tmpDir)
	fmt.Println("    EPHYR_MCP_LISTEN=:8554 \\")
	fmt.Println("    EPHYR_DASHBOARD_LISTEN=:8553 \\")
	fmt.Println("    EPHYR_DASHBOARD_TOKEN=dev \\")
	fmt.Printf("    ephyr-broker --policy %s\n", policyPath)
	fmt.Println("")
	fmt.Printf("  All state is ephemeral in %s.\n", tmpDir)
	fmt.Println("  Remove with: rm -rf", tmpDir)
	fmt.Println("")
}

// generateAPIKey produces a cryptographically random 32-byte API key
// encoded as base64url (no padding).
func generateAPIKey() string {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		fatalf("  Random key generation failed: %v", err)
	}
	return base64.RawURLEncoding.EncodeToString(key)
}

// generateToken produces a shorter random token (16 bytes) for dashboard access.
func generateToken() string {
	key := make([]byte, 16)
	if _, err := rand.Read(key); err != nil {
		fatalf("  Random token generation failed: %v", err)
	}
	return base64.RawURLEncoding.EncodeToString(key)
}

// promptValue reads interactive input from the user. If the user presses
// Enter without typing anything, defaultVal is returned.
func promptValue(reader *bufio.Reader, label, defaultVal string) string {
	if defaultVal != "" {
		fmt.Printf("  %s [%s]: ", label, defaultVal)
	} else {
		fmt.Printf("  %s: ", label)
	}
	input, _ := reader.ReadString('\n')
	input = strings.TrimSpace(input)
	if input == "" {
		return defaultVal
	}
	return input
}

// detectNologin returns the path to nologin (or /usr/bin/false as fallback).
func detectNologin() string {
	for _, p := range []string{"/usr/sbin/nologin", "/sbin/nologin"} {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return "/usr/bin/false"
}

// runCmd executes an external command, returning any error.
func runCmd(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// fatalf prints an error message and exits.
func fatalf(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}

// buildPolicyYAML produces a minimal policy.yaml with one agent configured.
func buildPolicyYAML(agentName, apiKeyHash string) string {
	return fmt.Sprintf(`# Ephyr -- Generated Policy
# See docs/configuration.md for full reference

global:
  max_active_certs: 10
  default_ttl: "5m"
  max_ttl: "30m"

agents:
  %s:
    api_key_hash: "%s"
    can_delegate: true
    max_concurrent_certs: 5

roles:
  read:
    principal: "agent-read"
  operator:
    principal: "agent-op"
  admin:
    principal: "agent-admin"

# Uncomment and configure your targets:
# targets:
#   webserver:
#     host: "10.0.1.10"
#     port: 22
#     allowed_roles: [read, operator]
#     auto_approve: true
#     # host_key: "ssh-ed25519 AAAAC3..."
`, agentName, apiKeyHash)
}

// buildSignerUnit returns the systemd unit file content for ephyr-signer.
func buildSignerUnit() string {
	return `[Unit]
Description=Ephyr SSH Certificate Signer
Documentation=https://github.com/EphyrAI/Ephyr
After=network.target
Before=ephyr-broker.service

[Service]
Type=simple
User=ephyr-broker
Group=ephyr-agents
ExecStart=/usr/local/bin/ephyr signer --ca-key /etc/ephyr/ca_key --socket /run/ephyr/signer.sock

StandardOutput=journal
StandardError=journal
SyslogIdentifier=ephyr-signer

Restart=on-failure
RestartSec=5s

ProtectSystem=strict
ProtectHome=yes
NoNewPrivileges=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
RestrictNamespaces=yes

ReadOnlyPaths=/etc/ephyr
ReadWritePaths=/run/ephyr

CapabilityBoundingSet=
AmbientCapabilities=
SystemCallArchitectures=native
SystemCallFilter=@system-service
SystemCallErrorNumber=EPERM

[Install]
WantedBy=multi-user.target
`
}

// buildBrokerUnit returns the systemd unit file content for ephyr-broker.
func buildBrokerUnit(dashToken, mcpPort, dashPort string) string {
	return fmt.Sprintf(`[Unit]
Description=Ephyr SSH Certificate Broker
Documentation=https://github.com/EphyrAI/Ephyr
After=network.target ephyr-signer.service
Wants=ephyr-signer.service

[Service]
Type=simple
User=ephyr-broker
Group=ephyr-agents
ExecStart=/usr/local/bin/ephyr broker --policy /etc/ephyr/policy.yaml
ExecReload=/bin/kill -HUP $MAINPID

Environment=EPHYR_SIGNER_SOCKET=/run/ephyr/signer.sock
Environment=EPHYR_MCP_LISTEN=:%s
Environment=EPHYR_DASHBOARD_LISTEN=:%s
Environment=EPHYR_DASHBOARD_TOKEN=%s

StandardOutput=journal
StandardError=journal
SyslogIdentifier=ephyr-broker

Restart=on-failure
RestartSec=5s

ProtectSystem=strict
ProtectHome=yes
NoNewPrivileges=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
RestrictNamespaces=yes

ReadWritePaths=/run/ephyr /var/log/ephyr /var/lib/ephyr

CapabilityBoundingSet=
AmbientCapabilities=
SystemCallArchitectures=native
SystemCallFilter=@system-service
SystemCallErrorNumber=EPERM

[Install]
WantedBy=multi-user.target
`, mcpPort, dashPort, dashToken)
}
