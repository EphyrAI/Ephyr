package main

import (
	"bufio"
	"flag"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/EphyrAI/Ephyr/internal/policy"
	"golang.org/x/crypto/ssh"
	sshagent "golang.org/x/crypto/ssh/agent"
	"golang.org/x/term"
)

// ANSI color helpers for provision output.
const (
	pReset  = "\033[0m"
	pBold   = "\033[1m"
	pRed    = "\033[31m"
	pGreen  = "\033[32m"
	pYellow = "\033[33m"
	pDim    = "\033[2m"
)

func pOK(msg string)   { fmt.Printf("  %s[OK]%s   %s\n", pGreen, pReset, msg) }
func pWarn(msg string)  { fmt.Printf("  %s[WARN]%s %s\n", pYellow, pReset, msg) }
func pFail(msg string)  { fmt.Printf("  %s[FAIL]%s %s\n", pRed, pReset, msg) }
func pStep(msg string)  { fmt.Printf("\n%s▸ %s%s\n", pBold, msg, pReset) }
func pDry(msg string)   { fmt.Printf("  %s[DRY]%s  %s\n", pDim, pReset, msg) }

func cmdTargetProvision(args []string) {
	fs := flag.NewFlagSet("target-provision", flag.ExitOnError)
	policyPath := fs.String("policy", "/etc/ephyr/policy.yaml", "Policy file path")
	caPubPath := fs.String("ca-pub", "/etc/ephyr/ca_key.pub", "CA public key file")
	dryRun := fs.Bool("dry-run", false, "Show what would be done")
	sshUser := fs.String("ssh-user", "root", "SSH user for provisioning")
	sshPassword := fs.Bool("ssh-password", false, "Prompt for SSH password")
	skipConfirm := fs.Bool("yes", false, "Skip confirmation prompts")
	_ = fs.Parse(args)

	if fs.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "error: target name is required")
		fmt.Fprintln(os.Stderr, "Usage: ephyr target provision <target-name> [flags]")
		os.Exit(1)
	}

	targetName := fs.Arg(0)

	// ── Load policy ──────────────────────────────────────────────────────
	_, resolved, err := policy.LoadFromFile(*policyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: loading policy: %v\n", err)
		os.Exit(1)
	}

	target, ok := resolved.Raw.Targets[targetName]
	if !ok {
		fmt.Fprintf(os.Stderr, "error: target %q not found in policy\n", targetName)
		fmt.Fprintln(os.Stderr, "Available targets:")
		names := make([]string, 0, len(resolved.Raw.Targets))
		for n := range resolved.Raw.Targets {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, n := range names {
			t := resolved.Raw.Targets[n]
			fmt.Fprintf(os.Stderr, "  %-20s %s:%d\n", n, t.Host, t.Port)
		}
		os.Exit(1)
	}

	// ── Resolve roles for this target ────────────────────────────────────
	var roles []*policy.ResolvedRole
	for _, roleName := range target.AllowedRoles {
		r, ok := resolved.ResolvedRoles[roleName]
		if !ok {
			fmt.Fprintf(os.Stderr, "error: role %q referenced by target %q not found\n", roleName, targetName)
			os.Exit(1)
		}
		roles = append(roles, r)
	}

	if len(roles) == 0 {
		fmt.Fprintf(os.Stderr, "error: target %q has no allowed_roles\n", targetName)
		os.Exit(1)
	}

	// ── Read CA public key ───────────────────────────────────────────────
	caPubKey, err := os.ReadFile(*caPubPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: reading CA public key from %s: %v\n", *caPubPath, err)
		os.Exit(1)
	}
	caPubKeyStr := strings.TrimSpace(string(caPubKey))
	if !strings.HasPrefix(caPubKeyStr, "ssh-") {
		fmt.Fprintf(os.Stderr, "error: %s does not look like an SSH public key\n", *caPubPath)
		os.Exit(1)
	}

	// ── Show plan ────────────────────────────────────────────────────────
	addr := fmt.Sprintf("%s:%d", target.Host, target.Port)

	fmt.Printf("\n%s═══ Ephyr Target Provisioning ═══%s\n", pBold, pReset)
	fmt.Printf("  Target:  %s (%s)\n", targetName, addr)
	fmt.Printf("  SSH as:  %s\n", *sshUser)
	fmt.Printf("  CA key:  %s\n", *caPubPath)
	fmt.Printf("  Policy:  %s\n", *policyPath)
	fmt.Printf("  Roles:   %d\n", len(roles))

	for _, r := range roles {
		sudoDesc := "none"
		if len(r.SudoRules) == 1 && r.SudoRules[0] == "ALL" {
			sudoDesc = "ALL"
		} else if len(r.SudoRules) > 0 {
			sudoDesc = fmt.Sprintf("%d rules", len(r.SudoRules))
		}
		fmt.Printf("           %-15s  shell=%s  sudo=%s  principal=%s\n",
			r.Name, r.Shell, sudoDesc, r.Principal)
	}

	if *dryRun {
		fmt.Printf("\n%s  ── DRY RUN: showing commands that would be executed ──%s\n", pDim, pReset)
		printDryRun(caPubKeyStr, roles)
		return
	}

	// ── Confirmation ─────────────────────────────────────────────────────
	if !*skipConfirm {
		fmt.Printf("\nProceed with provisioning? [y/N] ")
		reader := bufio.NewReader(os.Stdin)
		line, _ := reader.ReadString('\n')
		line = strings.TrimSpace(strings.ToLower(line))
		if line != "y" && line != "yes" {
			fmt.Fprintln(os.Stderr, "Aborted.")
			os.Exit(0)
		}
	}

	// ── SSH connection ───────────────────────────────────────────────────
	var authMethods []ssh.AuthMethod

	if *sshPassword {
		fmt.Fprintf(os.Stderr, "SSH password for %s@%s: ", *sshUser, target.Host)
		passBytes, err := term.ReadPassword(syscall.Stdin)
		fmt.Fprintln(os.Stderr) // newline after password input
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: reading password: %v\n", err)
			os.Exit(1)
		}
		authMethods = append(authMethods, ssh.Password(string(passBytes)))
	} else {
		// Try SSH agent or default key.
		signers := loadSSHSigners()
		if len(signers) == 0 {
			fmt.Fprintln(os.Stderr, "error: no SSH keys available and --ssh-password not set")
			fmt.Fprintln(os.Stderr, "Use --ssh-password to authenticate with a password")
			os.Exit(1)
		}
		authMethods = append(authMethods, ssh.PublicKeys(signers...))
	}

	sshConfig := &ssh.ClientConfig{
		User:            *sshUser,
		Auth:            authMethods,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), //nolint:gosec // provisioning tool, target not yet trusted
		Timeout:         10 * time.Second,
	}

	pStep(fmt.Sprintf("Connecting to %s", addr))
	client, err := ssh.Dial("tcp", addr, sshConfig)
	if err != nil {
		pFail(fmt.Sprintf("SSH connection failed: %v", err))
		os.Exit(1)
	}
	defer client.Close()
	pOK(fmt.Sprintf("Connected to %s as %s", addr, *sshUser))

	// ── Execute provisioning steps ───────────────────────────────────────
	runner := &sshRunner{client: client}
	failed := false

	// Step 1: Install CA public key.
	pStep("Installing CA public key")
	cmds := []string{
		fmt.Sprintf("echo %q > /etc/ssh/ephyr_ca.pub", caPubKeyStr),
		"chmod 644 /etc/ssh/ephyr_ca.pub",
		"chown root:root /etc/ssh/ephyr_ca.pub",
	}
	if err := runner.run(strings.Join(cmds, " && ")); err != nil {
		pFail(fmt.Sprintf("Failed to install CA key: %v", err))
		failed = true
	} else {
		pOK("CA public key installed to /etc/ssh/ephyr_ca.pub")
	}

	// Step 2: Configure sshd.
	pStep("Configuring sshd")

	// Backup sshd_config if not already backed up.
	if err := runner.run(`[ -f /etc/ssh/sshd_config.ephyr-backup ] || cp /etc/ssh/sshd_config /etc/ssh/sshd_config.ephyr-backup`); err != nil {
		pWarn(fmt.Sprintf("Could not backup sshd_config: %v", err))
	} else {
		pOK("sshd_config backup ensured")
	}

	// TrustedUserCAKeys (idempotent).
	if err := runner.run(`grep -q "^TrustedUserCAKeys.*/etc/ssh/ephyr_ca.pub" /etc/ssh/sshd_config 2>/dev/null || { echo "" >> /etc/ssh/sshd_config && echo "# Ephyr SSH Certificate Authentication" >> /etc/ssh/sshd_config && echo "TrustedUserCAKeys /etc/ssh/ephyr_ca.pub" >> /etc/ssh/sshd_config; }`); err != nil {
		pFail(fmt.Sprintf("Failed to configure TrustedUserCAKeys: %v", err))
		failed = true
	} else {
		pOK("TrustedUserCAKeys configured")
	}

	// AuthorizedPrincipalsFile (idempotent).
	if err := runner.run(`grep -q "^AuthorizedPrincipalsFile.*/etc/ssh/auth_principals" /etc/ssh/sshd_config 2>/dev/null || echo "AuthorizedPrincipalsFile /etc/ssh/auth_principals/%u" >> /etc/ssh/sshd_config`); err != nil {
		pFail(fmt.Sprintf("Failed to configure AuthorizedPrincipalsFile: %v", err))
		failed = true
	} else {
		pOK("AuthorizedPrincipalsFile configured")
	}

	// Step 3: Ensure sudo is installed.
	pStep("Ensuring sudo is available")
	if err := runner.run(`command -v sudo >/dev/null 2>&1 || { apt-get update -qq && apt-get install -y -qq sudo 2>/dev/null || yum install -y -q sudo 2>/dev/null || apk add --quiet sudo 2>/dev/null; }`); err != nil {
		pWarn(fmt.Sprintf("Could not ensure sudo: %v", err))
	} else {
		pOK("sudo is available")
	}
	// Ensure sudoers.d directory.
	_ = runner.run("mkdir -p /etc/sudoers.d")

	// Step 4: Ensure rbash if any role uses it.
	needsRbash := false
	for _, r := range roles {
		if strings.Contains(r.Shell, "rbash") {
			needsRbash = true
			break
		}
	}
	if needsRbash {
		pStep("Ensuring rbash is available")
		if err := runner.run(`[ -x /usr/bin/rbash ] || [ -x /bin/rbash ] || ln -sf /bin/bash /usr/bin/rbash`); err != nil {
			pWarn(fmt.Sprintf("Could not ensure rbash: %v", err))
		} else {
			pOK("rbash is available")
		}
	}

	// Step 5: Create role accounts.
	pStep("Creating role accounts")
	_ = runner.run("mkdir -p /etc/ssh/auth_principals && chmod 755 /etc/ssh/auth_principals && chown root:root /etc/ssh/auth_principals")

	for _, r := range roles {
		systemFlag := ""
		if r.System {
			systemFlag = "--system"
		}

		// Create user if it doesn't exist.
		createCmd := fmt.Sprintf(
			`id %s >/dev/null 2>&1 || useradd %s --create-home --shell %s --comment "Ephyr %s role" %s`,
			r.Principal, systemFlag, r.Shell, r.Name, r.Principal,
		)
		if err := runner.run(createCmd); err != nil {
			pFail(fmt.Sprintf("Failed to create user %s: %v", r.Principal, err))
			failed = true
		} else {
			pOK(fmt.Sprintf("User %s (shell=%s)", r.Principal, r.Shell))
		}

		// Create principals file.
		principalCmd := fmt.Sprintf(
			`echo %q > /etc/ssh/auth_principals/%s && chmod 644 /etc/ssh/auth_principals/%s && chown root:root /etc/ssh/auth_principals/%s`,
			r.Principal, r.Principal, r.Principal, r.Principal,
		)
		if err := runner.run(principalCmd); err != nil {
			pFail(fmt.Sprintf("Failed to create principals file for %s: %v", r.Principal, err))
			failed = true
		} else {
			pOK(fmt.Sprintf("Principals file for %s", r.Principal))
		}

		// Ensure .ssh directory.
		sshDirCmd := fmt.Sprintf(
			`home=$(getent passwd %s | cut -d: -f6) && mkdir -p "$home/.ssh" && chmod 700 "$home/.ssh" && chown %s "$home/.ssh"`,
			r.Principal, r.Principal,
		)
		_ = runner.run(sshDirCmd)
	}

	// Step 6: Install sudoers.
	pStep("Installing sudoers rules")
	sudoersContent := generateSudoers(roles)

	// Remove immutable flag if present from a previous run.
	_ = runner.run("[ -f /etc/sudoers.d/ephyr ] && chattr -i /etc/sudoers.d/ephyr 2>/dev/null || true")

	// Write sudoers file.
	writeCmd := fmt.Sprintf("cat > /etc/sudoers.d/ephyr << 'EPHYR_SUDOERS_EOF'\n%s\nEPHYR_SUDOERS_EOF", sudoersContent)
	if err := runner.run(writeCmd); err != nil {
		pFail(fmt.Sprintf("Failed to write sudoers file: %v", err))
		failed = true
	} else {
		// Set permissions and validate.
		if err := runner.run("chmod 440 /etc/sudoers.d/ephyr && chown root:root /etc/sudoers.d/ephyr"); err != nil {
			pFail(fmt.Sprintf("Failed to set sudoers permissions: %v", err))
			failed = true
		} else if err := runner.run("visudo -c -f /etc/sudoers.d/ephyr"); err != nil {
			pFail(fmt.Sprintf("Sudoers validation failed: %v", err))
			// Remove invalid file.
			_ = runner.run("rm -f /etc/sudoers.d/ephyr")
			failed = true
		} else {
			pOK("Sudoers rules installed and validated")
			// Make immutable.
			if err := runner.run("chattr +i /etc/sudoers.d/ephyr 2>/dev/null"); err != nil {
				pWarn("Could not make sudoers file immutable (chattr not available)")
			} else {
				pOK("Sudoers file made immutable (chattr +i)")
			}
		}
	}

	// Step 7: Validate sshd config and reload.
	pStep("Validating and reloading sshd")
	if err := runner.run("sshd -t"); err != nil {
		pFail(fmt.Sprintf("sshd configuration validation failed: %v", err))
		pWarn("Restoring sshd_config backup")
		_ = runner.run("[ -f /etc/ssh/sshd_config.ephyr-backup ] && cp /etc/ssh/sshd_config.ephyr-backup /etc/ssh/sshd_config")
		failed = true
	} else {
		pOK("sshd configuration is valid")
		if err := runner.run("systemctl reload sshd 2>/dev/null || systemctl reload ssh 2>/dev/null || systemctl restart sshd 2>/dev/null || systemctl restart ssh 2>/dev/null"); err != nil {
			pWarn(fmt.Sprintf("Could not reload sshd: %v", err))
		} else {
			pOK("sshd reloaded")
		}
	}

	// ── Summary ──────────────────────────────────────────────────────────
	fmt.Println()
	if failed {
		fmt.Printf("%s═══ Provisioning completed with errors ═══%s\n", pRed, pReset)
		fmt.Fprintln(os.Stderr, "Some steps failed. Review the output above.")
		os.Exit(1)
	}

	fmt.Printf("%s═══ Provisioning complete ═══%s\n", pGreen, pReset)
	fmt.Printf("\n  Target %s%s%s is ready for Ephyr SSH certificates.\n", pBold, targetName, pReset)
	fmt.Printf("  Role accounts created:\n")
	for _, r := range roles {
		sudoDesc := "no sudo"
		if len(r.SudoRules) == 1 && r.SudoRules[0] == "ALL" {
			sudoDesc = "sudo ALL"
		} else if len(r.SudoRules) > 0 {
			sudoDesc = fmt.Sprintf("sudo (%d rules)", len(r.SudoRules))
		}
		fmt.Printf("    %-15s  shell=%s  %s\n", r.Principal, r.Shell, sudoDesc)
	}
	fmt.Println()
}

// sshRunner executes commands on a remote host via SSH.
type sshRunner struct {
	client *ssh.Client
}

// run executes a command on the remote host and returns an error if it fails.
// On failure, the combined stdout/stderr output is included in the error.
func (r *sshRunner) run(cmd string) error {
	session, err := r.client.NewSession()
	if err != nil {
		return fmt.Errorf("creating session: %w", err)
	}
	defer session.Close()

	output, err := session.CombinedOutput(cmd)
	if err != nil {
		outStr := strings.TrimSpace(string(output))
		if outStr != "" {
			return fmt.Errorf("%w: %s", err, outStr)
		}
		return err
	}
	return nil
}

// loadSSHSigners attempts to load SSH private keys for authentication.
// It tries the standard locations: SSH agent, then ~/.ssh/id_ed25519, id_rsa.
func loadSSHSigners() []ssh.Signer {
	var signers []ssh.Signer

	// Try SSH agent.
	if agentSocket := os.Getenv("SSH_AUTH_SOCK"); agentSocket != "" {
		conn, err := net.Dial("unix", agentSocket)
		if err == nil {
			// Use the agent protocol to get signers.
			// We import the agent package inline to avoid pulling it in when not needed.
			agentSigners := getAgentSigners(conn)
			signers = append(signers, agentSigners...)
		}
	}

	// Try common key files.
	home, _ := os.UserHomeDir()
	keyFiles := []string{
		home + "/.ssh/id_ed25519",
		home + "/.ssh/id_rsa",
		home + "/.ssh/id_ecdsa",
	}
	for _, kf := range keyFiles {
		data, err := os.ReadFile(kf)
		if err != nil {
			continue
		}
		signer, err := ssh.ParsePrivateKey(data)
		if err != nil {
			continue
		}
		signers = append(signers, signer)
	}

	return signers
}

// getAgentSigners reads signers from an SSH agent connection.
func getAgentSigners(conn net.Conn) []ssh.Signer {
	ag := sshagent.NewClient(conn)
	signers, err := ag.Signers()
	if err != nil {
		conn.Close()
		return nil
	}
	// Note: we intentionally do NOT close conn here -- the signers
	// need the connection to remain open for signing operations.
	return signers
}

// generateSudoers creates the /etc/sudoers.d/ephyr file content from resolved roles.
func generateSudoers(roles []*policy.ResolvedRole) string {
	var b strings.Builder

	b.WriteString("# Ephyr role-based sudoers rules\n")
	b.WriteString("# Managed by ephyr target provision -- do not edit manually.\n")
	b.WriteString("# This file is made immutable (chattr +i) after provisioning.\n")
	b.WriteString("\n")

	// Deny list (same as provision-target.sh).
	b.WriteString("# ── Explicit DENY list (all roles) ──────────────────────────────────────\n")
	b.WriteString("# These commands are NEVER allowed via sudo, regardless of role.\n")
	b.WriteString("\n")
	b.WriteString("Cmnd_Alias EPHYR_DENY_SHELLS = /bin/bash, /bin/sh, /bin/zsh, /usr/bin/zsh, \\\n")
	b.WriteString("    /usr/bin/fish, /bin/fish\n")
	b.WriteString("\n")
	b.WriteString("Cmnd_Alias EPHYR_DENY_EDITORS = /usr/bin/vi, /usr/bin/vim, /usr/bin/nano, \\\n")
	b.WriteString("    /usr/bin/emacs, /bin/vi, /bin/nano\n")
	b.WriteString("\n")
	b.WriteString("Cmnd_Alias EPHYR_DENY_INTERPRETERS = /usr/bin/python*, /usr/bin/perl, \\\n")
	b.WriteString("    /usr/bin/ruby, /usr/bin/node, /usr/local/bin/python*, /usr/local/bin/node\n")
	b.WriteString("\n")
	b.WriteString("Cmnd_Alias EPHYR_DENY_PKGMGR = /usr/bin/apt install *, /usr/bin/apt remove *, \\\n")
	b.WriteString("    /usr/bin/apt purge *, /usr/bin/dpkg -i *, /usr/bin/dpkg --install *, \\\n")
	b.WriteString("    /usr/bin/dpkg -r *, /usr/bin/dpkg --remove *, /usr/bin/dpkg -P *, \\\n")
	b.WriteString("    /usr/bin/dpkg --purge *\n")
	b.WriteString("\n")
	b.WriteString("Cmnd_Alias EPHYR_DENY_DANGEROUS = /usr/bin/chattr, /usr/sbin/visudo, \\\n")
	b.WriteString("    /bin/su, /usr/bin/su, /usr/bin/passwd, /usr/sbin/usermod, \\\n")
	b.WriteString("    /usr/sbin/userdel, /bin/chmod, /usr/bin/chmod, /bin/chown, /usr/bin/chown\n")
	b.WriteString("\n")

	// Deny rules for each principal.
	denyRule := "ALL = !EPHYR_DENY_SHELLS, !EPHYR_DENY_EDITORS, !EPHYR_DENY_INTERPRETERS, !EPHYR_DENY_PKGMGR, !EPHYR_DENY_DANGEROUS"
	for _, r := range roles {
		fmt.Fprintf(&b, "%s %s\n", r.Principal, denyRule)
	}
	b.WriteString("\n")

	// Per-role sudo grants.
	for _, r := range roles {
		if len(r.SudoRules) == 0 {
			fmt.Fprintf(&b, "# ── %s: NO sudo access ──\n", r.Principal)
			fmt.Fprintf(&b, "# (deny rules above are the only rules for %s)\n\n", r.Principal)
			continue
		}

		if len(r.SudoRules) == 1 && r.SudoRules[0] == "ALL" {
			fmt.Fprintf(&b, "# ── %s: full sudo (ALL) ──\n", r.Principal)
			fmt.Fprintf(&b, "%s ALL = (ALL) NOPASSWD: ALL\n\n", r.Principal)
			continue
		}

		// Specific sudo rules.
		fmt.Fprintf(&b, "# ── %s: specific sudo rules ──\n", r.Principal)
		cmds := strings.Join(r.SudoRules, ", ")
		fmt.Fprintf(&b, "%s ALL = (ALL) NOPASSWD: %s\n\n", r.Principal, cmds)
	}

	return b.String()
}

// printDryRun shows the commands that would be executed without connecting.
func printDryRun(caPubKey string, roles []*policy.ResolvedRole) {
	pStep("Step 1: Install CA public key")
	pDry(fmt.Sprintf("echo %q > /etc/ssh/ephyr_ca.pub", caPubKey))
	pDry("chmod 644 /etc/ssh/ephyr_ca.pub")
	pDry("chown root:root /etc/ssh/ephyr_ca.pub")

	pStep("Step 2: Configure sshd")
	pDry("Backup sshd_config if not already backed up")
	pDry(`grep -q "TrustedUserCAKeys.../etc/ssh/ephyr_ca.pub" /etc/ssh/sshd_config || append`)
	pDry(`grep -q "AuthorizedPrincipalsFile.../etc/ssh/auth_principals" /etc/ssh/sshd_config || append`)

	pStep("Step 3: Ensure sudo")
	pDry("command -v sudo || install via apt-get/yum/apk")
	pDry("mkdir -p /etc/sudoers.d")

	needsRbash := false
	for _, r := range roles {
		if strings.Contains(r.Shell, "rbash") {
			needsRbash = true
			break
		}
	}
	if needsRbash {
		pStep("Step 4: Ensure rbash")
		pDry("[ -x /usr/bin/rbash ] || [ -x /bin/rbash ] || ln -sf /bin/bash /usr/bin/rbash")
	}

	pStep("Step 5: Create role accounts")
	pDry("mkdir -p /etc/ssh/auth_principals")
	for _, r := range roles {
		systemFlag := ""
		if r.System {
			systemFlag = " --system"
		}
		pDry(fmt.Sprintf("useradd%s --create-home --shell %s %s", systemFlag, r.Shell, r.Principal))
		pDry(fmt.Sprintf("echo %q > /etc/ssh/auth_principals/%s", r.Principal, r.Principal))
	}

	pStep("Step 6: Install sudoers")
	sudoers := generateSudoers(roles)
	for _, line := range strings.Split(sudoers, "\n") {
		if line != "" {
			pDry(line)
		}
	}
	pDry("visudo -c -f /etc/sudoers.d/ephyr")
	pDry("chattr +i /etc/sudoers.d/ephyr")

	pStep("Step 7: Validate and reload sshd")
	pDry("sshd -t")
	pDry("systemctl reload sshd")

	fmt.Printf("\n%s  ── DRY RUN complete (no changes made) ──%s\n\n", pDim, pReset)
}
