package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"
	"syscall"
	"time"

	"github.com/EphyrAI/Ephyr/internal/policy"
	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

// verifyCheck is one sub-check within a role verification.
type verifyCheck struct {
	Label   string
	Pass    bool
	Warning bool
	Detail  string
}

// cmdTarget handles: ephyr target <subcommand>
func cmdTarget(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "Usage: ephyr target <command>")
		fmt.Fprintln(os.Stderr, "  provision <target-name>  Provision target for Ephyr SSH certificate access")
		fmt.Fprintln(os.Stderr, "  verify <target-name>     Verify target connectivity and role accounts")
		os.Exit(1)
	}
	switch args[0] {
	case "provision":
		cmdTargetProvision(args[1:])
	case "verify":
		cmdTargetVerify(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "ephyr target: unknown command %q\n", args[0])
		os.Exit(1)
	}
}

// cmdTargetVerify handles: ephyr target verify <target-name> [flags]
//
// Supports both:
//
//	ephyr target verify <target-name> --flag ...
//	ephyr target verify --flag ... <target-name>
func cmdTargetVerify(args []string) {
	// Extract the target name (first non-flag argument) and reorder
	// args so that all flags precede the positional argument. This
	// allows users to place the target name before or after the flags.
	var targetName string
	var flagArgs []string
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if strings.HasPrefix(arg, "-") {
			flagArgs = append(flagArgs, arg)
			// If this is a flag that takes a value (not --ssh-password which is bool),
			// consume the next argument as the value.
			if i+1 < len(args) && !strings.Contains(arg, "=") && arg != "--ssh-password" {
				i++
				flagArgs = append(flagArgs, args[i])
			}
		} else if targetName == "" {
			targetName = arg
		}
	}

	fs := flag.NewFlagSet("target-verify", flag.ExitOnError)
	policyPath := fs.String("policy", "/etc/ephyr/policy.yaml", "Policy file")
	role := fs.String("role", "", "Test specific role (default: all)")
	brokerURL := fs.String("broker", "", "Broker MCP URL")
	apiKey := fs.String("key", "", "Broker API key")
	sshUser := fs.String("ssh-user", "", "Direct SSH user (bypass broker)")
	sshPassword := fs.Bool("ssh-password", false, "Prompt for SSH password")
	_ = fs.Parse(flagArgs)

	if targetName == "" {
		fmt.Fprintln(os.Stderr, "error: target name is required")
		fmt.Fprintln(os.Stderr, "Usage: ephyr target verify <target-name> [flags]")
		os.Exit(1)
	}

	// Load and parse policy.
	_, rc, err := policy.LoadFromFile(*policyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	targetCfg, ok := rc.Raw.Targets[targetName]
	if !ok {
		fmt.Fprintf(os.Stderr, "error: target %q not found in policy\n", targetName)
		fmt.Fprintln(os.Stderr, "Available targets:")
		for name := range rc.Raw.Targets {
			fmt.Fprintf(os.Stderr, "  %s\n", name)
		}
		os.Exit(1)
	}

	// Determine which roles to test.
	rolesToTest := targetCfg.AllowedRoles
	if *role != "" {
		// Verify the requested role is allowed on this target.
		found := false
		for _, r := range targetCfg.AllowedRoles {
			if r == *role {
				found = true
				break
			}
		}
		if !found {
			fmt.Fprintf(os.Stderr, "error: role %q is not allowed on target %q\n", *role, targetName)
			fmt.Fprintf(os.Stderr, "Allowed roles: %s\n", strings.Join(targetCfg.AllowedRoles, ", "))
			os.Exit(1)
		}
		rolesToTest = []string{*role}
	}

	// Resolve principals for each role.
	var roles []roleInfo
	for _, rName := range rolesToTest {
		resolved, ok := rc.ResolvedRoles[rName]
		if !ok {
			fmt.Fprintf(os.Stderr, "error: role %q not found in policy\n", rName)
			os.Exit(1)
		}
		roles = append(roles, roleInfo{
			Name:      rName,
			Principal: resolved.Principal,
			Shell:     resolved.Shell,
			SudoRules: resolved.SudoRules,
		})
	}

	// Choose mode.
	port := targetCfg.Port
	if port == 0 {
		port = 22
	}
	addr := fmt.Sprintf("%s:%d", targetCfg.Host, port)

	if *sshUser != "" {
		// Mode 2: Direct SSH.
		var password string
		if *sshPassword {
			password = promptPassword("SSH password: ")
		}
		verifyDirect(targetName, addr, *sshUser, password, roles)
	} else {
		// Mode 1: Via broker.
		broker := *brokerURL
		if broker == "" {
			broker = "http://localhost:8554"
		}
		verifyViaBroker(targetName, addr, broker, *apiKey, roles)
	}
}

// promptPassword securely reads a password from the terminal.
func promptPassword(prompt string) string {
	fmt.Fprint(os.Stderr, prompt)
	pw, err := term.ReadPassword(syscall.Stdin)
	fmt.Fprintln(os.Stderr) // newline after password entry
	if err != nil {
		fmt.Fprintf(os.Stderr, "error reading password: %v\n", err)
		os.Exit(1)
	}
	return string(pw)
}

// verifyViaBroker tests the full chain: broker -> signer -> cert -> SSH -> target.
func verifyViaBroker(targetName, addr, brokerURL, apiKey string, roles []roleInfo) {
	// ANSI color codes.
	const (
		reset  = "\033[0m"
		bold   = "\033[1m"
		red    = "\033[31m"
		green  = "\033[32m"
		yellow = "\033[33m"
		dim    = "\033[2m"
	)

	fmt.Printf("\n%s=== Target Verification: %s (%s) ===%s\n\n", bold, targetName, addr, reset)

	passed := 0
	failed := 0

	for _, r := range roles {
		start := time.Now()

		// Build MCP JSON-RPC request to call the exec tool.
		type mcpParams struct {
			Name      string          `json:"name"`
			Arguments json.RawMessage `json:"arguments"`
		}
		type mcpRequest struct {
			JSONRPC string    `json:"jsonrpc"`
			ID      int       `json:"id"`
			Method  string    `json:"method"`
			Params  mcpParams `json:"params"`
		}

		execArgs, _ := json.Marshal(map[string]string{
			"target":  targetName,
			"role":    r.Name,
			"command": "whoami",
		})

		reqBody := mcpRequest{
			JSONRPC: "2.0",
			ID:      1,
			Method:  "tools/call",
			Params: mcpParams{
				Name:      "exec",
				Arguments: execArgs,
			},
		}

		body, err := json.Marshal(reqBody)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  %-12s %s[FAIL]%s marshal error: %v\n", r.Name+":", red, reset, err)
			failed++
			continue
		}

		req, err := http.NewRequest("POST", brokerURL+"/mcp", strings.NewReader(string(body)))
		if err != nil {
			fmt.Fprintf(os.Stderr, "  %-12s %s[FAIL]%s request error: %v\n", r.Name+":", red, reset, err)
			failed++
			continue
		}
		if apiKey != "" {
			req.Header.Set("Authorization", "Bearer "+apiKey)
		}
		req.Header.Set("Content-Type", "application/json")

		client := &http.Client{Timeout: 30 * time.Second}
		resp, err := client.Do(req)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  %-12s %s[FAIL]%s HTTP error: %v\n", r.Name+":", red, reset, err)
			failed++
			continue
		}
		defer resp.Body.Close()

		// Parse JSON-RPC response.
		var mcpResp struct {
			Result struct {
				Content []struct {
					Type string `json:"type"`
					Text string `json:"text"`
				} `json:"content"`
				IsError bool `json:"isError"`
			} `json:"result"`
			Error *struct {
				Code    int    `json:"code"`
				Message string `json:"message"`
			} `json:"error"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&mcpResp); err != nil {
			fmt.Fprintf(os.Stderr, "  %-12s %s[FAIL]%s decode error: %v\n", r.Name+":", red, reset, err)
			failed++
			continue
		}

		elapsed := time.Since(start)

		if mcpResp.Error != nil {
			fmt.Printf("  %-12s %s[FAIL]%s RPC error: %s %s(%dms)%s\n",
				r.Name+":", red, reset, mcpResp.Error.Message, dim, elapsed.Milliseconds(), reset)
			failed++
			continue
		}

		if mcpResp.Result.IsError {
			detail := ""
			if len(mcpResp.Result.Content) > 0 {
				detail = mcpResp.Result.Content[0].Text
			}
			fmt.Printf("  %-12s %s[FAIL]%s exec error: %s %s(%dms)%s\n",
				r.Name+":", red, reset, detail, dim, elapsed.Milliseconds(), reset)
			failed++
			continue
		}

		// Extract stdout from the exec result. The text content is a JSON-encoded ExecResult.
		if len(mcpResp.Result.Content) == 0 {
			fmt.Printf("  %-12s %s[FAIL]%s empty response %s(%dms)%s\n",
				r.Name+":", red, reset, dim, elapsed.Milliseconds(), reset)
			failed++
			continue
		}

		var execResult struct {
			Stdout   string `json:"stdout"`
			ExitCode int    `json:"exit_code"`
		}
		if err := json.Unmarshal([]byte(mcpResp.Result.Content[0].Text), &execResult); err != nil {
			// Fall back to treating the text as raw stdout.
			execResult.Stdout = mcpResp.Result.Content[0].Text
		}

		stdout := strings.TrimSpace(execResult.Stdout)

		if stdout == r.Principal {
			fmt.Printf("  %-12s %s[PASS]%s whoami=%s %s(%dms)%s\n",
				r.Name+":", green, reset, stdout, dim, elapsed.Milliseconds(), reset)
			passed++
		} else {
			fmt.Printf("  %-12s %s[FAIL]%s whoami=%q expected=%q %s(%dms)%s\n",
				r.Name+":", red, reset, stdout, r.Principal, dim, elapsed.Milliseconds(), reset)
			failed++
		}
	}

	fmt.Println()
	total := passed + failed
	if failed == 0 {
		fmt.Printf("  %sResult: %d/%d passed%s\n\n", green, passed, total, reset)
	} else {
		fmt.Printf("  %sResult: %d/%d passed%s\n\n", red, passed, total, reset)
	}

	if failed > 0 {
		os.Exit(1)
	}
}

// roleInfo is used in both verifyViaBroker and verifyDirect.
type roleInfo struct {
	Name      string
	Principal string
	Shell     string
	SudoRules []string
}

// verifyDirect tests role accounts directly via SSH password auth.
func verifyDirect(targetName, addr, sshUser, password string, roles []roleInfo) {
	// ANSI color codes.
	const (
		reset  = "\033[0m"
		bold   = "\033[1m"
		red    = "\033[31m"
		green  = "\033[32m"
		yellow = "\033[33m"
		dim    = "\033[2m"
	)

	fmt.Printf("\n%s=== Target Verification: %s (%s) [direct SSH] ===%s\n", bold, targetName, addr, reset)

	// Build SSH client config with password auth.
	var authMethods []ssh.AuthMethod
	if password != "" {
		authMethods = append(authMethods, ssh.Password(password))
	}
	// Also try keyboard-interactive for password prompts.
	if password != "" {
		authMethods = append(authMethods, ssh.KeyboardInteractive(
			func(user, instruction string, questions []string, echos []bool) ([]string, error) {
				answers := make([]string, len(questions))
				for i := range questions {
					answers[i] = password
				}
				return answers, nil
			},
		))
	}

	config := &ssh.ClientConfig{
		User:            sshUser,
		Auth:            authMethods,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	}

	client, err := ssh.Dial("tcp", addr, config)
	if err != nil {
		fmt.Fprintf(os.Stderr, "\n  %s[FAIL]%s Cannot connect to %s as %s: %v\n\n", red, reset, addr, sshUser, err)
		os.Exit(1)
	}
	defer client.Close()

	fmt.Printf("  %sConnected as %s%s\n", dim, sshUser, reset)

	passed := 0
	failed := 0
	warnings := 0

	for _, r := range roles {
		fmt.Printf("\n  %s:%s\n", r.Name, reset)

		checks := verifyRoleDirect(client, r)
		for _, c := range checks {
			if c.Warning {
				fmt.Printf("    %s[WARN]%s %s: %s\n", yellow, reset, c.Label, c.Detail)
				warnings++
			} else if c.Pass {
				fmt.Printf("    %s[PASS]%s %s: %s\n", green, reset, c.Label, c.Detail)
			} else {
				fmt.Printf("    %s[FAIL]%s %s: %s\n", red, reset, c.Label, c.Detail)
			}
		}

		// A role passes if no check failed (warnings are OK).
		roleFailed := false
		for _, c := range checks {
			if !c.Pass && !c.Warning {
				roleFailed = true
				break
			}
		}
		if roleFailed {
			failed++
		} else {
			passed++
		}
	}

	fmt.Println()
	total := passed + failed
	warnStr := ""
	if warnings > 0 {
		warnStr = fmt.Sprintf(" (%d warning", warnings)
		if warnings > 1 {
			warnStr += "s"
		}
		warnStr += ")"
	}

	if failed == 0 {
		fmt.Printf("  %sResult: %d/%d passed%s%s\n\n", green, passed, total, warnStr, reset)
	} else {
		fmt.Printf("  %sResult: %d/%d passed%s%s\n\n", red, passed, total, warnStr, reset)
	}

	if failed > 0 {
		os.Exit(1)
	}
}

// verifyRoleDirect runs sub-checks for a single role via direct SSH.
func verifyRoleDirect(client *ssh.Client, r roleInfo) []verifyCheck {
	var checks []verifyCheck

	// Check 1: User exists (su - <principal> -c whoami).
	whoamiOut, err := sshRun(client, fmt.Sprintf("su - %s -c whoami 2>/dev/null", r.Principal))
	whoami := strings.TrimSpace(whoamiOut)
	if err != nil || whoami != r.Principal {
		checks = append(checks, verifyCheck{
			Label:  "User exists",
			Pass:   false,
			Detail: fmt.Sprintf("user %s not found or su failed", r.Principal),
		})
		// If the user doesn't exist, skip remaining checks.
		return checks
	}
	checks = append(checks, verifyCheck{
		Label:  "User exists",
		Pass:   true,
		Detail: fmt.Sprintf("User %s exists", r.Principal),
	})

	// Check 2: Shell matches expected.
	shellOut, err := sshRun(client, fmt.Sprintf("getent passwd %s | cut -d: -f7", r.Principal))
	shell := strings.TrimSpace(shellOut)
	if err != nil || shell == "" {
		checks = append(checks, verifyCheck{
			Label:   "Shell",
			Warning: true,
			Detail:  "cannot determine shell",
		})
	} else {
		if shell == r.Shell {
			checks = append(checks, verifyCheck{
				Label:  "Shell",
				Pass:   true,
				Detail: shell,
			})
		} else {
			checks = append(checks, verifyCheck{
				Label:  "Shell",
				Pass:   false,
				Detail: fmt.Sprintf("got %s, expected %s", shell, r.Shell),
			})
		}
	}

	// Check 3: Principal file exists.
	principalFile := fmt.Sprintf("/etc/ssh/auth_principals/%s", r.Principal)
	pfOut, err := sshRun(client, fmt.Sprintf("test -f %s && echo exists || echo missing", principalFile))
	pf := strings.TrimSpace(pfOut)
	if err != nil || pf != "exists" {
		checks = append(checks, verifyCheck{
			Label:  "Principal file",
			Pass:   false,
			Detail: fmt.Sprintf("%s missing", principalFile),
		})
	} else {
		checks = append(checks, verifyCheck{
			Label:  "Principal file",
			Pass:   true,
			Detail: principalFile,
		})
	}

	// Check 4: Sudo rules.
	sudoOut, err := sshRun(client, fmt.Sprintf("sudo -l -U %s 2>/dev/null", r.Principal))
	if err != nil {
		// sudo may not be installed.
		checks = append(checks, verifyCheck{
			Label:   "Sudo",
			Warning: true,
			Detail:  "cannot check (no sudo installed or permission denied)",
		})
	} else {
		sudoOut = strings.TrimSpace(sudoOut)
		if len(r.SudoRules) == 0 {
			// Expect no sudo access.
			if strings.Contains(sudoOut, "is not allowed to run sudo") ||
				strings.Contains(sudoOut, "not allowed") ||
				!strings.Contains(sudoOut, "may run") {
				checks = append(checks, verifyCheck{
					Label:  "Sudo",
					Pass:   true,
					Detail: "no sudo (as expected)",
				})
			} else {
				checks = append(checks, verifyCheck{
					Label:   "Sudo",
					Warning: true,
					Detail:  "unexpected sudo access detected",
				})
			}
		} else {
			// Expect some sudo access -- count rules.
			ruleCount := 0
			scanner := bufio.NewScanner(strings.NewReader(sudoOut))
			for scanner.Scan() {
				line := strings.TrimSpace(scanner.Text())
				if strings.HasPrefix(line, "(") || strings.Contains(line, "NOPASSWD") ||
					strings.Contains(line, "ALL") {
					ruleCount++
				}
			}
			if ruleCount > 0 {
				checks = append(checks, verifyCheck{
					Label:  "Sudo",
					Pass:   true,
					Detail: fmt.Sprintf("%d rules configured", ruleCount),
				})
			} else if strings.Contains(sudoOut, "may run") {
				checks = append(checks, verifyCheck{
					Label:  "Sudo",
					Pass:   true,
					Detail: "sudo access configured",
				})
			} else {
				checks = append(checks, verifyCheck{
					Label:  "Sudo",
					Pass:   false,
					Detail: "expected sudo rules but none found",
				})
			}
		}
	}

	return checks
}

// sshRun executes a single command on an SSH client and returns stdout.
func sshRun(client *ssh.Client, command string) (string, error) {
	session, err := client.NewSession()
	if err != nil {
		return "", err
	}
	defer session.Close()

	// Combine stdout and stderr capture.
	var stdout strings.Builder
	session.Stdout = &stdout

	timer := time.NewTimer(10 * time.Second)
	defer timer.Stop()

	type result struct {
		err error
	}
	done := make(chan result, 1)
	go func() {
		done <- result{err: session.Run(command)}
	}()

	select {
	case res := <-done:
		return stdout.String(), res.err
	case <-timer.C:
		session.Close()
		return stdout.String(), fmt.Errorf("command timed out after 10s")
	}
}

