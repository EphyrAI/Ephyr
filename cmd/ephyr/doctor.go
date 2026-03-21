package main

import (
	"crypto/ed25519"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/EphyrAI/Ephyr/internal/audit"
	"github.com/EphyrAI/Ephyr/internal/policy"
	"golang.org/x/crypto/ssh"
	"gopkg.in/yaml.v3"
)

// CheckResult holds the result of a single doctor check.
type CheckResult struct {
	Category string `json:"category"`
	Name     string `json:"name"`
	Status   string `json:"status"` // "ok", "warn", "fail"
	Message  string `json:"message"`
}

// doctorReport is the JSON output format for ephyr doctor --json.
type doctorReport struct {
	Version  string        `json:"version"`
	Checks   []CheckResult `json:"checks"`
	Failures int           `json:"failures"`
	Warnings int           `json:"warnings"`
}

// cmdDoctor implements: ephyr doctor [--policy PATH] [--json]
//
// Performs a comprehensive health check of the Ephyr installation,
// covering infrastructure, policy, target reachability, and storage.
func cmdDoctor(args []string) {
	fs := flag.NewFlagSet("doctor", flag.ExitOnError)
	policyPath := fs.String("policy", "/etc/ephyr/policy.yaml", "Policy file")
	jsonOutput := fs.Bool("json", false, "JSON output")
	_ = fs.Parse(args)

	var checks []CheckResult

	// Infrastructure checks.
	checks = append(checks, checkCAKey()...)
	checks = append(checks, checkServices()...)
	checks = append(checks, checkEndpoints()...)

	// Policy checks.
	checks = append(checks, checkPolicy(*policyPath)...)

	// Target reachability.
	checks = append(checks, checkTargets(*policyPath)...)

	// Storage checks.
	checks = append(checks, checkStorage()...)

	// Audit chain integrity.
	checks = append(checks, checkAuditChain()...)

	// System checks.
	checks = append(checks, checkVersion())

	// Print results.
	printDoctorResults(checks, *jsonOutput)
}

// checkCAKey verifies the CA private key and public key files.
func checkCAKey() []CheckResult {
	var results []CheckResult
	caKeyPath := "/etc/ephyr/ca_key"

	// Check CA private key exists.
	info, err := os.Stat(caKeyPath)
	if err != nil {
		results = append(results, CheckResult{
			Category: "Infrastructure",
			Name:     "CA key",
			Status:   "fail",
			Message:  fmt.Sprintf("%s: not found", caKeyPath),
		})
		// If key doesn't exist, skip pub key check too.
		results = append(results, CheckResult{
			Category: "Infrastructure",
			Name:     "CA public key",
			Status:   "fail",
			Message:  fmt.Sprintf("%s.pub: skipped (no private key)", caKeyPath),
		})
		return results
	}

	// Check permissions.
	perm := info.Mode().Perm()
	if perm != 0600 {
		results = append(results, CheckResult{
			Category: "Infrastructure",
			Name:     "CA key",
			Status:   "warn",
			Message:  fmt.Sprintf("%s: permissions %04o (expected 0600)", caKeyPath, perm),
		})
	} else {
		// Verify it's a valid Ed25519 key.
		keyData, err := os.ReadFile(caKeyPath)
		if err != nil {
			results = append(results, CheckResult{
				Category: "Infrastructure",
				Name:     "CA key",
				Status:   "fail",
				Message:  fmt.Sprintf("%s: unreadable: %v", caKeyPath, err),
			})
		} else {
			rawKey, err := ssh.ParseRawPrivateKey(keyData)
			if err != nil {
				results = append(results, CheckResult{
					Category: "Infrastructure",
					Name:     "CA key",
					Status:   "fail",
					Message:  fmt.Sprintf("%s: invalid key: %v", caKeyPath, err),
				})
			} else {
				// Check it's Ed25519.
				switch rawKey.(type) {
				case *ed25519.PrivateKey:
					results = append(results, CheckResult{
						Category: "Infrastructure",
						Name:     "CA key",
						Status:   "ok",
						Message:  fmt.Sprintf("%s (Ed25519, %04o)", caKeyPath, perm),
					})
				default:
					results = append(results, CheckResult{
						Category: "Infrastructure",
						Name:     "CA key",
						Status:   "warn",
						Message:  fmt.Sprintf("%s: not Ed25519 (type: %T)", caKeyPath, rawKey),
					})
				}
			}
		}
	}

	// Check CA public key.
	pubKeyPath := caKeyPath + ".pub"
	if _, err := os.Stat(pubKeyPath); err != nil {
		results = append(results, CheckResult{
			Category: "Infrastructure",
			Name:     "CA public key",
			Status:   "fail",
			Message:  fmt.Sprintf("%s: not found", pubKeyPath),
		})
	} else {
		results = append(results, CheckResult{
			Category: "Infrastructure",
			Name:     "CA public key",
			Status:   "ok",
			Message:  pubKeyPath,
		})
	}

	return results
}

// checkServices verifies signer and broker systemd services and sockets.
func checkServices() []CheckResult {
	var results []CheckResult

	// Signer.
	signerActive := isSystemdActive("ephyr-signer")
	_, signerSocketErr := os.Stat("/run/ephyr/signer.sock")
	if signerActive && signerSocketErr == nil {
		results = append(results, CheckResult{
			Category: "Infrastructure",
			Name:     "Signer",
			Status:   "ok",
			Message:  "active, socket exists",
		})
	} else {
		parts := []string{}
		if !signerActive {
			parts = append(parts, "service not active")
		}
		if signerSocketErr != nil {
			parts = append(parts, "socket missing")
		}
		results = append(results, CheckResult{
			Category: "Infrastructure",
			Name:     "Signer",
			Status:   "fail",
			Message:  strings.Join(parts, ", "),
		})
	}

	// Broker.
	brokerActive := isSystemdActive("ephyr-broker")
	_, brokerSocketErr := os.Stat("/run/ephyr/broker.sock")
	if brokerActive && brokerSocketErr == nil {
		results = append(results, CheckResult{
			Category: "Infrastructure",
			Name:     "Broker",
			Status:   "ok",
			Message:  "active, socket exists",
		})
	} else {
		parts := []string{}
		if !brokerActive {
			parts = append(parts, "service not active")
		}
		if brokerSocketErr != nil {
			parts = append(parts, "socket missing")
		}
		results = append(results, CheckResult{
			Category: "Infrastructure",
			Name:     "Broker",
			Status:   "fail",
			Message:  strings.Join(parts, ", "),
		})
	}

	return results
}

// isSystemdActive returns true if the given systemd unit is active.
func isSystemdActive(unit string) bool {
	cmd := exec.Command("systemctl", "is-active", unit)
	out, err := cmd.Output()
	return err == nil && strings.TrimSpace(string(out)) == "active"
}

// checkEndpoints verifies MCP and dashboard HTTP endpoints.
func checkEndpoints() []CheckResult {
	var results []CheckResult

	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			DialContext: (&net.Dialer{
				Timeout: 3 * time.Second,
			}).DialContext,
		},
	}

	// MCP endpoint.
	resp, err := client.Get("http://localhost:8554/mcp")
	if err != nil {
		results = append(results, CheckResult{
			Category: "Infrastructure",
			Name:     "MCP",
			Status:   "fail",
			Message:  "localhost:8554 not responding",
		})
	} else {
		resp.Body.Close()
		results = append(results, CheckResult{
			Category: "Infrastructure",
			Name:     "MCP",
			Status:   "ok",
			Message:  "localhost:8554 responds",
		})
	}

	// Dashboard endpoint.
	resp, err = client.Get("http://localhost:8553")
	if err != nil {
		results = append(results, CheckResult{
			Category: "Infrastructure",
			Name:     "Dashboard",
			Status:   "fail",
			Message:  "localhost:8553 not responding",
		})
	} else {
		resp.Body.Close()
		results = append(results, CheckResult{
			Category: "Infrastructure",
			Name:     "Dashboard",
			Status:   "ok",
			Message:  "localhost:8553 responds",
		})
	}

	return results
}

// checkPolicy loads and validates the policy file.
func checkPolicy(path string) []CheckResult {
	var results []CheckResult

	data, err := os.ReadFile(path)
	if err != nil {
		results = append(results, CheckResult{
			Category: "Policy",
			Name:     "Policy file",
			Status:   "fail",
			Message:  fmt.Sprintf("%s: %v", path, err),
		})
		return results
	}

	var cfg policy.Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		results = append(results, CheckResult{
			Category: "Policy",
			Name:     "Policy file",
			Status:   "fail",
			Message:  fmt.Sprintf("YAML parse error: %v", err),
		})
		return results
	}

	ApplyPolicyDefaults(&cfg)
	rpt := policy.ValidatePolicy(&cfg)

	// Count agents, targets, roles.
	agentCount := len(cfg.Agents)
	targetCount := len(cfg.Targets)
	roleCount := len(cfg.Roles)

	if rpt.Errors > 0 {
		results = append(results, CheckResult{
			Category: "Policy",
			Name:     "Validation",
			Status:   "fail",
			Message:  fmt.Sprintf("%d errors, %d warnings (%d agents, %d targets, %d roles)", rpt.Errors, rpt.Warnings, agentCount, targetCount, roleCount),
		})
	} else if rpt.Warnings > 0 {
		results = append(results, CheckResult{
			Category: "Policy",
			Name:     "Validation",
			Status:   "ok",
			Message:  fmt.Sprintf("valid: %d agents, %d targets, %d roles", agentCount, targetCount, roleCount),
		})
		results = append(results, CheckResult{
			Category: "Policy",
			Name:     "Warnings",
			Status:   "warn",
			Message:  fmt.Sprintf("%d warnings (run 'ephyr policy validate' for details)", rpt.Warnings),
		})
	} else {
		results = append(results, CheckResult{
			Category: "Policy",
			Name:     "Validation",
			Status:   "ok",
			Message:  fmt.Sprintf("valid: %d agents, %d targets, %d roles", agentCount, targetCount, roleCount),
		})
	}

	return results
}

// checkTargets tests TCP connectivity to each target in the policy.
func checkTargets(path string) []CheckResult {
	var results []CheckResult

	data, err := os.ReadFile(path)
	if err != nil {
		// Policy already reported as missing in checkPolicy; skip silently.
		return results
	}

	var cfg policy.Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return results
	}

	ApplyPolicyDefaults(&cfg)

	// Sort target names for deterministic output.
	names := make([]string, 0, len(cfg.Targets))
	for name := range cfg.Targets {
		names = append(names, name)
	}
	sortStrings(names)

	for _, name := range names {
		target := cfg.Targets[name]
		port := target.Port
		if port == 0 {
			port = 22
		}
		addr := fmt.Sprintf("%s:%d", target.Host, port)

		conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
		if err != nil {
			results = append(results, CheckResult{
				Category: "Targets",
				Name:     name,
				Status:   "fail",
				Message:  fmt.Sprintf("%s: unreachable", addr),
			})
		} else {
			conn.Close()
			results = append(results, CheckResult{
				Category: "Targets",
				Name:     name,
				Status:   "ok",
				Message:  fmt.Sprintf("%s: reachable", addr),
			})
		}
	}

	return results
}

// checkStorage verifies audit log and data directory.
func checkStorage() []CheckResult {
	var results []CheckResult

	// Audit log.
	auditPath := "/var/log/ephyr/audit.json"
	if info, err := os.Stat(auditPath); err != nil {
		if os.IsNotExist(err) {
			// Check if the directory at least exists and is writable.
			dir := "/var/log/ephyr"
			if _, dirErr := os.Stat(dir); dirErr != nil {
				results = append(results, CheckResult{
					Category: "Storage",
					Name:     "Audit log",
					Status:   "fail",
					Message:  fmt.Sprintf("%s: directory does not exist", dir),
				})
			} else {
				results = append(results, CheckResult{
					Category: "Storage",
					Name:     "Audit log",
					Status:   "warn",
					Message:  fmt.Sprintf("%s: file does not exist (directory exists)", auditPath),
				})
			}
		} else {
			results = append(results, CheckResult{
				Category: "Storage",
				Name:     "Audit log",
				Status:   "fail",
				Message:  fmt.Sprintf("%s: %v", auditPath, err),
			})
		}
	} else {
		// Check if writable by opening for append.
		f, err := os.OpenFile(auditPath, os.O_WRONLY|os.O_APPEND, info.Mode())
		if err != nil {
			results = append(results, CheckResult{
				Category: "Storage",
				Name:     "Audit log",
				Status:   "fail",
				Message:  fmt.Sprintf("%s: not writable", auditPath),
			})
		} else {
			f.Close()
			results = append(results, CheckResult{
				Category: "Storage",
				Name:     "Audit log",
				Status:   "ok",
				Message:  fmt.Sprintf("%s (writable)", auditPath),
			})
		}
	}

	// Data directory.
	dataDir := "/var/lib/ephyr/"
	if _, err := os.Stat(dataDir); err != nil {
		results = append(results, CheckResult{
			Category: "Storage",
			Name:     "Data dir",
			Status:   "fail",
			Message:  fmt.Sprintf("%s: does not exist", dataDir),
		})
	} else {
		results = append(results, CheckResult{
			Category: "Storage",
			Name:     "Data dir",
			Status:   "ok",
			Message:  fmt.Sprintf("%s (exists)", dataDir),
		})
	}

	return results
}

// checkVersion reports the ephyr binary version.
func checkVersion() CheckResult {
	return CheckResult{
		Category: "System",
		Name:     "Version",
		Status:   "ok",
		Message:  fmt.Sprintf("ephyr %s", version),
	}
}

// checkAuditChain verifies the hash chain integrity of the audit log.
func checkAuditChain() []CheckResult {
	var results []CheckResult
	auditPath := "/var/log/ephyr/audit.json"

	if _, err := os.Stat(auditPath); err != nil {
		// File doesn't exist -- already reported by checkStorage, skip.
		return results
	}

	count, err := audit.VerifyChain(auditPath)
	if err != nil {
		results = append(results, CheckResult{
			Category: "Integrity",
			Name:     "Audit chain",
			Status:   "fail",
			Message:  fmt.Sprintf("chain broken at entry %d: %v", count+1, err),
		})
	} else {
		results = append(results, CheckResult{
			Category: "Integrity",
			Name:     "Audit chain",
			Status:   "ok",
			Message:  fmt.Sprintf("%d entries verified (SHA-256 hash chain)", count),
		})
	}

	return results
}

// printDoctorResults renders all check results in either text or JSON format.
func printDoctorResults(checks []CheckResult, jsonOut bool) {
	failures := 0
	warnings := 0
	for _, c := range checks {
		switch c.Status {
		case "fail":
			failures++
		case "warn":
			warnings++
		}
	}

	if jsonOut {
		rpt := doctorReport{
			Version:  version,
			Checks:   checks,
			Failures: failures,
			Warnings: warnings,
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(rpt); err != nil {
			fmt.Fprintf(os.Stderr, "error: json encode: %v\n", err)
			os.Exit(2)
		}
		if failures > 0 {
			os.Exit(1)
		}
		return
	}

	// ANSI color codes.
	const (
		reset  = "\033[0m"
		bold   = "\033[1m"
		red    = "\033[31m"
		green  = "\033[32m"
		yellow = "\033[33m"
		cyan   = "\033[36m"
	)

	fmt.Printf("\n%s=== Ephyr Doctor ===%s\n", bold, reset)

	// Group checks by category, preserving first-seen order.
	type categoryGroup struct {
		name   string
		checks []CheckResult
	}
	seen := make(map[string]int)
	var groups []categoryGroup
	for _, c := range checks {
		idx, ok := seen[c.Category]
		if !ok {
			idx = len(groups)
			seen[c.Category] = idx
			groups = append(groups, categoryGroup{name: c.Category})
		}
		groups[idx].checks = append(groups[idx].checks, c)
	}

	for _, g := range groups {
		fmt.Printf("\n  %s%s%s\n", cyan, g.name, reset)

		for _, c := range g.checks {
			var tag string
			switch c.Status {
			case "ok":
				tag = fmt.Sprintf("%s[OK]%s  ", green, reset)
			case "warn":
				tag = fmt.Sprintf("%s[WARN]%s", yellow, reset)
			case "fail":
				tag = fmt.Sprintf("%s[FAIL]%s", red, reset)
			}
			fmt.Printf("    %s %s: %s\n", tag, c.Name, c.Message)
		}
	}

	// Summary.
	fmt.Println()
	summaryColor := green
	if failures > 0 {
		summaryColor = red
	} else if warnings > 0 {
		summaryColor = yellow
	}
	fmt.Printf("  %s%sSummary: %d failures, %d warnings%s\n\n", bold, summaryColor, failures, warnings, reset)

	if failures > 0 {
		os.Exit(1)
	}
}

// sortStrings sorts a string slice in place.
func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}
