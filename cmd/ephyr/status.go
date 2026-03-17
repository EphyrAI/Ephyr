package main

import (
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"
)

// serviceCheck holds the result of a single health check.
type serviceCheck struct {
	name    string
	ok      bool
	status  string
	detail  string
}

// cmdHealthStatus implements: ephyr status [--restart]
//
// Checks health of all Ephyr components:
//   - ephyr-signer systemd service + /run/ephyr/signer.sock
//   - ephyr-broker systemd service + /run/ephyr/broker.sock
//   - MCP endpoint (localhost:8554/mcp)
//   - Dashboard (localhost:8553)
func cmdHealthStatus(args []string) {
	fs := flag.NewFlagSet("status", flag.ExitOnError)
	restart := fs.Bool("restart", false, "Restart unhealthy services (signer first, then broker)")
	_ = fs.Parse(args)

	fmt.Println("=== Ephyr Status ===")

	if *restart {
		runRestart()
		return
	}

	checks := runChecks()
	printChecks(checks)

	// Determine overall status.
	var failures []string
	for _, c := range checks {
		if !c.ok {
			failures = append(failures, c.name)
		}
	}

	if len(failures) == 0 {
		fmt.Println("  Status:     ALL OK")
	} else {
		fmt.Printf("  Status:     UNHEALTHY (%s down)\n", strings.Join(failures, ", "))
		os.Exit(1)
	}
}

// runChecks performs all health checks and returns results.
func runChecks() []serviceCheck {
	return []serviceCheck{
		checkSystemdService("Signer", "ephyr-signer", "/run/ephyr/signer.sock"),
		checkSystemdService("Broker", "ephyr-broker", "/run/ephyr/broker.sock"),
		checkHTTPEndpoint("MCP", "http://localhost:8554/mcp"),
		checkHTTPEndpoint("Dashboard", "http://localhost:8553"),
	}
}

// printChecks prints all check results.
func printChecks(checks []serviceCheck) {
	for _, c := range checks {
		pad := strings.Repeat(" ", 12-len(c.name))
		fmt.Printf("  %s:%s%-10s %s\n", c.name, pad, c.status, c.detail)
	}
}

// checkSystemdService checks if a systemd unit is active and its socket exists.
func checkSystemdService(label, unit, socketPath string) serviceCheck {
	check := serviceCheck{name: label}

	// Check systemd service status.
	cmd := exec.Command("systemctl", "is-active", unit)
	out, err := cmd.Output()
	svcStatus := strings.TrimSpace(string(out))
	if err != nil || svcStatus != "active" {
		if svcStatus == "" {
			svcStatus = "inactive"
		}
		check.status = svcStatus
		check.detail = socketPath + " (service not active)"
		check.ok = false
		return check
	}

	check.status = "active"

	// Check socket file exists.
	if _, err := os.Stat(socketPath); err != nil {
		check.detail = socketPath + " MISSING"
		check.ok = false
		return check
	}

	check.detail = socketPath + " exists"
	check.ok = true
	return check
}

// checkHTTPEndpoint checks if an HTTP endpoint responds.
func checkHTTPEndpoint(label, url string) serviceCheck {
	check := serviceCheck{name: label}

	client := &http.Client{
		Timeout: 3 * time.Second,
		Transport: &http.Transport{
			DialContext: (&net.Dialer{
				Timeout: 2 * time.Second,
			}).DialContext,
		},
	}

	resp, err := client.Get(url)
	if err != nil {
		check.status = "down"
		check.detail = url + " not responding"
		check.ok = false
		return check
	}
	resp.Body.Close()

	check.status = "healthy"
	check.detail = url + " responds"
	check.ok = true
	return check
}

// runRestart restarts services in the correct order (signer first, then broker).
func runRestart() {
	// Check and restart signer.
	signerCheck := checkSystemdService("Signer", "ephyr-signer", "/run/ephyr/signer.sock")
	if !signerCheck.ok {
		fmt.Printf("  Signer:     %-10s restarting...\n", signerCheck.status)
		if err := restartService("ephyr-signer"); err != nil {
			fmt.Printf("  Signer:     %-10s FAILED: %v\n", "error", err)
			os.Exit(1)
		}
		// Re-check after restart.
		time.Sleep(500 * time.Millisecond)
		signerCheck = checkSystemdService("Signer", "ephyr-signer", "/run/ephyr/signer.sock")
		if signerCheck.ok {
			fmt.Printf("  Signer:     %-10s OK\n", "active")
		} else {
			fmt.Printf("  Signer:     %-10s FAILED to recover\n", signerCheck.status)
			os.Exit(1)
		}
	} else {
		fmt.Printf("  Signer:     %-10s %s\n", signerCheck.status, signerCheck.detail)
	}

	// Check and restart broker.
	brokerCheck := checkSystemdService("Broker", "ephyr-broker", "/run/ephyr/broker.sock")
	if !brokerCheck.ok {
		fmt.Printf("  Broker:     %-10s restarting... (waiting 1s for signer)\n", brokerCheck.status)
		time.Sleep(1 * time.Second)
		if err := restartService("ephyr-broker"); err != nil {
			fmt.Printf("  Broker:     %-10s FAILED: %v\n", "error", err)
			os.Exit(1)
		}
		// Re-check after restart.
		time.Sleep(1 * time.Second)
		brokerCheck = checkSystemdService("Broker", "ephyr-broker", "/run/ephyr/broker.sock")
		if brokerCheck.ok {
			fmt.Printf("  Broker:     %-10s OK\n", "active")
		} else {
			fmt.Printf("  Broker:     %-10s FAILED to recover\n", brokerCheck.status)
			os.Exit(1)
		}
	} else {
		fmt.Printf("  Broker:     %-10s %s\n", brokerCheck.status, brokerCheck.detail)
	}

	// Final endpoint checks.
	time.Sleep(500 * time.Millisecond)
	mcpCheck := checkHTTPEndpoint("MCP", "http://localhost:8554/mcp")
	dashCheck := checkHTTPEndpoint("Dashboard", "http://localhost:8553")

	fmt.Printf("  MCP:        %-10s %s\n", mcpCheck.status, mcpCheck.detail)
	fmt.Printf("  Dashboard:  %-10s %s\n", dashCheck.status, dashCheck.detail)

	allOK := signerCheck.ok && brokerCheck.ok && mcpCheck.ok && dashCheck.ok
	if allOK {
		fmt.Println("  Status:     RECOVERED")
	} else {
		var failures []string
		if !mcpCheck.ok {
			failures = append(failures, "MCP")
		}
		if !dashCheck.ok {
			failures = append(failures, "Dashboard")
		}
		fmt.Printf("  Status:     PARTIAL (%s still down)\n", strings.Join(failures, ", "))
		os.Exit(1)
	}
}

// restartService restarts a systemd service.
func restartService(unit string) error {
	cmd := exec.Command("systemctl", "restart", unit)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}
