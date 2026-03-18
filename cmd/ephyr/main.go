// Package main implements the unified ephyr binary.
//
// It combines the broker, signer, and CLI tools into a single binary
// with subcommands:
//
//	ephyr broker [flags]          Start the broker server
//	ephyr signer [flags]          Start the signer server
//	ephyr init [--dev]            Setup wizard
//	ephyr keygen [--force]        Generate Ed25519 agent keypair
//	ephyr inspect [--token TOKEN] Inspect macaroon token
//	ephyr monitor [--log path]    Live audit stream
//	ephyr demo [--broker URL]     Run pipeline demo
//	ephyr host-key [--host HOST]  Scan SSH host key
//	ephyr version                 Show version
package main

import (
	"fmt"
	"os"
)

// version is set at build time via -ldflags.
var version = "dev"

const usage = `ephyr — Ephyr SSH certificate broker and agent CLI

Usage:
  ephyr broker [flags]            Start the Ephyr broker server
  ephyr signer [flags]            Start the Ephyr signer server
  ephyr init [--dev] [--non-interactive]  Setup wizard (install Ephyr from scratch)
  ephyr keygen [--force]          Generate Ed25519 agent keypair
  ephyr request -t HOST -r ROLE   Request a certificate
  ephyr ssh -t HOST -r ROLE       Request cert + open SSH session
  ephyr exec -t HOST -r ROLE -- CMD  Request cert + run remote command
  ephyr status [--restart]        Health check (verify services, sockets, endpoints)
  ephyr certs                     List active certificates
  ephyr targets                   List available SSH targets
  ephyr services                  List HTTP proxy services
  ephyr remotes                   List federated MCP servers
  ephyr whoami                    Show agent identity
  ephyr host-key --host HOST[:PORT]  Scan and print SSH host key
  ephyr inspect [--token] [--json]   Inspect a macaroon token
  ephyr monitor [--log path] [--severity WARN,ALERT] [--agent name] [--type exec,denied]
                                  Live audit stream (default: /var/log/ephyr/audit.json)
  ephyr policy validate [--policy path] [--strict] [--json]
                                  Validate policy configuration
  ephyr demo [--broker URL] [--key KEY]  Run full pipeline demo (macaroon + PoP)
  ephyr version                   Show version

Global:
  --socket PATH    Broker socket (default: /run/ephyr/broker.sock)
  --config-dir DIR Config directory (default: ~/.ephyr)
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(1)
	}

	subcmd := os.Args[1]

	switch subcmd {
	case "broker":
		cmdBroker(os.Args[2:])
	case "signer":
		cmdSigner(os.Args[2:])
	case "init":
		cmdSetupInit(os.Args[2:])
	case "keygen":
		cmdKeygen(os.Args[2:])
	case "request":
		cmdRequest(os.Args[2:])
	case "ssh":
		cmdSSH(os.Args[2:])
	case "exec":
		cmdExec(os.Args[2:])
	case "status":
		cmdHealthStatus(os.Args[2:])
	case "certs":
		cmdCerts(os.Args[2:])
	case "targets":
		cmdTargets(os.Args[2:])
	case "services":
		cmdServices(os.Args[2:])
	case "remotes":
		cmdRemotes(os.Args[2:])
	case "whoami":
		cmdWhoami(os.Args[2:])
	case "inspect":
		cmdInspect(os.Args[2:])
	case "monitor":
		cmdMonitor(os.Args[2:])
	case "host-key":
		cmdHostKey(os.Args[2:])
	case "policy":
		cmdPolicy(os.Args[2:])
	case "demo":
		cmdDemo(os.Args[2:])
	case "version", "--version", "-v":
		fmt.Printf("ephyr %s\n", version)
	case "help", "--help", "-h":
		fmt.Fprint(os.Stdout, usage)
	default:
		fmt.Fprintf(os.Stderr, "ephyr: unknown command %q\n\n", subcmd)
		fmt.Fprint(os.Stderr, usage)
		os.Exit(1)
	}
}

// envOrDefault returns the environment variable value if set, otherwise the default.
func envOrDefault(key, defaultVal string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return defaultVal
}
