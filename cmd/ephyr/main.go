// Package main implements the ephyr agent CLI.
//
// Usage:
//
//	ephyr init [--force]
//	ephyr request --target <host> --role <role> [--duration <dur>]
//	ephyr ssh --target <host> --role <role> [--duration <dur>]
//	ephyr exec --target <host> --role <role> [--duration <dur>] -- <command...>
//	ephyr status
//	ephyr targets
//	ephyr whoami
package main

import (
	"fmt"
	"os"
)

const usage = `ephyr — SSH certificate agent CLI

Usage:
  ephyr init [--force]              Generate Ed25519 keypair
  ephyr request -t HOST -r ROLE     Request a certificate
  ephyr ssh -t HOST -r ROLE         Request cert + open SSH session
  ephyr exec -t HOST -r ROLE -- CMD Request cert + run remote command
  ephyr status                      List active certificates
  ephyr targets                     List available SSH targets
  ephyr services                    List HTTP proxy services
  ephyr remotes                     List federated MCP servers
  ephyr whoami                      Show agent identity
  ephyr inspect [--token] [--json]  Inspect a macaroon token

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
	case "init":
		cmdInit(os.Args[2:])
	case "request":
		cmdRequest(os.Args[2:])
	case "ssh":
		cmdSSH(os.Args[2:])
	case "exec":
		cmdExec(os.Args[2:])
	case "status":
		cmdStatus(os.Args[2:])
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
	case "help", "--help", "-h":
		fmt.Fprint(os.Stdout, usage)
	default:
		fmt.Fprintf(os.Stderr, "ephyr: unknown command %q\n\n", subcmd)
		fmt.Fprint(os.Stderr, usage)
		os.Exit(1)
	}
}
