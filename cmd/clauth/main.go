// Package main implements the clauth agent CLI.
//
// Usage:
//
//	clauth init [--force]
//	clauth request --target <host> --role <role> [--duration <dur>]
//	clauth ssh --target <host> --role <role> [--duration <dur>]
//	clauth exec --target <host> --role <role> [--duration <dur>] -- <command...>
//	clauth status
//	clauth targets
//	clauth whoami
package main

import (
	"fmt"
	"os"
)

const usage = `clauth — SSH certificate agent CLI

Usage:
  clauth init [--force]              Generate Ed25519 keypair
  clauth request -t HOST -r ROLE     Request a certificate
  clauth ssh -t HOST -r ROLE         Request cert + open SSH session
  clauth exec -t HOST -r ROLE -- CMD Request cert + run remote command
  clauth status                      List active certificates
  clauth targets                     List available SSH targets
  clauth services                    List HTTP proxy services
  clauth remotes                     List federated MCP servers
  clauth whoami                      Show agent identity

Global:
  --socket PATH    Broker socket (default: /run/clauth/broker.sock)
  --config-dir DIR Config directory (default: ~/.clauth)
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
	case "help", "--help", "-h":
		fmt.Fprint(os.Stdout, usage)
	default:
		fmt.Fprintf(os.Stderr, "clauth: unknown command %q\n\n", subcmd)
		fmt.Fprint(os.Stderr, usage)
		os.Exit(1)
	}
}
