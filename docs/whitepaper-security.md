# Ephyr Security Whitepaper

**Secure Infrastructure Access for AI Agents**

Version 0.3 | March 2026

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Threat Landscape: AI Agents and Infrastructure](#2-threat-landscape-ai-agents-and-infrastructure)
3. [Architecture Deep Dive](#3-architecture-deep-dive)
   - 3.1 [Three-Process Model](#31-three-process-model)
   - 3.2 [Unix Socket IPC and Peer Credential Verification](#32-unix-socket-ipc-and-peer-credential-verification)
   - 3.3 [Systemd Sandboxing](#33-systemd-sandboxing)
   - 3.4 [Network Isolation via nftables](#34-network-isolation-via-nftables)
4. [Trust Model](#4-trust-model)
   - 4.1 [Three-Tier Signing Hierarchy](#41-three-tier-signing-hierarchy)
   - 4.2 [Key Custody and Lifecycle](#42-key-custody-and-lifecycle)
   - 4.3 [Broker Compromise Containment](#43-broker-compromise-containment)
   - 4.4 [Key Rotation](#44-key-rotation)
5. [Authentication](#5-authentication)
   - 5.1 [Layer 1: SO_PEERCRED (Kernel-Verified Identity)](#51-layer-1-so_peercred-kernel-verified-identity)
   - 5.2 [Layer 2: Session Tokens](#52-layer-2-session-tokens)
   - 5.3 [Layer 3: Dashboard Token](#53-layer-3-dashboard-token)
   - 5.4 [Layer 4: MCP API Keys (bcrypt)](#54-layer-4-mcp-api-keys-bcrypt)
   - 5.5 [Layer 5: SSH Certificates](#55-layer-5-ssh-certificates)
   - 5.6 [Auth Cache](#56-auth-cache)
6. [Authorization](#6-authorization)
   - 6.1 [Policy Engine](#61-policy-engine)
   - 6.2 [Eight-Step Evaluation Pipeline](#62-eight-step-evaluation-pipeline)
   - 6.3 [RBAC Model](#63-rbac-model)
   - 6.4 [Capability Envelopes](#64-capability-envelopes)
   - 6.5 [Wildcard Resolution](#65-wildcard-resolution)
7. [Token Architecture](#7-token-architecture)
   - 7.1 [Macaroon-Based Task Tokens](#71-macaroon-based-task-tokens)
   - 7.2 [Delegation Certificates](#72-delegation-certificates)
   - 7.3 [Validation Chain](#73-validation-chain)
   - 7.4 [Identity URN Scheme](#74-identity-urn-scheme)
   - 7.5 [ULID Task Identifiers](#75-ulid-task-identifiers)
   - 7.6 [Ephyr Bind (Planned)](#76-ephyr-bind-planned)
8. [Revocation](#8-revocation)
   - 8.1 [Epoch Watermark Model](#81-epoch-watermark-model)
   - 8.2 [Lineage-Walk Validation](#82-lineage-walk-validation)
   - 8.3 [Cascading Revocation](#83-cascading-revocation)
   - 8.4 [Background Garbage Collection](#84-background-garbage-collection)
   - 8.5 [Comparison with Traditional Approaches](#85-comparison-with-traditional-approaches)
9. [Audit and Correlation](#9-audit-and-correlation)
   - 9.1 [Task-Scoped Audit](#91-task-scoped-audit)
   - 9.2 [Lineage Tracking](#92-lineage-tracking)
   - 9.3 [Structured Logging](#93-structured-logging)
   - 9.4 [Real-Time Event Hub](#94-real-time-event-hub)
   - 9.5 [Activity Ring Buffer](#95-activity-ring-buffer)
10. [Cryptographic Choices](#10-cryptographic-choices)
    - 10.1 [Ed25519 for All Signing Operations](#101-ed25519-for-all-signing-operations)
    - 10.2 [bcrypt for API Key Storage](#102-bcrypt-for-api-key-storage)
    - 10.3 [SHA-256 for Auth Cache Keys](#103-sha-256-for-auth-cache-keys)
    - 10.4 [ULID for Task Identifiers](#104-ulid-for-task-identifiers)
    - 10.5 [Random Value Generation](#105-random-value-generation)
11. [Network Security](#11-network-security)
    - 11.1 [UID-Based nftables Isolation](#111-uid-based-nftables-isolation)
    - 11.2 [Credential Injection Model](#112-credential-injection-model)
    - 11.3 [CIDR Allow/Deny Policy](#113-cidr-allowdeny-policy)
    - 11.4 [DNS Resolution Security](#114-dns-resolution-security)
12. [Hardening Guide](#12-hardening-guide)
    - 12.1 [Systemd Sandboxing Directives](#121-systemd-sandboxing-directives)
    - 12.2 [Production Deployment Recommendations](#122-production-deployment-recommendations)
    - 12.3 [Target Host Hardening](#123-target-host-hardening)
    - 12.4 [Monitoring and Alerting](#124-monitoring-and-alerting)
13. [Comparison with Existing Solutions](#13-comparison-with-existing-solutions)
    - 13.1 [SPIFFE/SPIRE](#131-spiffespire)
    - 13.2 [HashiCorp Vault SSH Secrets Engine](#132-hashicorp-vault-ssh-secrets-engine)
    - 13.3 [Traditional PAM and SSH Key Management](#133-traditional-pam-and-ssh-key-management)
    - 13.4 [Summary Matrix](#134-summary-matrix)
14. [Known Limitations and Future Work](#14-known-limitations-and-future-work)
    - 14.1 [Current Limitations](#141-current-limitations)
    - 14.2 [Planned Improvements](#142-planned-improvements)
    - 14.3 [Research Directions](#143-research-directions)
15. [Appendix A: Trust Boundary Diagram](#15-appendix-a-trust-boundary-diagram)
16. [Appendix B: Threat Enumeration Summary](#16-appendix-b-threat-enumeration-summary)
17. [Appendix C: Dependency Analysis](#17-appendix-c-dependency-analysis)

---

## 1. Executive Summary

Ephyr is an open-source, Go-based privileged access broker purpose-built for
AI agent infrastructure. It replaces static SSH keys and long-lived API tokens
with ephemeral, policy-governed credentials -- enabling organizations to grant
infrastructure access to autonomous AI agents without expanding their permanent
attack surface.

### The Problem

AI agents -- LLM-driven automation systems -- are increasingly deployed to
manage infrastructure: running diagnostics, restarting services, querying
databases, and orchestrating multi-step operations. Traditional access models
fail for these workloads:

- **Static SSH keys** grant persistent access with no expiration, no audit
  trail tied to the task that initiated the operation, and no mechanism to
  scope access to the current operation's requirements.

- **Long-lived API tokens** are bearer credentials that, once leaked, grant
  full access until manually rotated. Agent environments -- where prompts may
  be manipulated and tool outputs may be observed by untrusted parties -- make
  credential leakage a primary concern.

- **Human-centric IAM** assumes interactive approval workflows, password
  challenges, and session durations measured in hours. Agent operations require
  sub-second credential issuance, task-scoped lifetimes measured in minutes,
  and fully automated policy evaluation.

### The Solution

Ephyr provides a single MCP (Model Context Protocol) endpoint through which
agents request access. Every operation flows through an eight-step authorization
pipeline, results in an ephemeral credential with a default five-minute
lifetime, and is recorded in a structured audit log correlated to the specific
task that initiated it. Agents never handle infrastructure credentials directly
-- the broker generates keypairs, obtains signed certificates, establishes
connections, and injects credentials on the agent's behalf.

### Security Value Proposition

| Property | Mechanism |
|----------|-----------|
| **No persistent secrets** | Ephemeral Ed25519 keypairs generated per-request, never written to disk |
| **Bounded blast radius** | 5-minute default certificate TTL; delegation certs limit broker authority to 1 hour |
| **Defense in depth** | 5 authentication layers, 3-tier trust hierarchy, process-level isolation |
| **Unforgeable identity** | SO_PEERCRED kernel verification for co-located agents |
| **Zero credential exposure** | HTTP proxy injects credentials invisibly; agents cannot extract tokens |
| **Task-scoped audit** | Every operation tied to a ULID-identified task with hierarchical lineage |
| **Minimal dependencies** | ~33,000 lines of Go (377 tests, 2 fuzz tests); 3 external libraries (gorilla/websocket, x/crypto, yaml.v3) |

### Intended Audience

This whitepaper is written for security engineers, infrastructure architects,
and compliance teams evaluating Ephyr for production deployment. It provides
a thorough description of the security architecture, cryptographic decisions,
threat model, and known limitations -- sufficient for an informed risk
assessment.

---

## 2. Threat Landscape: AI Agents and Infrastructure

### 2.1 The Agent Identity Problem

Human users have well-established identity frameworks: SSO providers, MFA
devices, biometric authentication, and session management tied to browser
cookies or desktop credentials. AI agents operate outside these frameworks.
An agent is a process -- potentially running in a container, a VM, or as a
subprocess of another tool -- with no inherent identity beyond its OS-level
UID and the API keys it was provisioned with.

This creates several security challenges unique to agent workloads:

**Identity bootstrapping.** How does an agent prove it is the entity it claims
to be? Unlike a human who can enter a password or present a hardware token,
an agent's identity must be established through some combination of its
execution context (where it runs, as which user) and provisioned credentials.

**Credential scope.** A human administrator who SSH-keys into a server has
a mental model of what they intend to do and (ideally) stops there. An agent
executing a multi-step plan may request access to resources it does not
actually need for the current task, particularly if the plan was generated
by a language model susceptible to prompt injection.

**Audit attribution.** When three agents access the same server in the same
minute, traditional syslog entries that record only the SSH principal and
source IP are insufficient. Security teams need to trace each command back to
the specific task, agent, and triggering event.

**Credential lifecycle.** Agents operate continuously. A credential issued to
an agent at 2 AM may still be valid at 2 PM, long after the task that
required it has completed. Traditional session timeouts assume human
interaction patterns; agent operations are bursty and task-scoped.

### 2.2 The Blast Radius Problem

When a human account is compromised, the blast radius is bounded by that
human's privileges. When an agent account is compromised, the blast radius is
the union of all resources the agent could ever access -- because agents
are typically provisioned with broad permissions to handle diverse tasks.

Consider a monitoring agent with SSH access to twenty servers. If its
credential is compromised, the attacker has immediate access to all twenty
servers for the full lifetime of the credential. With a static SSH key, that
lifetime is indefinite.

Ephyr addresses this by making every credential:

1. **Ephemeral** -- default 5-minute lifetime, maximum 24-hour hard cap
2. **Task-scoped** -- the capability envelope constrains which targets, roles,
   services, and HTTP methods a specific task token can authorize
3. **Auditable** -- each credential is tied to a ULID-identified task with
   a hierarchical lineage chain

### 2.3 The Credential Management Problem

Deploying agents at scale requires distributing credentials to each agent
instance. Every distribution point is an exfiltration opportunity. API keys
in environment variables, SSH keys in mounted volumes, and tokens in
configuration files create a sprawling credential surface.

Ephyr's design principle is that agents should never hold infrastructure
credentials. The broker holds all credentials (SSH CA key, API tokens, service
passwords) in a single, hardened location. Agents interact exclusively through
the broker's MCP endpoint, receiving only the results of operations --
never the credentials that enabled them.

### 2.4 The Prompt Injection Threat

AI agents are uniquely susceptible to prompt injection: malicious content in
tool outputs or user messages can manipulate the agent's behavior. An agent
that holds credentials and can construct arbitrary SSH commands or HTTP requests
is a powerful target for this attack.

Ephyr mitigates prompt injection impact through:

- **Capability envelopes** that upper-bound what any task token can authorize,
  regardless of what the agent requests
- **Policy-engine validation** that rejects requests outside the agent's
  configured permissions
- **HTTP proxy credential injection** that prevents agents from extracting
  or redirecting credentials to unintended destinations
- **CIDR-based network policy** that restricts proxy destinations to approved
  address ranges

---

## 3. Architecture Deep Dive

### 3.1 Three-Process Model

Ephyr implements strict privilege separation through three independent
OS-level processes, each running with the minimum privileges required for
its function:

```
                    +-------------------------------------------------+
                    |            EPHYR HOST (any Linux platform)      |
                    |                                                 |
  +-----------+     |  +----------+   AF_UNIX    +----------------+  |
  |           |     |  |          |<============>|                |  |
  | Agent CLI |=====|=>| Signer   | SO_PEERCRED  |    Broker      |  |
  | (UID 1000)|     |  | (UID 999)| (UID check)  |   (UID 999)   |  |
  |           |     |  |          |              |                |  |
  +-----------+     |  | CA Key   |              | Policy Engine  |  |
       ||           |  | AF_UNIX  |              | Session Mgr    |  |
       ||           |  | only     |              | MCP Server     |  |
       ||           |  +----------+              | HTTP Proxy     |  |
       ||           |                            | Dashboard      |  |
  nftables          |                            | Audit Logger   |  |
  BLOCKS            |                            | Event Hub      |  |
  direct            |                            +----+---+---+---+  |
  access            |                                 |   |   |      |
                    +---------------------------------|---|---|-------+
                                                      |   |   |
                                            SSH certs |   |   | MCP
                                           (ephemeral)|   |   | federation
                                                      v   |   v
                                                  +------+ | +--------+
                                                  |Target| | |Remote  |
                                                  |Hosts | | |MCP     |
                                                  +------+ | |Servers |
                                                           | +--------+
                                                           v
                                                     +---------+
                                                     | HTTP    |
                                                     | Services|
                                                     +---------+
```

**Why three processes?** The signer holds the CA private key -- the single
most valuable secret in the system. By isolating it in a dedicated process
with no network access, Ephyr ensures that a broker compromise cannot
extract the CA key. The signer validates every IPC connection via
`SO_PEERCRED`, accepting only connections from UID 999 (the broker). Even
if an attacker achieves code execution within the broker process, they cannot
open a TCP socket to exfiltrate the key (the signer has no network) and
they cannot impersonate the broker UID to extract the key via IPC (the
kernel enforces UID verification).

**Why not a single process with separate goroutines?** Goroutine isolation
is not a security boundary. A compromised goroutine within the same process
can read any memory in the process address space, including the CA private
key. OS-level process isolation, combined with systemd sandboxing and network
restrictions, provides defense-in-depth that in-process isolation cannot.

### 3.2 Unix Socket IPC and Peer Credential Verification

All inter-process communication uses Unix domain sockets with `SO_PEERCRED`
verification. This is a Linux kernel mechanism that provides unforgeable
caller identity:

```
  Agent Process (UID 1000)
       |
       | connect(/run/ephyr/broker.sock)
       |
       v
  Kernel: getsockopt(SO_PEERCRED)
       |
       | Returns: { uid: 1000, gid: 1000, pid: 42381 }
       |           (populated from kernel process table)
       v
  Broker Process
       |
       | Maps UID 1000 -> "claude" agent in policy.yaml
       | Proceeds with request evaluation
```

**Properties of SO_PEERCRED:**

- **Unforgeable from userspace.** The UID, GID, and PID are read directly
  from the kernel process table. A process cannot claim a different UID
  without actually running as that UID (which requires root or
  `CAP_SETUID`).

- **Verified on every connection.** Each new Unix socket connection triggers
  a fresh `SO_PEERCRED` extraction. There is no session token to steal or
  replay at this layer.

- **Zero configuration.** No secrets, keys, or passwords need to be
  distributed to agents for local authentication. The agent's OS UID is
  its identity.

The signer applies the same mechanism with a stricter policy: it extracts
`SO_PEERCRED` from every connection and rejects any UID that does not match
the `EPHYR_BROKER_UID` environment variable (999 in production). This means
even root-privilege agents on the same host cannot directly communicate with
the signer -- only the broker can.

**IPC Protocol.** The signer uses a one-shot, newline-delimited JSON protocol.
Each connection handles exactly one request-response exchange, then closes.
This eliminates state management complexity and prevents connection pooling
attacks. The protocol is deliberately simpler than JSON-RPC 2.0 -- there is
no multiplexing, no streaming, and no session state.

```json
// Request: SSH certificate signing (broker -> signer)
{"action":"sign","public_key":"ssh-ed25519 AAAA...","principals":["agent-read"],
 "duration":"5m","key_id":"ephyr:claude@webserver/read","force_command":""}

// Response: SSH certificate (signer -> broker)
{"certificate":"<base64 SSH certificate>","serial":"a1b2c3d4e5f60718",
 "expires_at":"2026-03-10T14:35:00Z"}

// Request: delegation certificate (broker -> signer)
{"action":"sign_delegation","public_key":"<base64 broker Ed25519 pubkey>",
 "broker_id":"broker-01","ttl":"1h"}

// Response: delegation cert with root signature (signer -> broker)
{"cert_id":"deleg-a1b2","signature":"<base64 Ed25519 sig>",
 "expires_at":"2026-03-10T15:30:00Z","root_public_key":"<base64>"}
```

Four actions are supported:
- `sign` -- sign an SSH user certificate for ephemeral target access
- `sign_delegation` -- sign a delegation certificate granting the broker's ephemeral Ed25519 public key short-lived token signing authority (used for JWT legacy path; macaroon path uses HMAC root keys generated locally)
- `root_public_key` -- return the signer's Ed25519 public key for pinning
- `ping` -- health check

### 3.3 Systemd Sandboxing

Both the signer and broker run as systemd services with extensive security
directives. The signer, as the most security-critical component, receives the
strictest sandbox.

**Signer Sandbox (systemd-analyze security score: 1.9/10):**

| Directive | Security Effect |
|-----------|----------------|
| `ProtectSystem=strict` | Entire filesystem is read-only except explicitly allowed paths |
| `MemoryDenyWriteExecute=yes` | Prevents mapping memory as both writable and executable; blocks JIT compilation, shellcode injection, and most memory corruption exploits |
| `RestrictAddressFamilies=AF_UNIX` | Kernel-level prohibition on creating TCP, UDP, or raw sockets. The signer process cannot communicate over the network under any circumstances. |
| `CapabilityBoundingSet=` (empty) | All Linux capabilities dropped. Process cannot perform any privileged operations. |
| `NoNewPrivileges=yes` | Cannot escalate privileges via setuid/setgid binaries |
| `SystemCallFilter=@system-service` | Allowlisted system calls only; disallowed syscalls return EPERM |
| `ProtectHome=yes` | Home directories are invisible to the process |
| `PrivateTmp=yes` | Isolated /tmp namespace |
| `PrivateDevices=yes` | No access to /dev (no device files) |
| `ProtectKernelTunables=yes` | /proc/sys and /sys are read-only |
| `ProtectKernelModules=yes` | Cannot load kernel modules |
| `ReadOnlyPaths=/etc/ephyr` | CA key directory is read-only (key loaded at startup) |
| `ReadWritePaths=/run/ephyr` | Only the socket directory is writable |
| `RestrictNamespaces=yes` | Cannot create new namespaces (no container escape) |
| `LockPersonality=yes` | Cannot change execution domain |
| `RestrictRealtime=yes` | Cannot acquire realtime scheduling priority |
| `ProtectHostname=yes` | Cannot change hostname |
| `RestrictSUIDSGID=yes` | Cannot set SUID/SGID bits on files |

The practical effect: even if an attacker achieves code execution within the
signer process, they cannot:
- Open any network connection (AF_UNIX restriction)
- Write to any file outside /run/ephyr (ProtectSystem=strict)
- Execute injected shellcode (MemoryDenyWriteExecute)
- Escalate to root (NoNewPrivileges, empty CapabilityBoundingSet)
- Load a kernel module (ProtectKernelModules)
- Create a container to escape (RestrictNamespaces)

**Broker Sandbox:**

The broker has a slightly relaxed sandbox to allow TCP listeners (dashboard
and MCP ports) and write access to logs and configuration:

| Directive | Value |
|-----------|-------|
| `RestrictAddressFamilies` | `AF_UNIX AF_INET AF_INET6` (Unix + TCP) |
| `ReadWritePaths` | `/run/ephyr /var/log/ephyr /var/lib/ephyr` |
| `CapabilityBoundingSet` | Empty (no capabilities) |

All other hardening directives match the signer. The broker can listen on
TCP ports but cannot perform privileged operations, access home directories,
or modify the system filesystem.

### 3.4 Network Isolation via nftables

When agents run co-located on the broker host (the recommended deployment
model), nftables UID-based rules prevent agents from bypassing the broker:

```
                   +-------------------------------------+
                   |           EPHYR HOST               |
                   |                                     |
  Agent (UID 1000) |  nftables OUTPUT chain:             |
  can ONLY reach:  |    uid 1000 -> REJECT               |
    - broker.sock  |    (for all TCP/UDP to backend IPs) |
    - localhost     |                                     |
                   |  Broker (UID 999)                   |
                   |    -> unrestricted outbound         |
                   +-------------------------------------+
```

The nftables rules operate at Layer 3/4, matching the source UID of outbound
packets. An agent process running as UID 1000 is blocked from establishing
TCP connections to any backend IP range (RFC 1918 or configured targets).
All infrastructure access must flow through the broker's Unix socket, where
policy evaluation, credential injection, and audit logging occur.

This is a defense-in-depth measure. Even if an agent discovers a backend
service's IP address and port, it cannot connect directly. The broker is
the sole network gateway for agent operations.

---

## 4. Trust Model

### 4.1 Three-Tier Signing Hierarchy

Ephyr implements a three-tier signing hierarchy that bounds the authority
of each layer:

```
  +-------------------+
  |  Root CA (Signer) |    Tier 0: Long-lived Ed25519 key
  |  /etc/ephyr/     |    Scope: Can sign anything (SSH certs + delegation certs)
  |  ca_key            |    Exposure: Zero network, UID-restricted IPC, systemd sandbox
  +--------+----------+
           |
           | signs (infrequent IPC, ~1x per hour)
           v
  +-------------------+
  | Delegation Cert   |    Tier 1: Broker's ephemeral Ed25519 key + signed cert
  | (Broker memory)   |    Scope: Can mint macaroon root keys within envelope bounds
  +--------+----------+    Lifetime: 1 hour (configurable)
           |
           | derives root key (no IPC needed)
           v
  +-------------------+
  | Macaroon Token    |    Tier 2: HMAC-SHA256 chained bearer token
  | (CTT-E / CTT-D)  |    Scope: Single task, bounded by capability envelope caveats
  | (Agent memory)    |    Lifetime: Up to 1 hour (configurable, max of delegation TTL)
  +-------------------+    Delegation: clone + add caveats (CTT-D, max depth 5)
```

**Why three tiers?** The root CA key is the most sensitive secret. If the
broker had to contact the signer for every task token, the IPC channel would
be a high-frequency target. By introducing a delegation certificate, the
broker can mint macaroon task tokens locally using root keys derived from
an ephemeral key that is itself signed by the root CA. This reduces IPC
to approximately once per hour (delegation rotation), while the signer
validates every delegation request against its peer credential check.

### 4.2 Key Custody and Lifecycle

**Root CA Key:**
- Generated once via `ssh-keygen -t ed25519`
- Stored at `/etc/ephyr/ca_key` with permissions 0600
- Read by the signer at process startup; never re-read
- The signer validates file permissions at load time (rejects anything
  other than 0600)
- Backed up offline and encrypted; loss requires re-provisioning all
  target hosts with a new CA public key

**Delegation Key:**
- Generated by the broker using `crypto/ed25519.GenerateKey` with
  `crypto/rand.Reader` as entropy source
- Exists only in broker process memory; never written to disk
- Replaced every 50 minutes (default `refreshAt`); the old key is retained
  as `prevKey` for graceful rollover until tokens derived from it expire

**Task Token Keys:**
- Task tokens are HMAC-SHA256 macaroons, not signed JWTs
- Each task tree gets one root key derived from the delegation key
- The HMAC chain proves caveat accumulation -- caveats cannot be removed
  without knowledge of the root key
- Delegation (CTT-D) works by cloning a parent macaroon and appending
  narrowing caveats; no additional key material is generated per delegation

### 4.3 Broker Compromise Containment

A critical design goal: broker compromise must not yield the CA key and
must be bounded in scope.

**What an attacker gains with broker code execution:**

1. The ability to request SSH certificates from the signer, but only
   within the constraints of the policy engine (the signer enforces
   maximum TTL of 24 hours independently)
2. Access to plaintext service credentials in `/var/lib/ephyr/services.json`
   and federated MCP credentials in `/var/lib/ephyr/remotes.json`
3. The ability to mint macaroon task tokens using root keys derived from
   the current delegation key
4. Read/write access to the audit log (within the broker's ReadWritePaths)
5. The ability to toggle hosts, services, and remotes on/off

**What an attacker does NOT gain:**

1. The CA private key (isolated in the signer process, UID-restricted IPC)
2. The ability to extend delegation certificate lifetime beyond the current
   cert's expiry (at most ~1 hour)
3. Persistence -- once the broker process is restarted, the delegation key
   rotates and the attacker's key is invalidated
4. The ability to modify the policy file (`/etc/ephyr/policy.yaml` is
   read-only to the broker process via `ProtectSystem=strict`)

**Temporal bound:** A broker compromise is bounded by the delegation
certificate's remaining TTL. After rotation, the old delegation key is
discarded and any macaroon root keys derived from it become invalid once
the cert expires. The maximum window is the delegation TTL (default
1 hour).

**What a broker compromise does NOT provide:**
- The CA private key (isolated in the signer process)
- The ability to extend delegation certificate lifetime beyond the
  current cert's expiry
- Persistence beyond a broker restart (delegation key rotates)
- The ability to modify policy (`/etc/ephyr/policy.yaml` is read-only)
- Protection against detection (audit log and WebSocket event hub
  record all broker operations)

### 4.4 Key Rotation

**Delegation Certificate Rotation:**

The `DelegationManager` implements automatic key rotation:

1. At startup, the broker generates a fresh Ed25519 keypair and requests
   a delegation certificate from the signer via IPC
2. A background goroutine triggers rotation at the `refreshAt` interval
   (default 50 minutes, configurable)
3. On rotation:
   - New Ed25519 keypair generated
   - New delegation certificate requested from signer
   - Previous key moved to `prevKey` for graceful rollover
   - Token minter updated with new delegation key for root key derivation
   - Metrics incremented (`DelegationRotations`)
4. If rotation fails (signer unreachable), the broker continues using the
   existing key and retries at the next interval

**Root CA Key Rotation (manual):**

Root key rotation is a manual operational procedure:

1. Generate a new Ed25519 CA key
2. Deploy the new CA public key to all target hosts' `TrustedUserCAKeys`
   alongside the old key (both are trusted during the transition)
3. Restart the signer with the new CA key
4. After all outstanding certificates signed by the old key have expired,
   remove the old CA public key from target hosts

---

## 5. Authentication

Ephyr implements five independent authentication layers, each providing
a different guarantee. No single layer's compromise grants full system access.

```
  +-----------------------------------------------------------------+
  | Layer 5: SSH Certificates (Ed25519, ephemeral, 5-min TTL)       |
  |   Authenticates broker to target hosts                          |
  +-----------------------------------------------------------------+
  | Layer 4: MCP API Keys (bcrypt + auth cache)                     |
  |   Authenticates remote agents to broker                         |
  +-----------------------------------------------------------------+
  | Layer 3: Dashboard Token (constant-time comparison)             |
  |   Authenticates human operators to dashboard                    |
  +-----------------------------------------------------------------+
  | Layer 2: Session Tokens (256-bit, crypto/rand)                  |
  |   Authenticates agent sessions after UID verification           |
  +-----------------------------------------------------------------+
  | Layer 1: SO_PEERCRED (kernel-verified UID)                      |
  |   Authenticates co-located agents at the OS level               |
  +-----------------------------------------------------------------+
```

### 5.1 Layer 1: SO_PEERCRED (Kernel-Verified Identity)

The primary authentication mechanism for co-located agents. When an agent
connects to `/run/ephyr/broker.sock`, the broker extracts the caller's
credentials using the `getsockopt(SO_PEERCRED)` system call:

```go
func GetPeerCred(conn net.Conn) (uid uint32, pid int32, err error) {
    unixConn := conn.(*net.UnixConn)
    raw, _ := unixConn.SyscallConn()
    var cred *syscall.Ucred
    raw.Control(func(fd uintptr) {
        cred, _ = syscall.GetsockoptUcred(int(fd),
            syscall.SOL_SOCKET, syscall.SO_PEERCRED)
    })
    return cred.Uid, cred.Pid, nil
}
```

The kernel populates the `Ucred` structure from its process table. This
cannot be spoofed from userspace -- it requires `CAP_SETUID` (which the
agent does not have, since `NoNewPrivileges=yes` is set on all systemd
units) or a kernel exploit.

The extracted UID is mapped to an agent identity in `policy.yaml`. If no
agent is registered for the UID, the connection is rejected before any
further processing.

**Socket permissions:** `/run/ephyr/broker.sock` is created with mode
0660 and group `ephyr-agents`. Only processes in that group can connect.

### 5.2 Layer 2: Session Tokens

After UID verification, agents establish a session by calling
`POST /v1/session`. The broker generates a 256-bit token using
`crypto/rand.Read`:

```go
func generateToken() (string, error) {
    b := make([]byte, 32)     // 256 bits
    _, err := rand.Read(b)    // CSPRNG
    return hex.EncodeToString(b), err  // 64 hex characters
}
```

**Session properties:**
- One active session per agent (creating a new session invalidates
  the previous token)
- Cross-checked against SO_PEERCRED: the session UID must match the
  connection UID on every request
- No session expiry (sessions live until agent creates a new one or
  the broker restarts)
- Token masked in API responses: `[:8]...[-8:]`

**Security rationale:** Sessions provide a second factor beyond UID
verification. If an attacker gains access to the Unix socket but not the
agent's session token, they can see that an agent exists but cannot
execute operations. Combined with SO_PEERCRED, an attacker would need
both the correct UID and a valid session token.

### 5.3 Layer 3: Dashboard Token

The dashboard at port 8553 is protected by a static token compared using
`crypto/subtle.ConstantTimeCompare`:

```go
if subtle.ConstantTimeCompare([]byte(provided), []byte(expected)) != 1 {
    // reject
}
```

**Properties:**
- Constant-time comparison prevents timing-based token extraction
- CORS restricted to same-origin
- Static assets (CSS, JS) are exempt from authentication
- Token masked in audit logs: `first4...last4`

**Dashboard privacy features:**
- SensitiveField components auto-hide content after 5 seconds
- CanvasSecret renders tokens on HTML canvas (not text-selectable,
  not present in DOM)
- Page content blurs on tab switch (prevents over-the-shoulder
  observation)
- Print CSS hides all sensitive content

### 5.4 Layer 4: MCP API Keys (bcrypt)

Remote agents connecting to the MCP server at port 8554 authenticate via
the `X-API-Key` HTTP header. Keys are stored as bcrypt hashes in
`policy.yaml`:

```yaml
agents:
  claude:
    uid: 1000
    api_key_hash: "$2a$10$..."  # bcrypt hash
```

**bcrypt properties relevant to Ephyr:**
- Cost factor 10 (default) -- each comparison takes approximately
  100ms on modern hardware
- Inherently constant-time per comparison (no timing side-channel on
  hash match vs. mismatch)
- Salt embedded in the hash -- no separate salt storage required
- 72-byte input limit (Go's `bcrypt` implementation truncates at
  72 bytes)

The `MCPAuthenticator` iterates through all registered agents on each
authentication attempt, comparing the provided key against each agent's
bcrypt hash. This is O(n) in the number of agents, with each comparison
taking ~100ms. For typical deployments (fewer than 10 agents), this is
acceptable. For larger deployments, the auth cache (Section 5.6)
mitigates the cost.

### 5.5 Layer 5: SSH Certificates

SSH certificates authenticate the broker to target hosts. For each
command execution:

1. Broker generates an ephemeral Ed25519 keypair in memory
2. Broker requests a signed certificate from the signer, specifying:
   - Principals (the SSH user, e.g., `agent-read`)
   - Duration (default 5 minutes, clamped by policy)
   - Key ID format: `ephyr:{agent}@{target}/{role}:{serial_hex}`
3. Signer validates the request, applies its own duration cap (24-hour
   hard maximum), and returns the signed certificate
4. Broker establishes the SSH connection using the ephemeral keypair
   and certificate
5. After command execution, the keypair and certificate are discarded

**Certificate properties:**
- Serial: Cryptographically random 8-byte uint64 (`crypto/rand`)
- Clock skew grace: 30 seconds before `now`
- Extensions: `permit-pty`, `permit-port-forwarding`, `permit-agent-forwarding`
- Critical options: `force-command` when target policy specifies one

**Target-side validation:** Target hosts are configured with
`TrustedUserCAKeys` pointing to the Ephyr CA public key and
`AuthorizedPrincipalsFile` mapping each role account to its principal.
The certificate's principal (e.g., `agent-read`) must match a line in
the target user's principals file.

### 5.6 Auth Cache

To avoid repeated bcrypt comparisons for the same API key, the
`MCPAuthenticator` maintains an in-memory cache keyed on
`SHA-256(apiKey)`:

```
  API Key arrives
       |
       v
  SHA-256(key) -> cache lookup
       |
  +----+----+
  |         |
  HIT     MISS
  |         |
  return   bcrypt compare against all agents
  cached     |
  agent    match found?
             |
          +--+--+
          |     |
         YES    NO
          |     |
       cache  reject
       result
```

**Cache properties:**
- Key: `SHA-256(apiKey)` -- the raw API key is never stored in the cache
- Value: `*MCPAgent` struct + expiry timestamp
- TTL: 60 seconds (configurable via `EPHYR_AUTH_CACHE_TTL`)
- Invalidation: entire cache cleared on agent add/remove
- Thread-safe: `sync.RWMutex` with separate lock from agent registry
- Observable: `CacheStats()` returns hit/miss counters

**Security considerations:**
- SHA-256 is used only as a cache key, not for authentication. The
  security guarantee comes from bcrypt -- the cache merely avoids
  repeating the expensive bcrypt comparison.
- Cache TTL bounds the window during which a revoked key remains valid
  (maximum 60 seconds by default).
- Setting TTL to 0 disables caching entirely.

---

## 6. Authorization

### 6.1 Policy Engine

Authorization is governed by a declarative YAML policy file at
`/etc/ephyr/policy.yaml`. The policy defines four sections:

```yaml
global:
  max_active_certs: 10
  default_ttl: "5m"
  max_ttl: "30m"
  rate_limit:
    requests_per_window: 10
    window_seconds: 60

agents:
  claude:
    uid: 1000
    max_concurrent_certs: 3
    api_key_hash: "$2a$10$..."
    inherits: [monitoring]
    ssh:
      web-server:
        roles: [read, operator]
        auto_approve: true
    services:
      "*":
        methods: [GET, POST]
    dashboard: viewer

templates:
  monitoring:
    ssh:
      "*":
        roles: [read]
    services:
      grafana:
        methods: [GET]

roles:
  read:
    principal: "agent-read"
  operator:
    principal: "agent-op"
  admin:
    principal: "agent-admin"

targets:
  web-server:
    host: "10.0.1.10"
    port: 22
    allowed_roles: [read, operator, admin]
    max_ttl: "30m"
    auto_approve: true
```

Policy is hot-reloaded via `SIGHUP` (`systemctl reload ephyr-broker`)
without service restart. Invalid configurations are rejected, and the
broker continues using the previous valid policy.

### 6.2 Eight-Step Evaluation Pipeline

Every SSH certificate request passes through eight sequential checks.
Failure at any step short-circuits the pipeline:

```
  Certificate Request
       |
  [1] Agent exists by UID? -------> DENY: "unknown agent UID"
       |
  [2] Target exists in policy? ---> DENY: "unknown target"
       |
  [3] Role in target's            > DENY: "role not allowed on target"
      allowed_roles?
       |
  [4] Duration clamped to
      min(requested,
          target.max_ttl,
          global.max_ttl)  -------> (silent clamp, no denial)
       |
  [5] Agent active certs           > DENY: "at concurrent cert limit"
      < max_concurrent_certs?
       |
  [6] Duplicate cert for same
      agent+target+role? ----------> (auto-revoke old cert)
       |
  [7] Global active certs         > DENY: "global limit reached"
      < max_active_certs?
       |
  [8] Auto-approve check ---------> APPROVE or PENDING
```

**Design notes:**

- **Step 4** silently clamps duration rather than rejecting. This prevents
  agents from being denied access due to requesting a longer-than-allowed
  TTL -- the policy simply enforces its maximum.

- **Step 6** auto-revokes duplicate certificates. Agents retry on failure,
  and stale certificates consuming concurrency slots would create deadlocks.
  The deduplication key is `{agentUID}:{target}:{role}`.

- **Step 5 runs before Step 6.** Expired certificates are purged before
  the pipeline begins (`CleanExpired()`), so stale entries do not affect
  concurrency counts.

### 6.3 RBAC Model

Ephyr v0.2 introduces role-based access control (RBAC) with per-agent
permissions across three proxy paths:

**SSH Access:** Per-agent, per-target role restrictions. An agent can be
allowed `read` on all targets but `operator` only on specific targets.

**Service Access:** Per-agent HTTP method restrictions per service.
An agent can be allowed `GET` on all services but `POST` only on specific
services.

**Remote Access:** Per-agent tool restrictions per federated MCP server.
An agent can be allowed all tools on one remote but only specific tools
on another.

**Dashboard Access:** Four levels: `none`, `viewer`, `operator`, `admin`.
Controls which dashboard operations an agent's API key can perform.

**Template Inheritance:** Agents can inherit from templates via the
`inherits` field. Templates are merged left-to-right (first template
wins per key), then agent-specific settings overlay templates.
Agent-level settings always override inherited templates.

**Legacy Mode:** Agents with no RBAC fields configured receive
`LegacyMode=true`, which grants full access to all targets, services,
and remotes. This ensures backward compatibility with existing
deployments.

**Resolution algorithm:**

```
  1. Check if agent has ANY RBAC fields (ssh, services, remotes,
     dashboard, inherits)
  2. If no RBAC fields: LegacyMode=true (full access)
  3. If RBAC fields present:
     a. Merge templates left-to-right (first-wins per key)
     b. Overlay agent-specific settings (always wins)
     c. Intersect SSH roles with target's allowed_roles
        (agent cannot exceed target's role list)
```

### 6.4 Capability Envelopes

Task tokens (CTT-E) carry a capability envelope that defines the upper
bound of what the token can authorize:

```json
{
  "envelope": {
    "targets":  ["web-server", "blog-server"],
    "roles":    ["read", "operator"],
    "services": ["grafana", "gitea"],
    "remotes":  ["demo-tools"],
    "methods":  ["GET", "POST"]
  }
}
```

The envelope is computed from the agent's RBAC permissions at token
issuance time. Every brokered request must satisfy both the capability
envelope AND the policy engine -- the envelope is a pre-check that runs
before full policy evaluation.

**Subset enforcement:** Delegation tokens (CTT-D) require child
envelopes to be strict subsets of their parent's envelope. The
effective envelope reducer derives semantic narrowing via set
intersection and minimum operations. The `IsSubsetOf()` method
validates this at issuance time, ensuring that delegation never
amplifies privileges. Delegation depth is capped at 5 levels.

### 6.5 Wildcard Resolution

Policy supports the `"*"` wildcard for targets, services, and remotes.
However, tokens never contain wildcards. At token issuance time,
wildcards are resolved to explicit literal arrays:

```
  Policy: agent.ssh = { "*": { roles: [read] } }
  Targets in policy: [web-server, blog-server, staging-server]

  Resolved envelope.targets = ["web-server", "blog-server", "staging-server"]
```

This ensures that tokens are self-describing -- a security reviewer can
inspect a token and see exactly which resources it authorizes, without
needing to resolve wildcards against the current policy.

---

## 7. Token Architecture

### 7.1 Macaroon-Based Task Tokens

Task tokens (CTT-E for root tasks, CTT-D for delegated tasks) are
HMAC-SHA256 macaroons serialized in a compact binary format. Macaroons
replace the earlier JWT-based token design, providing cryptographic
proof of caveat accumulation combined with deterministic semantic
narrowing via the effective envelope reducer.

```
  Macaroon Structure:
  +---------------------------------------------------------+
  | Location: "ephyr-broker"                                |
  | Id:       <root task ULID bytes>                        |
  |                                                         |
  | Caveats (HMAC-chained):                                 |
  |   "targets = web-server"                                |
  |   "roles = read"                                        |
  |   "services = grafana"                                  |
  |   "methods = GET"                                       |
  |   "expires = 1741870200"                                |
  |   "agent = claude"                                      |
  |   "initiated_by = ephyr:apikey:ak_claud"                |
  |   "can_delegate = true"                                 |
  |   "delegation_depth = 5"                                |
  |                                                         |
  | Signature: HMAC-SHA256 chain                            |
  |   sig_0 = HMAC(root_key, id)                            |
  |   sig_1 = HMAC(sig_0, caveat_0)                         |
  |   sig_N = HMAC(sig_{N-1}, caveat_{N-1})                 |
  +---------------------------------------------------------+

  Binary format (version 0x02):
  [1B version][4B id_len][id][4B loc_len][loc]
  [4B num_caveats][4B cav_len][cav]...[32B signature]
  Maximum: 8192 bytes
```

**HMAC chain properties:**

- **Caveat accumulation is cryptographically enforced.** Each caveat
  updates the signature: `sig_new = HMAC-SHA256(sig_old, caveat)`.
  Removing a caveat produces a different chain, and the final signature
  will not match. An agent cannot widen its permissions by stripping
  caveats.

- **Delegation by attenuation.** A delegating agent clones the parent
  macaroon, appends narrowing caveats, and passes the result. The child
  token is strictly more constrained than the parent. The
  `IsSubsetOf()` method in the effective envelope reducer validates
  that delegation never amplifies privileges.

- **One root key per task tree.** The macaroon's `Id()` is always the
  root task ULID. All tokens in a delegation chain share the same root
  key, which only the broker possesses. Agents hold the token (with its
  chained signature) but never the root key.

**Effective envelope reducer:**

The reducer walks the caveat list and derives the effective
authorization envelope via deterministic semantic narrowing:

- **Set intersection** for multi-valued dimensions (targets, roles,
  services, remotes, methods). Each successive caveat can only narrow
  the permitted set.
- **Minimum** for numeric dimensions (delegation_depth). Each
  successive caveat can only decrease the remaining depth.
- **Logical AND** for boolean dimensions (can_delegate). Once
  delegation is disabled, it cannot be re-enabled.
- **Earliest** for temporal dimensions (expires). Each successive
  caveat can only bring the expiry forward.

If any dimension reduces to an empty set, the token is rejected with
`ErrEmptyDimension` -- a token that authorizes nothing is invalid.

**Bearer token semantics:** Task tokens are bearer credentials. Any
entity possessing the serialized token can present it to the broker.
This is an explicit design choice for Ephyr Core and Ephyr Delegation.
The risk of token replay is mitigated by short TTLs (default 5 minutes)
and epoch watermark revocation. Ephyr Bind (Section 7.6) addresses
this by adding proof-of-possession binding.

**What macaroon tokens provide:**

- Cryptographic proof of caveat accumulation (HMAC chain)
- Deterministic semantic narrowing (effective envelope reducer)
- Delegation without broker involvement (clone + add caveats)
- Compact binary serialization (typically under 1 KB)

**What macaroon tokens do NOT provide:**

- Protection against bearer token theft (mitigated by TTL + watermark)
- Protection against a compromised agent runtime replaying the token
- Body integrity (the token does not bind to a specific request body)
- TLS channel binding
- Holder binding (addressed by Ephyr Bind, Section 7.6)

**Design decisions:**

- **HMAC-SHA256 over EdDSA signatures for tokens:** Macaroons use
  symmetric HMAC, which is faster than asymmetric Ed25519 signing and
  enables delegation without broker involvement. The broker holds
  the root key and can verify any token in the chain. Agents cannot
  forge tokens because they lack the root key.

- **Binary format over JWT encoding:** The compact binary format
  (version 0x02) avoids base64url overhead and JSON parsing. Tokens
  are smaller and faster to serialize/deserialize.

- **ULID-based identifiers:** Token IDs use the root task ULID,
  providing lexicographic sortability by creation time and
  cryptographic randomness (80 bits from `crypto/rand`).

### 7.2 Delegation Certificates

Delegation certificates authorize the broker to derive macaroon root
keys for task trees. They use a canonical JSON format signed by the
root CA:

```
  Payload (deterministic JSON with sorted keys):
  {
    "broker_id":  "broker-01",
    "cert_id":    "a1b2c3d4...",
    "expires_at": 1741872000,
    "issued_at":  1741868400,
    "public_key": "<base64 Ed25519 public key bytes>"
  }

  Signature: Ed25519(canonical_json_bytes)
```

**Deterministic serialization:** The payload is serialized with
`json.Marshal` over a `map[string]interface{}` with sorted keys. This
ensures that signature verification produces the same byte sequence
regardless of the platform.

**Lifecycle:**
1. Broker generates ephemeral Ed25519 keypair
2. Broker sends public key to signer via `sign_delegation` IPC
3. Signer validates broker UID (SO_PEERCRED), applies TTL cap
   (maximum 24 hours), signs canonical payload
4. Broker stores cert and private key in memory
5. Token issuer updated to use new signing key
6. Rotation occurs every 50 minutes (default)

### 7.3 Validation Chain

Every macaroon task token is validated through a multi-step chain:

```
  Serialized Macaroon Token
       |
  [1] Deserialize binary format (version check, bounds checks)
       |
  [2] Extract root task ULID from macaroon Id()
      Look up root key from broker's key store
       |                                  -----> REJECT: "unknown task
       |                                          root key"
  [3] Verify HMAC chain:
      sig = HMAC(root_key, id)
      for each caveat:
        sig = HMAC(sig, caveat)
      Compare final sig to token sig ----> REJECT: "invalid signature"
       |
  [4] Run effective envelope reducer:
      Walk caveats, apply set intersection,
      minimum, AND, earliest rules ------> REJECT: "empty dimension"
       |
  [5] Check expiry caveat (expires < now) -> REJECT: "token expired"
       |
  [6] Check revocation watermarks
      (lineage walk) --------------------> REJECT: "task revoked"
       |
  [7] Return ReducerOutput (envelope + metadata)
```

Steps 2-3 form the cryptographic trust chain: the broker derives the
root key from the delegation key, and the HMAC chain proves that every
caveat was legitimately added. If any caveat is removed, reordered, or
modified, the HMAC chain breaks and verification fails.

### 7.4 Identity URN Scheme

Agent identity in task tokens uses a URN scheme (embedded as a caveat)
that encodes the authentication method:

| Authentication Method | Identity URN |
|----------------------|--------------|
| Local Unix socket (SO_PEERCRED) | `ephyr:local:uid:1000` |
| MCP API key | `ephyr:apikey:ak_claud` (first 6 chars of agent name) |

This allows audit consumers to distinguish between co-located agents
(authenticated via kernel UID verification) and remote agents
(authenticated via bcrypt API keys), which have different trust properties.

### 7.5 ULID Task Identifiers

Task IDs use ULIDs (Universally Unique Lexicographically Sortable
Identifiers) -- 128-bit identifiers encoded as 26 Crockford Base32
characters:

```
  01JQXYZ1234567890ABCDEFGH
  |------||----------------|
  48-bit    80-bit crypto
  Unix ms   random (crypto/rand)
  timestamp
```

**Properties:**
- Lexicographic sort order matches creation time
- Collision probability: 2^(-80) per millisecond (80 bits of randomness)
- Crockford Base32 excludes I, L, O, U (reduces visual ambiguity)
- Timestamp component enables extraction of creation time without
  database lookup (`ULIDTime()`)
- 26-character string is shorter than UUID (36 characters) while
  providing better sortability

**Implementation detail:** Ephyr implements ULID generation natively
(no external dependency) using `crypto/rand` for the random component,
ensuring cryptographic-quality randomness.

### 7.6 Ephyr Bind (v0.3)

Ephyr Bind (v0.3 tier) extends bearer macaroon tokens with holder
binding via DPoP-style proof-of-possession.

**Holder binding mechanism:**
- Each task generates an ephemeral Ed25519 keypair
- The public key is embedded as a caveat in the macaroon
- Each request includes a proof-of-possession signature over a
  challenge (nonce + timestamp + body_hash)
- The broker verifies that the presenter holds the corresponding
  private key

**Security properties Bind provides:**

- **Holder binding:** A stolen token is useless without the holder's
  private key. The token is cryptographically bound to the agent
  process that created it.
- **Body integrity:** The `body_hash` field in the PoP proof binds
  each request to its specific payload, preventing request body
  tampering by intermediaries.
- **Replay prevention:** A nonce cache at the broker rejects duplicate
  proof presentations. Combined with short TTLs, this eliminates
  replay attacks.
- **Two-phase delegation:** The delegating parent never sees the
  child's private key. The parent mints a token with a placeholder,
  and the child binds it to its own keypair. This prevents the parent
  from impersonating the child.
- **BindDeadline auto-revocation:** Unbound tokens (minted but not
  yet bound to a holder key) are automatically revoked after a
  configurable deadline, preventing orphaned unbound tokens from
  accumulating.

**What Bind does NOT provide:**

- Protection against a compromised agent runtime (the private key
  lives in agent process memory; a compromised runtime can extract it)
- TLS channel binding (Bind operates at the application layer, not
  the transport layer)
- Protection against a compromised broker (the broker verifies proofs
  but also holds the macaroon root key)

---

## 8. Revocation

### 8.1 Epoch Watermark Model

Traditional revocation approaches (CRLs, OCSP) maintain a list of every
revoked credential. This is O(n) in the number of revocations and
requires distribution of revocation lists to validators.

Ephyr uses epoch watermarks: when a task is revoked, its ID is recorded
with a timestamp. Any token whose `iat` (issued-at) is at or before the
watermark for any task in its lineage is considered revoked.

```
  Revocation Map:
  +----------+--------------------------+
  | Task ID  | Revoked At               |
  +----------+--------------------------+
  | 01JQABC  | 2026-03-10T14:30:00.000Z |
  | 01JQDEF  | 2026-03-10T14:35:00.000Z |
  +----------+--------------------------+

  Token validation:
    For each task_id in token.lineage:
      if revocationMap[task_id].revokedAt >= token.iat:
        REJECT (token issued before or at revocation time)
```

### 8.2 Lineage-Walk Validation

When checking a token for revocation, the `RevocationMap` walks the
token's entire lineage array:

```go
func (r *RevocationMap) CheckLineage(lineage []string, issuedAt time.Time) error {
    r.mu.RLock()
    defer r.mu.RUnlock()
    for _, taskID := range lineage {
        if watermark, ok := r.watermarks[taskID]; ok {
            if !issuedAt.After(watermark) {
                return fmt.Errorf("task %s was revoked at %s", taskID, watermark)
            }
        }
    }
    return nil
}
```

This is O(depth), where depth is the number of ancestors in the task
hierarchy. In practice, task hierarchies are shallow (typically fewer
than 5 levels), making the check nearly constant-time.

### 8.3 Cascading Revocation

Because tokens carry their full lineage (from root task to leaf), revoking
a parent task automatically invalidates all child tokens. No explicit
enumeration of children is required:

```
  Root Task A ─────> Child B ─────> Grandchild C
  (ULID: 01JQ001)   (ULID: 01JQ002) (ULID: 01JQ003)

  Lineage of C: ["01JQ001", "01JQ002", "01JQ003"]

  Revoking A (watermark: 01JQ001 -> now):
    - Token for A: lineage[0] is revoked -> REJECTED
    - Token for B: lineage[0] is revoked -> REJECTED
    - Token for C: lineage[0] is revoked -> REJECTED

  All descendants invalidated with a single map entry.
```

### 8.4 Background Garbage Collection

The `RevocationMap` runs a background goroutine every 60 seconds that
removes watermarks older than the maximum task TTL. Once
`watermark_time + maxTTL` has passed, any token issued before the
watermark has already expired naturally -- the watermark is no longer
needed.

```
  GC cycle:
    cutoff = now - maxTaskTTL
    for each (taskID, watermark) in map:
      if watermark < cutoff:
        delete(taskID)
```

This ensures the revocation map size is bounded by the number of
revocations within one maxTTL window (default 1 hour), not by the total
historical revocation count.

### 8.5 Comparison with Traditional Approaches

| Property | CRL | OCSP | Epoch Watermark |
|----------|-----|------|-----------------|
| Storage growth | O(total revocations) | O(1) per check | O(active revocations) |
| Distribution | Push CRL to all validators | Real-time query per check | Local map, no distribution |
| Cascading revocation | Must enumerate all children | Must enumerate all children | Automatic via lineage walk |
| Offline operation | Yes (cached CRL) | No (requires responder) | Yes (local map) |
| GC complexity | Manual CRL trimming | N/A | Automatic (TTL-based) |
| Latency | File read | Network round-trip | HashMap lookup |

The epoch watermark model is particularly well-suited to Ephyr's use case
because task tokens are short-lived (minutes to hours) and hierarchical.
The combination of automatic cascading and TTL-based garbage collection
keeps the revocation map small and fast.

---

## 9. Audit and Correlation

### 9.1 Task-Scoped Audit

Every operation in Ephyr is logged to `/var/log/ephyr/audit.json` as
newline-delimited JSON. Each entry includes the agent name, task ID (when
available), target, role, and a details map with operation-specific context.

Key event types:

| Event Type | Severity | Description |
|------------|----------|-------------|
| `startup` | INFO | Broker started with configuration summary |
| `shutdown` | INFO | Broker shutting down |
| `cert_issued` | INFO | SSH certificate signed and delivered |
| `cert_denied` | WARN | Certificate request rejected by policy |
| `cert_pending` | INFO | Certificate request awaiting approval |
| `cert_revoked` | WARN | Certificate revoked (manual or auto-duplicate) |
| `session_start` | INFO | Agent session created |
| `rate_limited` | WARN | Request rejected by rate limiter |
| `policy_reload` | INFO | Policy hot-reloaded via SIGHUP |
| `host_toggle` | WARN | Host enabled/disabled via dashboard |
| `mcp_exec` | INFO | Command executed via MCP tool |
| `mcp_session_create` | INFO | Persistent SSH session opened |
| `mcp_session_close` | INFO | Persistent SSH session closed |
| `http_proxy` | INFO | HTTP request proxied to service |
| `http_proxy_denied` | WARN | HTTP proxy request rejected by policy |
| `task_create` | INFO | New task created with CTT-E token |
| `task_revoke` | WARN | Task revoked (watermark set) |
| `anomaly_detected` | ALERT | Anomalous behavior detected |

### 9.2 Lineage Tracking

When task identity is enabled, every audit entry includes the task ID
and its lineage. This allows security teams to reconstruct the complete
chain of operations from a root task to any leaf operation:

```json
{
  "timestamp": "2026-03-10T14:30:00Z",
  "severity": "INFO",
  "event_type": "mcp_exec",
  "agent": "claude",
  "target": "web-server",
  "role": "read",
  "details": {
    "task_id": "01JQXYZ...",
    "command": "df -h",
    "exit_code": "0",
    "duration_ms": "245"
  }
}
```

Queries like "show me every operation performed by task 01JQXYZ and
its subtasks" become simple log filters. This is critical for incident
response: if a task produces unexpected behavior, the full execution
history can be reconstructed from the audit log.

### 9.3 Structured Logging

All audit entries follow a consistent schema:

```go
type AuditEvent struct {
    Severity  Severity          // INFO, WARN, ERROR, ALERT
    EventType string            // event category
    Agent     string            // agent name
    Target    string            // target host or service
    Role      string            // SSH role
    Serial    string            // certificate serial (hex)
    Duration  string            // certificate TTL
    Reason    string            // policy decision reason
    Details   map[string]string // operation-specific key-value pairs
}
```

JSON format is chosen for machine parseability -- logs can be ingested
directly by SIEM systems, Grafana Loki, Elasticsearch, or any JSON-line
compatible log aggregator.

Logrotate manages 30-day retention with automatic rotation.

### 9.4 Real-Time Event Hub

All audit events are simultaneously broadcast via WebSocket to connected
dashboard clients. The event hub uses a non-blocking send pattern with
a 64-message buffer per client:

```
  Audit Event
       |
       +---> audit.json (file, append-only)
       |
       +---> WebSocket Hub
              |
              +---> Dashboard Client 1 [buffer: 64 msgs]
              +---> Dashboard Client 2 [buffer: 64 msgs]
              +---> Dashboard Client N [buffer: 64 msgs]
```

If a client falls behind (buffer full), messages are dropped rather than
blocking the broker. This provides a real-time secondary audit trail --
an attacker who compromises the broker and truncates the audit file
cannot retroactively erase events that were already delivered to
connected dashboard clients.

**Keep-alive:** 30-second ping, 60-second pong timeout.

### 9.5 Activity Ring Buffer

A 10,000-entry circular buffer provides fast in-memory analytics without
the overhead of database queries:

- **O(1) insert** -- constant-time regardless of buffer size
- **Bounded memory** -- oldest entries silently overwritten on wrap
- **Filterable queries** -- agent, type, target, service, time range,
  errors-only
- **Per-agent statistics** -- totals, last active time, error rates
- **Dashboard integration** -- top targets, top services, recent entries

The ring buffer is complementary to the audit log. The audit log is the
authoritative record; the ring buffer provides fast operational queries
for the dashboard.

---

## 10. Cryptographic Choices

### 10.1 Ed25519 for All Signing Operations

Every asymmetric signing operation in Ephyr uses Ed25519 (Edwards-curve
Digital Signature Algorithm over Curve25519):

- Root CA certificate signing
- Delegation certificate signing
- Ephemeral SSH keypair generation

Task tokens use HMAC-SHA256 (symmetric) for their caveat chain. The
macaroon implementation is bespoke — written from scratch using only
Go's standard library `crypto/hmac` and `crypto/sha256` packages (~300
lines in `internal/macaroon/types.go`). No external macaroon library
(e.g., `gopkg.in/macaroon.v2`) is used. This keeps the dependency
count at three and the cryptographic surface area auditable. The binary
serialization format (version 0x02) is a custom length-prefixed
encoding, not the standard macaroon V2 wire format. See Section 7.1
for details.

**Why Ed25519:**

| Property | Benefit |
|----------|---------|
| Fixed key size (32 bytes) | No key size decisions; immune to "small key" misconfigurations |
| Deterministic signatures | No random nonce required; eliminates nonce-reuse catastrophes (cf. Sony PS3 ECDSA) |
| Constant-time operations | Immune to timing side-channels by design |
| Fast verification (~70us) | Suitable for per-request token validation on hot paths |
| Universal SSH support | OpenSSH 6.5+ supports Ed25519; no compatibility issues on modern systems |
| Compact signatures (64 bytes) | Minimal overhead in delegation certificates and SSH certificates |

**What was NOT chosen:**

- **RSA-2048/4096:** Larger keys, slower operations, more complex
  implementation surface. No advantage for this use case.
- **ECDSA (P-256):** Requires random nonce per signature; nonce reuse
  reveals the private key. EdDSA's deterministic nonces eliminate this
  risk class entirely.
- **Post-quantum (ML-DSA/Dilithium):** Ephyr's short token lifetimes
  (minutes) and ephemeral keys mean harvest-now-decrypt-later is not a
  meaningful threat. Post-quantum signatures are dramatically larger
  (2-4KB) and would significantly increase token size for no practical
  benefit at this time.

### 10.2 bcrypt for API Key Storage

MCP API keys are stored as bcrypt hashes with cost factor 10:

```go
hash, err := bcrypt.GenerateFromPassword([]byte(key), bcrypt.DefaultCost)
```

**Why bcrypt over alternatives:**

| Algorithm | Resistance | Reason for/against |
|-----------|-----------|-------------------|
| bcrypt (chosen) | GPU-resistant, adaptive cost | Standard library support in Go (`x/crypto`); well-understood; cost factor adjustable |
| Argon2id | Memory-hard, GPU-resistant | Superior for password storage, but Go's `x/crypto` bcrypt is sufficient for API keys; Argon2 requires additional tuning parameters (memory, iterations, parallelism) |
| scrypt | Memory-hard | Harder to tune correctly; bcrypt is simpler and adequate |
| SHA-256 | Not key-stretching | Insufficient; fast hashes enable brute-force at billions of attempts per second |

bcrypt's ~100ms cost per comparison also provides implicit rate limiting
on authentication attempts -- an attacker sending high volumes of invalid
keys consumes significant CPU, which is observable via monitoring.

### 10.3 SHA-256 for Auth Cache Keys

The auth cache keys API key fingerprints using SHA-256:

```go
func apiKeyFingerprint(apiKey string) string {
    h := sha256.Sum256([]byte(apiKey))
    return hex.EncodeToString(h[:])
}
```

SHA-256 is used here exclusively as a cache key derivation function --
it is not used for authentication. The security requirement is
collision resistance (different API keys should produce different cache
keys), not brute-force resistance. SHA-256 provides 128-bit collision
resistance, which is more than sufficient.

### 10.4 ULID for Task Identifiers

ULIDs were chosen over UUIDs for task identification:

| Property | UUID v4 | ULID |
|----------|---------|------|
| Sortability | Random (no natural order) | Lexicographic = chronological |
| Encoding | 36 chars (hex + hyphens) | 26 chars (Crockford Base32) |
| Timestamp extractable | No | Yes (48-bit millisecond precision) |
| Randomness | 122 bits | 80 bits |
| Database index performance | Poor (random inserts) | Good (monotonic inserts) |

The 80-bit randomness component (from `crypto/rand`) provides adequate
collision resistance for Ephyr's use case -- tasks are created at human
time scales (seconds to minutes apart), not at high-frequency machine
rates.

### 10.5 Random Value Generation

All random values in Ephyr are generated using `crypto/rand.Read`,
which reads from the operating system's CSPRNG (`/dev/urandom` on Linux).
No math/rand is used anywhere in the codebase for security-relevant values.

| Value | Size | Format | Purpose |
|-------|------|--------|---------|
| Session tokens | 256 bits (32 bytes) | Hex (64 chars) | Agent session authentication |
| Certificate serials | 64 bits (8 bytes) | Hex (16 chars) | SSH certificate identity |
| Request IDs | 128 bits (16 bytes) | Hex (32 chars) | Request correlation |
| Grant IDs | 128 bits (16 bytes) | Hex (32 chars) | Access grant identity |
| ULID randomness | 80 bits (10 bytes) | Crockford Base32 | Task ID entropy |
| Delegation cert IDs | 128 bits (16 bytes) | Hex (32 chars) | Delegation cert identity |

---

## 11. Network Security

### 11.1 UID-Based nftables Isolation

The recommended deployment model places agents on the same host as the
broker, with nftables rules preventing direct backend access:

```
  # Reference nftables rules for agent isolation

  table inet ephyr {
    chain output {
      type filter hook output priority 0; policy accept;

      # Allow broker (UID 999) unrestricted outbound
      meta skuid 999 accept

      # Block agent UIDs from reaching backend networks
      meta skuid 1000 ip daddr 192.168.0.0/16 reject
      meta skuid 1000 ip daddr 10.0.0.0/8 reject
      meta skuid 1000 ip daddr 172.16.0.0/12 reject

      # Allow loopback for all
      oifname "lo" accept
    }
  }
```

**Why UID-based rules:** Process-level network isolation without
containers, namespaces, or VMs. The kernel matches the UID of the
process creating each outbound connection. An agent running as UID 1000
is blocked from TCP connections to any RFC 1918 address -- all
infrastructure access must flow through the broker's Unix socket.

**Limitations:** UID-based nftables only works when agents are co-located
on the broker host. Remote agents connecting via MCP over TCP are
constrained solely by broker policy. The nftables rules provide defense-
in-depth for the co-located deployment model, but the broker's policy
engine is the authoritative enforcement point for all agents.

### 11.2 Credential Injection Model

Agents never see infrastructure credentials. The broker injects
credentials into outbound requests on the agent's behalf:

```
  Agent Request:                   Broker Sends:
  POST http://gitea/api/v1/repos   POST http://gitea/api/v1/repos
  (no auth headers)                 Authorization: token ghp_xxx...
                                    (credential from services.json)
```

**Injection modes:**

| Auth Type | How Credentials Are Injected |
|-----------|------------------------------|
| `bearer` | `Authorization: Bearer {credential}` header |
| `basic` | HTTP Basic Auth header (base64-encoded `user:pass`) |
| `header` | Custom header with optional prefix (e.g., `X-API-Key: {prefix}{credential}`) |
| `query` | URL query parameter (e.g., `?api_key={credential}`) |
| `none` | No credentials injected (passthrough) |

**Header protection:** Agent-supplied headers cannot override injected
authentication headers. If a service uses bearer auth, the agent cannot
set its own `Authorization` header -- the broker's injected value takes
precedence. This prevents agents from redirecting credentials to
unintended destinations.

**Redaction:** Credentials are masked in all API responses (`"***"`),
audit logs, and dashboard displays. The only location where plaintext
credentials exist is `/var/lib/ephyr/services.json` and the broker's
process memory.

### 11.3 CIDR Allow/Deny Policy

The HTTP proxy enforces a network policy that controls which destinations
agents can reach:

```yaml
# /var/lib/ephyr/network_policy.json
{
  "allow_cidrs":    ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"],
  "deny_cidrs":     ["192.168.10.0/24"],
  "external":       "deny",
  "external_allow": ["*.github.com"]
}
```

**Evaluation order:**
1. Deny CIDRs checked first -- any match is an immediate reject
2. For private IPs (RFC 1918): must match at least one allow CIDR
3. For public IPs: governed by the `external` mode:
   - `deny` -- all public IPs blocked (default)
   - `restricted` -- only hostnames matching `external_allow` glob
     patterns permitted
   - `open` -- all destinations allowed (not recommended)

**All resolved IPs must pass.** When a hostname resolves to multiple
IP addresses, every resolved IP is checked against the policy. A hostname
that resolves to both a private and a public IP is rejected if the public
IP fails the external policy.

### 11.4 DNS Resolution Security

DNS resolution uses a 2-second timeout via Go's `net.DefaultResolver`:

```go
ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
defer cancel()
addrs, err := net.DefaultResolver.LookupHost(ctx, hostname)
```

If the input is already an IP address (detected via `net.ParseIP`), DNS
resolution is skipped entirely. This prevents DNS rebinding attacks
where a hostname initially resolves to an allowed IP but later resolves
to a restricted IP.

---

## 12. Hardening Guide

### 12.1 Systemd Sandboxing Directives

The following table summarizes all systemd security directives applied to
the signer and broker services:

| Directive | Signer | Broker | Effect |
|-----------|--------|--------|--------|
| `ProtectSystem=strict` | Yes | Yes | Read-only filesystem |
| `ProtectHome=yes` | Yes | Yes | Home directories invisible |
| `NoNewPrivileges=yes` | Yes | Yes | No setuid escalation |
| `PrivateTmp=yes` | Yes | Yes | Isolated /tmp |
| `PrivateDevices=yes` | Yes | Yes | No /dev access |
| `ProtectKernelTunables=yes` | Yes | Yes | Read-only /proc/sys |
| `ProtectKernelModules=yes` | Yes | Yes | No module loading |
| `ProtectControlGroups=yes` | Yes | Yes | Read-only cgroups |
| `RestrictSUIDSGID=yes` | Yes | Yes | No SUID/SGID bits |
| `RestrictNamespaces=yes` | Yes | Yes | No namespace creation |
| `CapabilityBoundingSet=` | Yes | Yes | All capabilities dropped |
| `SystemCallFilter=@system-service` | Yes | Yes | Allowlisted syscalls |
| `SystemCallArchitectures=native` | Yes | Yes | Only native arch syscalls |
| `MemoryDenyWriteExecute=yes` | Yes | No | No W+X memory mappings |
| `RestrictAddressFamilies=AF_UNIX` | Yes | No | Unix sockets only |
| `RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6` | No | Yes | Unix + TCP |
| `ProtectHostname=yes` | Yes | No | Cannot change hostname |
| `RestrictRealtime=yes` | Yes | No | No RT scheduling |
| `LockPersonality=yes` | Yes | No | Cannot change exec domain |
| `ReadOnlyPaths=/etc/ephyr` | Yes | No | CA key read-only |
| `ReadWritePaths=/run/ephyr` | Yes | Yes | Socket directory |
| `ReadWritePaths=/var/log/ephyr` | No | Yes | Audit log |
| `ReadWritePaths=/var/lib/ephyr` | No | Yes | Configuration |

### 12.2 Production Deployment Recommendations

Ordered by impact:

**Critical:**

1. **Deploy on a dedicated host.** Run the signer and broker on a
   dedicated host (VM, LXC container, bare metal, or cloud instance) with
   no other workloads. This ensures systemd sandboxing is the primary
   isolation layer, not one among many. Co-location with the agent is
   supported but weakens the trust boundary -- the agent process can
   potentially access broker memory or Unix sockets if it escalates
   privileges.

2. **Enable host key verification.** The default SSH client uses
   `InsecureIgnoreHostKey`. Until host key pinning is implemented in
   policy, ensure the network path between the broker and all targets
   is trusted (same VLAN, no untrusted L2 neighbors). This is the
   highest-priority item to address. **These are prioritized for
   immediate remediation and are the most likely blockers for
   enterprise adoption.**

3. **Enable TLS verification for services.** The HTTP proxy uses
   `InsecureSkipVerify: true`. Deploy proper TLS certificates or a
   private CA for internal services. Place a TLS-terminating reverse
   proxy in front of the dashboard and MCP ports. **Like T6 above,
   this is prioritized for the next release cycle.**

**High:**

4. **Configure nftables for co-located agents.** Apply UID-based rules
   to block direct agent-to-backend traffic.

5. **Rotate MCP API keys regularly.** Treat API keys as time-limited
   credentials. Rotate quarterly and immediately on suspected compromise.

6. **Ship audit logs externally.** Forward `/var/log/ephyr/audit.json`
   to a SIEM or append-only log store. This bounds the tamper window
   for audit manipulation.

7. **Set `external: "deny"` in network policy.** Never allow unrestricted
   public internet access from the proxy.

**Standard:**

8. **Keep certificate TTLs short.** The 5-minute default is appropriate.
   Resist the temptation to increase TTLs for convenience.

9. **Use dedicated role accounts on targets.** Configure `agent-read`
   (rbash, no sudo), `agent-op` (bash, limited sudo), and `agent-admin`
   (bash, scoped sudo). Never map agent principals to root.

10. **Back up the CA key securely.** Store an offline, encrypted backup.
    Loss requires re-provisioning all targets.

### 12.3 Target Host Hardening

Ephyr provides a target provisioning script (`deploy/scripts/provision-target.sh`)
that configures:

**Role accounts:**

| Account | Shell | Sudo | Purpose |
|---------|-------|------|---------|
| `agent-read` | `/usr/bin/rbash` | None | Read-only operations |
| `agent-op` | `/bin/bash` | Limited (systemctl status, docker ps/logs, monitoring) | Operational tasks |
| `agent-admin` | `/bin/bash` | Extended (systemctl start/stop, docker run/exec, apt list) | Administrative tasks |

**Sudoers deny list (all roles):**
- Shell interpreters (bash, sh, zsh, fish)
- Text editors (vi, vim, nano, emacs)
- Language interpreters (python, perl, ruby, node)
- Package management mutations (apt install/remove, dpkg -i)
- Dangerous commands (chattr, visudo, su, passwd, usermod, chmod, chown)

**Sudoers file protection:** The generated sudoers file is validated
via `visudo -c` and then made immutable with `chattr +i`.

**SSH configuration:**
- `TrustedUserCAKeys` points to the Ephyr CA public key
- `AuthorizedPrincipalsFile` maps role accounts to SSH principals
- sshd configuration is validated before applying

### 12.4 Monitoring and Alerting

Ephyr exposes Prometheus-compatible metrics at `GET /metrics`:

**Latency histograms** (7 buckets from <100us to >50ms):
- `ephyr_token_sign_seconds` -- CTT-E token signing
- `ephyr_token_validate_seconds` -- CTT-E token validation
- `ephyr_watermark_check_seconds` -- Revocation check
- `ephyr_envelope_check_seconds` -- Capability envelope check
- `ephyr_policy_eval_seconds` -- Policy pipeline evaluation
- `ephyr_ssh_cert_seconds` -- SSH certificate signing (IPC)
- `ephyr_delegation_ipc_seconds` -- Delegation IPC
- `ephyr_exec_e2e_seconds` -- End-to-end exec latency

**Counters:**
- `ephyr_tasks_created_total`, `ephyr_tokens_signed_total`,
  `ephyr_tokens_validated_total`, `ephyr_tokens_rejected_total`
- `ephyr_watermark_revocations_total`, `ephyr_delegation_rotations_total`
- `ephyr_auth_cache_hits_total`, `ephyr_auth_cache_misses_total`

**Gauges:**
- `ephyr_tasks_active`, `ephyr_active_watermarks`
- `ephyr_delegation_cert_age_seconds`, `ephyr_delegation_certs_held`

**Recommended alerts:**
- `ephyr_tokens_rejected_total` increasing rapidly (brute-force attempt)
- `ephyr_delegation_cert_age_seconds > 3600` (delegation rotation failed)
- `ephyr_ssh_cert_seconds` p99 > 1s (signer IPC latency degradation)
- `ephyr_auth_cache_misses_total` spike (cache invalidation or new keys)

---

## 13. Comparison with Existing Solutions

### 13.1 SPIFFE/SPIRE

SPIFFE (Secure Production Identity Framework for Everyone) and its
reference implementation SPIRE provide workload identity through X.509
SVIDs (SPIFFE Verifiable Identity Documents).

| Aspect | SPIFFE/SPIRE | Ephyr |
|--------|-------------|--------|
| Identity model | X.509 SVIDs with SPIFFE IDs (URIs) | SSH certificates with principal-based roles |
| Agent identity | Workload attestation (k8s, AWS, process) | SO_PEERCRED UID verification (Linux) |
| Certificate format | X.509 | OpenSSH user certificates |
| Signing architecture | Server with upstream CAs, nested topology | Two-process (signer + broker), single CA |
| Token support | JWT-SVIDs | HMAC-SHA256 macaroons with caveat chain (CTT-E/CTT-D) |
| Policy model | Registration entries + RBAC | YAML policy with 8-step evaluation pipeline |
| Target integration | mTLS between workloads | SSH `TrustedUserCAKeys` on target hosts |
| Operational complexity | High (control plane, agents, registration API) | Low (two systemd services, one YAML file) |
| AI agent focus | General-purpose workload identity | Purpose-built for AI agent access patterns |
| HTTP proxy | No built-in credential injection | Built-in proxy with 5 auth types |
| MCP integration | None | Native MCP server with 10+ tools |

**When to choose SPIFFE/SPIRE:** Large-scale, multi-cluster environments
where workload-to-workload mTLS is the primary requirement. Kubernetes-native
environments with existing SPIRE infrastructure.

**When to choose Ephyr:** AI agent infrastructure where SSH access,
HTTP credential injection, and MCP tool federation are the primary
requirements. Environments where operational simplicity and minimal
dependencies are valued.

### 13.2 HashiCorp Vault SSH Secrets Engine

Vault's SSH secrets engine can operate in signed certificate mode,
issuing short-lived SSH certificates from a CA key stored in Vault.

| Aspect | Vault SSH Engine | Ephyr |
|--------|-----------------|--------|
| CA key storage | Vault's encrypted storage backend (Shamir/auto-unseal) | Dedicated signer process with systemd sandbox |
| Certificate issuance | REST API with Vault token | MCP tool call or Unix socket API |
| Policy model | Vault policies + SSH role configuration | YAML policy with 8-step pipeline + RBAC |
| Credential injection | Vault Agent sidecar can inject secrets | Built-in HTTP proxy with transparent injection |
| Agent identity | Vault auth methods (AppRole, k8s, etc.) | SO_PEERCRED or bcrypt API keys |
| Task correlation | Via Vault audit log entity/alias | ULID task IDs with hierarchical lineage |
| Revocation | Vault lease revocation (per-credential) | Epoch watermark (cascading, O(depth)) |
| Operational overhead | Vault cluster (HA requires 3+ nodes) | Two systemd services on one host |
| Dependencies | Vault server + storage backend + auth backend | Go binary + 3 libraries |
| AI agent integration | REST API (no MCP support) | Native MCP server |

**When to choose Vault:** Organizations already running Vault for secrets
management, where SSH certificate issuance is one of many secret types.
Environments requiring HSM-backed key storage (Vault supports PKCS#11).

**When to choose Ephyr:** Dedicated AI agent access broker where MCP
integration, task-scoped audit, and credential injection are critical.
Environments that value minimal operational overhead.

### 13.3 Traditional PAM and SSH Key Management

| Aspect | Traditional SSH Keys | Ephyr |
|--------|---------------------|--------|
| Key lifecycle | Permanent (until manually rotated) | Ephemeral (5-minute default TTL) |
| Credential storage | `.ssh/authorized_keys` on each host | CA public key on hosts; no per-agent keys |
| Access revocation | Remove key from each host (O(hosts)) | Policy change or watermark (O(1)) |
| Audit | sshd log (IP + user) | Structured JSON with task ID, agent, role |
| Blast radius | Full host access for key lifetime | Scoped to role + target + TTL |
| Agent identity | SSH key fingerprint | UID-verified identity with task lineage |
| Scaling | O(agents x hosts) key distribution | O(hosts) CA key distribution |
| Credential rotation | Manual, error-prone | Automatic (ephemeral per-request) |

### 13.4 Summary Matrix

```
                    |  SPIFFE/SPIRE  |  Vault SSH  |  PAM/Keys  |  Ephyr
  ──────────────────|────────────────|─────────────|────────────|──────────
  AI agent focus    |      No        |     No      |     No     |   Yes
  MCP integration   |      No        |     No      |     No     |   Yes
  HTTP proxy        |      No        |    Partial  |     No     |   Yes
  Ephemeral certs   |     Yes        |     Yes     |     No     |   Yes
  Task lineage      |      No        |     No      |     No     |   Yes
  Cascading revoke  |      No        |     No      |     No     |   Yes
  Credential inject |      No        |    Partial  |     No     |   Yes
  Operational cost  |     High       |    Medium   |     Low    |   Low
  Dependencies      |     High       |    Medium   |     None   |  Minimal
```

---

## 14. Known Limitations and Future Work

### 14.1 Current Limitations

**Single-tenant architecture.** Ephyr is designed for single-tenant
deployment. All agents, targets, and services are governed by one policy
file and one CA key. Multi-tenant environments must deploy separate
Ephyr instances. There is no built-in mechanism for cross-instance
trust or delegation.

**No external IdP federation.** Agent identity is established via
SO_PEERCRED (UID) or bcrypt API keys. There is no integration with
OIDC providers, SAML IdPs, or LDAP directories. Environments requiring
centralized identity management must provision agent UIDs and API keys
out-of-band.

**No X.509 interop.** Ephyr issues OpenSSH certificates exclusively.
It cannot issue X.509 client certificates for mTLS workflows. Workloads
requiring X.509 identity should use SPIFFE/SPIRE or a traditional PKI
alongside Ephyr.

**SSH host key verification disabled.** The broker's SSH client uses
`InsecureIgnoreHostKey`, making SSH connections vulnerable to
man-in-the-middle attacks. This is the most significant known security
gap (see Threat T6 in the threat model).

**TLS certificate verification disabled.** The HTTP proxy and MCP
federation client use `InsecureSkipVerify: true`, making HTTPS
connections vulnerable to interception (see Threat T7).

**Credentials stored in plaintext.** Service credentials
(`/var/lib/ephyr/services.json`) and federated MCP server credentials
(`/var/lib/ephyr/remotes.json`) are stored as plaintext JSON.
File permissions (0600) are the sole protection.

**Dashboard token is static.** The dashboard uses a single static token
with no automatic rotation, session expiry, or concurrent session limits.

**No push revocation for SSH certificates.** OpenSSH does not support
online CRL checking for user certificates. Revocation is effective only
at the broker level -- a certificate that has already been delivered
remains valid on the target until its TTL expires.

**MCP API keys are bearer tokens.** No secondary authentication factor
(mTLS, OIDC) is supported on the MCP TCP endpoint. A stolen API key
grants full access for the impersonated agent's policy scope.

**Task tokens are bearer tokens.** Macaroon task tokens (CTT-E/CTT-D)
are bearer credentials until Ephyr Bind is implemented. Any entity
possessing a serialized token can present it to the broker. Short TTLs
and epoch watermark revocation mitigate replay risk, but do not
eliminate it. Specifically, bearer tokens do not provide:

- Protection against a compromised agent runtime replaying the token
- Body integrity (the token does not bind to a specific request body)
- TLS channel binding (not implemented)

These limitations are addressed by Ephyr Bind (Section 7.6).

### 14.2 Planned Improvements

| Improvement | Addresses | Priority |
|-------------|-----------|----------|
| SSH host key pinning in policy.yaml | T6 (SSH MITM) | Critical |
| Per-service TLS CA configuration | T7 (HTTPS MITM) | High |
| Credential encryption at rest | T10 (plaintext creds) | High |
| mTLS client certificates for MCP | T1 (API key theft) | Medium |
| OIDC authentication option | T1 (API key threat) | Medium |
| Remote audit log shipping | T11 (log tampering) | Medium |
| Log entry signing (HMAC/Ed25519) | T11 (log tampering) | Medium |
| WebSocket message-based auth | T9 (dashboard token leak) | Medium |
| Per-agent rate limiting on MCP TCP | T12 (DoS) | Medium |
| Ephyr Bind (holder-bound tokens via DPoP-style PoP) | Bearer token replay, body integrity | Medium |
| `RevokedKeys` file distribution | T5 (target-side revocation) | Low |

### 14.3 Research Directions

**Confidential computing.** Running the signer in a TEE (Trusted
Execution Environment) such as AMD SEV-SNP or Intel TDX would protect
the CA key even against root-level compromise of the host OS. This
would address the residual risk in Threat T4 (signer compromise via
host root access).

**Post-quantum transition.** While not urgent for short-lived tokens,
a migration path to ML-DSA (FIPS 204) or SLH-DSA (FIPS 205) should be
planned for the CA key, which is long-lived and could be targeted by
harvest-now-decrypt-later attacks against the signed certificates.

**Formal verification.** The policy engine's 8-step pipeline and the
token validation chain are amenable to formal verification using
tools like TLA+ or Alloy. This would provide mathematical guarantees
about the absence of policy bypass paths.

**Hardware-backed key storage.** Integration with TPM 2.0 or PKCS#11
HSMs for the root CA key would eliminate the file-based key storage
risk entirely. The signer could load the key from a hardware token
at startup without it ever existing in a regular file.

---

## 15. Appendix A: Trust Boundary Diagram

```
 ┌───────────────────────────────────────────────────────────────────────────┐
 │  EPHYR HOST (dedicated VM, container, bare metal, or cloud instance)    │
 │                                                                           │
 │  ┌─────────────────┐                                                     │
 │  │  SIGNER          │   Trust Boundary B1                                │
 │  │  (UID: signer)   │   ───────────────────                              │
 │  │                   │                                                    │
 │  │  - Ed25519 CA key │   Protections:                                    │
 │  │  - AF_UNIX ONLY   │   - SO_PEERCRED (broker UID only)                │
 │  │  - No TCP/UDP/raw │   - MemoryDenyWriteExecute                       │
 │  │  - CapBound=empty │   - SystemCallFilter=@system-service             │
 │  │  - W^X enforced   │   - ProtectSystem=strict                         │
 │  │                   │   - RestrictAddressFamilies=AF_UNIX              │
 │  └────────┬──────────┘                                                   │
 │           │ /run/ephyr/signer.sock                                      │
 │           │ (one-shot JSON, UID-verified)                                │
 │  ┌────────┴──────────────────────────────────────────────────────────┐   │
 │  │  BROKER (UID: 999)                Trust Boundary B2               │   │
 │  │  ──────────────────────────────────────────────────────           │   │
 │  │                                                                   │   │
 │  │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐            │   │
 │  │  │ Policy   │ │ Session  │ │  Token   │ │ Audit    │            │   │
 │  │  │ Engine   │ │ Manager  │ │  Issuer  │ │ Logger   │            │   │
 │  │  └──────────┘ └──────────┘ └──────────┘ └──────────┘            │   │
 │  │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐            │   │
 │  │  │ Exec     │ │ Proxy    │ │ Revoc.   │ │ Grant    │            │   │
 │  │  │ Pool     │ │ Engine   │ │ Map      │ │ Store    │            │   │
 │  │  └──────────┘ └──────────┘ └──────────┘ └──────────┘            │   │
 │  │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐            │   │
 │  │  │ MCP      │ │ Deleg.   │ │ Task     │ │ Activity │            │   │
 │  │  │ Server   │ │ Manager  │ │ Manager  │ │ Ring Buf │            │   │
 │  │  └──────────┘ └──────────┘ └──────────┘ └──────────┘            │   │
 │  │                                                                   │   │
 │  │  Listeners:                                                       │   │
 │  │    /run/ephyr/broker.sock (Unix, SO_PEERCRED) ─── B0: Agent CLI │   │
 │  │    :8553 (TCP, token auth) ─────────────────────── B5: Dashboard  │   │
 │  │    :8554 (TCP, bcrypt API key) ─────────────────── B0r: MCP      │   │
 │  └──────┬──────────────┬──────────────┬──────────────────────────────┘   │
 │         │              │              │                                   │
 └─────────│──────────────│──────────────│───────────────────────────────────┘
           │              │              │
      ┌────┴────┐   ┌────┴────┐   ┌────┴──────┐
      │  SSH    │   │  HTTP   │   │  Remote   │
      │  Targets│   │Services │   │  MCP      │
      │  (B3)   │   │  (B4)   │   │ Servers   │
      │         │   │         │   │  (B5)     │
      └─────────┘   └─────────┘   └───────────┘
```

**Boundary descriptions:**
- **B0:** Agent CLI to Broker -- Unix socket, SO_PEERCRED UID verification
- **B0r:** Remote Agent to Broker -- TCP :8554, bcrypt API key
- **B1:** Broker to Signer -- Unix socket, SO_PEERCRED UID restriction
- **B2:** Broker internal -- all components share the broker process
- **B3:** Broker to Target Hosts -- SSH with ephemeral certificates
- **B4:** Broker to HTTP Services -- HTTP/HTTPS with credential injection
- **B5:** Broker to Remote MCP / Dashboard to Admin -- TCP with auth

---

## 16. Appendix B: Threat Enumeration Summary

| ID | Threat | Severity | Boundary | Mitigation Status |
|----|--------|----------|----------|-------------------|
| T1 | Agent credential theft (API key) | High | B0r | Mitigated (bcrypt); residual (bearer token, no 2FA) |
| T2 | Agent session hijacking | Medium | B0 | Mitigated (ownership check per operation) |
| T3 | Broker compromise | Critical | B2 | Mitigated (CA key isolated in signer); residual (service creds exposed) |
| T4 | Signer compromise (CA key theft) | Critical | B1 | Mitigated (systemd sandbox, no network); residual (root host access) |
| T5 | Target compromise via active session | Medium | B3 | Mitigated (5-min TTL); residual (no push revocation) |
| T6 | SSH man-in-the-middle | Critical | B3 | **OPEN** -- `InsecureIgnoreHostKey` |
| T7 | HTTPS man-in-the-middle | High | B4/B5 | **OPEN** -- `InsecureSkipVerify: true` |
| T8 | Network bypass (agent direct access) | Medium | B0 | Mitigated (nftables UID rules for co-located agents) |
| T9 | Dashboard token leakage | Medium | B5 | Partially mitigated (constant-time compare, privacy mode) |
| T10 | Credential exposure at rest | High | -- | Partially mitigated (file permissions); residual (plaintext JSON) |
| T11 | Audit log tampering | Medium | -- | Partially mitigated (append-only, WebSocket secondary); residual (no signing) |
| T12 | Denial of service | Medium | B0r | Partially mitigated (rate limiting, bcrypt cost); residual (no per-agent MCP limits) |
| T13 | Task token replay (bearer theft) | Medium | B2 | Partially mitigated (TTL + watermark); residual (bearer semantics until Bind) |
| T14 | Compromised agent runtime | High | B0 | Not mitigated -- agent holds token and can replay it. Bind limits exposure but cannot prevent extraction from same-process memory |

---

## 17. Appendix C: Dependency Analysis

Ephyr maintains a minimal dependency footprint. The entire project
(~33,000 lines of Go, including 377 tests and 2 fuzz tests) depends on
only three external libraries:

```
module github.com/EphyrAI/Ephyr

go 1.24.1

require (
    github.com/gorilla/websocket v1.5.3
    golang.org/x/crypto v0.48.0
    gopkg.in/yaml.v3 v3.0.1
)

require golang.org/x/sys v0.41.0 // indirect
```

| Dependency | Purpose | Risk Assessment |
|------------|---------|-----------------|
| `gorilla/websocket` | Dashboard WebSocket event hub and terminal | Mature, widely-used library. WebSocket-only; no HTTP routing or middleware attack surface. |
| `golang.org/x/crypto` | bcrypt (API key hashing), SSH (certificate signing, client) | Official Go extended library. Maintained by the Go team. Used for all cryptographic operations. |
| `gopkg.in/yaml.v3` | Policy file parsing | Mature YAML parser. Used only at startup and SIGHUP reload. Not on the hot path. |
| `golang.org/x/sys` | Indirect dependency of x/crypto (syscall support) | Official Go extended library. |

**No dependency on:**
- HTTP routing frameworks (standard library `net/http` used directly)
- JSON libraries (standard library `encoding/json`)
- Logging frameworks (standard library `log`)
- Database drivers (all state is in-memory or flat files)
- Container runtimes or orchestrators
- Cloud provider SDKs

This minimal dependency surface significantly reduces supply chain risk.
The project can be audited by reading approximately 33,000 lines of Go
plus the four dependencies listed above.

---

## Document Information

| Field | Value |
|-------|-------|
| Project | Ephyr -- Secure Agent Access Broker |
| Version | 0.3 |
| Codebase | ~33,000 lines of Go (377 tests, 2 fuzz tests) |
| License | Apache 2.0 |
| Repository | https://github.com/EphyrAI/Ephyr |
| Last Updated | March 2026 |
| Classification | Public |

---

*This document describes the security architecture of Ephyr as implemented
in version 0.3. It is intended as a reference for security teams evaluating
the project. For deployment instructions, see `docs/deployment.md`. For
API reference, see `docs/api-reference.md`. For the full threat model, see
`docs/THREAT_MODEL.md`.*
