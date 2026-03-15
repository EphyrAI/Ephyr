# Ephyr Threat Model

## Introduction

Ephyr is a privileged access broker for AI agents. It issues ephemeral SSH certificates, proxies authenticated HTTP requests, and federates remote MCP tool servers -- all governed by declarative policy, audited per-action, and mediated through a single MCP endpoint. Agents never hold long-lived infrastructure secrets.

This document enumerates the trust boundaries in the system, catalogs known threats against each boundary, describes current mitigations, and is honest about residual risks and planned improvements. It is intended for security reviewers evaluating Ephyr for production deployment.

**Scope:** The broker, signer, and CLI processes; the MCP, dashboard, and proxy interfaces; credential storage; and the audit subsystem. Target host hardening, OS-level controls, and application-layer security on managed hosts are explicitly out of scope (see [Out of Scope](#what-is-explicitly-out-of-scope)).

---

## System Overview

Ephyr is split into three processes, each running with minimum required privileges:

| Process | Role | Privileges |
|---------|------|------------|
| **ephyr-signer** | Holds Ed25519 CA private key, signs certificates | No network access (AF_UNIX only), MemoryDenyWriteExecute, all capabilities dropped |
| **ephyr-broker** | Policy engine, MCP server, HTTP proxy, dashboard, audit | TCP listeners (dashboard :8553, MCP :8554), Unix socket IPC to signer and CLI |
| **ephyr** (CLI) | Agent-side tool, communicates via Unix socket | Runs as agent's OS user, authenticated by SO_PEERCRED |

The broker mediates three proxy paths:

1. **SSH execution** -- Broker generates an ephemeral Ed25519 keypair in memory, requests a signed certificate from the signer, connects to the target host, executes the command, and returns results. The agent never sees the certificate or private key.
2. **HTTP proxy** -- Broker matches the requested URL against configured services, injects stored credentials (bearer, basic, header, or query parameter), forwards the request, and returns the response. The agent never sees the injected credentials.
3. **MCP federation** -- Broker proxies JSON-RPC tool calls to remote MCP servers, injecting credentials as needed. Remote tools appear namespaced (e.g., `server.tool`) through the broker's single MCP endpoint.

### Trust Boundary Diagram

```
 ┌─────────────────────────────────────────────────────────────────────┐
 │  BROKER HOST (dedicated VM, container, bare metal, or cloud)        │
 │                                                                     │
 │  ┌──────────────┐    Unix socket     ┌───────────────────────────┐ │
 │  │              │   (SO_PEERCRED)    │                           │ │
 │  │   Signer     │◄──────[B1]────────►│        Broker             │ │
 │  │  (CA key)    │  /run/ephyr/      │  ┌─────────┐             │ │
 │  │  AF_UNIX only│  signer.sock       │  │ Policy  │             │ │
 │  └──────────────┘                    │  │ Engine  │             │ │
 │                                       │  └─────────┘             │ │
 │                                       │  ┌─────────┐             │ │
 │  ┌──────────────┐    Unix socket     │  │ Proxy   │             │ │
 │  │  Agent CLI   │◄──────[B0]────────►│  │ Engine  │             │ │
 │  │  (co-located)│  /run/ephyr/      │  └─────────┘             │ │
 │  └──────────────┘  broker.sock       │  ┌─────────┐             │ │
 │        │                              │  │  MCP    │             │ │
 │        │ nftables UID-based           │  │ Server  │             │ │
 │        │ blocks direct access         │  └─────────┘             │ │
 │        ▼                              │                           │ │
 │  ┌──────────────┐                    └──────┬──────┬──────┬──────┘ │
 │  │   BLOCKED    │                      TCP  │      │      │        │
 └──│──────────────│──────────────────────────-│──────│──────│────────┘
    └──────────────┘                           │      │      │
                                               │      │      │
         ┌──────────────────[B2]───────────────┘      │      │
         │ SSH (ephemeral certs)                      │      │
         ▼                                            │      │
 ┌───────────────┐     ┌──────────────────[B3]────────┘      │
 │ Target Hosts  │     │ HTTP (credential injection)         │
 │ (SSH + CA     │     ▼                                     │
 │  trust)       │ ┌──────────────┐               [B4]──────┘
 └───────────────┘ │ HTTP Services│               │
                   │ (Gitea, etc.)│               ▼
                   └──────────────┘     ┌────────────────┐
                                        │ Remote MCP     │
 ┌──────────────┐                       │ Servers        │
 │ Admin        │──────[B5]────────►    └────────────────┘
 │ (Dashboard)  │  TCP :8553
 └──────────────┘  Token auth
                                        ┌────────────────┐
 ┌──────────────┐                       │ MCP Endpoint   │
 │ Remote Agent │──────[B0r]───────►    │ TCP :8554      │
 │ (MCP client) │  API key auth         │ (bcrypt keys)  │
 └──────────────┘                       └────────────────┘
```

**Boundary Key:**
- **B0** -- Agent (CLI) to Broker: Unix socket, SO_PEERCRED UID verification
- **B0r** -- Remote Agent to Broker: TCP :8554, API key (bcrypt-hashed)
- **B1** -- Broker to Signer: Unix socket, SO_PEERCRED UID restriction (broker UID only)
- **B2** -- Broker to Target Hosts: SSH with ephemeral Ed25519 certificates
- **B3** -- Broker to HTTP Services: HTTP/HTTPS with credential injection
- **B4** -- Broker to Remote MCP Servers: JSON-RPC over HTTP, credential injection
- **B5** -- Admin to Dashboard: TCP :8553, static token auth

---

## Trust Boundaries

### B0 / B0r: Agent to Broker

**Co-located agents (Unix socket):** The CLI connects to `/run/ephyr/broker.sock` (permissions 0660, group `ephyr-agents`). The kernel provides the caller's UID, GID, and PID via `SO_PEERCRED` -- this is unforgeable from userspace. The broker maps the UID to a registered agent in policy. Rate limiting is enforced per-UID (default: 10 requests / 60 seconds). Session tokens (256-bit, `crypto/rand`) provide a second factor after initial UID verification.

**Remote agents (MCP over TCP):** Agents connect to `:8554` via HTTP POST. Authentication is via `X-API-Key` header, compared against bcrypt hashes stored in policy YAML (default cost 10). `bcrypt.CompareHashAndPassword` is inherently constant-time.

### B1: Broker to Signer

The signer listens on `/run/ephyr/signer.sock`. It extracts `SO_PEERCRED` from every connection and rejects any UID that does not match `EPHYR_BROKER_UID` (999 in production). The signer's systemd unit restricts address families to `AF_UNIX` -- it cannot open TCP, UDP, or raw sockets. Communication uses a one-shot newline-delimited JSON protocol (not persistent connections).

### B2: Broker to Target Hosts

The broker generates an ephemeral Ed25519 keypair in memory, requests a signed certificate from the signer (scoped to a specific agent, target, role, and TTL), and establishes an SSH connection to the target. The private key exists only in process memory and is never written to disk. Certificates default to 5-minute TTL with a 30-minute per-target maximum and a 24-hour hard cap enforced by the signer. Targets validate certificates via `TrustedUserCAKeys` and map principals to OS users.

### B3: Broker to HTTP Services

The proxy engine resolves the target URL's DNS (2-second timeout), evaluates CIDR allow/deny policy, matches the URL against configured service prefixes, and injects stored credentials. Agent-supplied headers cannot override injected authentication headers. Network policy defaults to RFC 1918 private ranges only; external access requires explicit hostname allowlist entries.

### B4: Broker to Remote MCP Servers

The broker proxies JSON-RPC 2.0 tool calls to federated MCP servers, injecting any configured credentials. Remote tools are auto-discovered via the MCP handshake (`initialize` then `tools/list`) with periodic background refresh and exponential backoff on failures. Each remote server's tools are namespaced to prevent collision.

### B5: Admin to Dashboard

The dashboard at `:8553` is protected by a static token compared with `crypto/subtle.ConstantTimeCompare`. CORS is restricted to same-origin. Static assets (CSS, JS) are exempt from auth. The dashboard provides operational controls including certificate revocation, host/service/remote toggle, and policy inspection.

---

## Threat Categories

### T1: Agent Credential Theft

**Threat:** An attacker obtains a valid MCP API key and impersonates an agent.

| Aspect | Detail |
|--------|--------|
| **Current mitigation** | API keys are stored as bcrypt hashes in policy YAML -- the plaintext key is never stored on the broker. bcrypt comparison is inherently constant-time. |
| **Residual risk** | API keys are bearer tokens. A stolen key grants full access for the impersonated agent's policy scope. There is no IP binding, client certificate requirement, or secondary authentication factor on the MCP TCP endpoint. |
| **Planned** | mTLS client certificates; OIDC/JWT authentication for environments that need stronger agent identity assurance. |

### T2: Agent Session Hijacking

**Threat:** An agent uses another agent's persistent SSH session to execute commands on a target.

| Aspect | Detail |
|--------|--------|
| **Current mitigation** | Persistent sessions are tracked by agent identity (UID for co-located agents, API key identity for MCP agents). `session_close` and command execution on a persistent session validate that the requesting agent owns the session. Sessions idle for 5 minutes are automatically cleaned up. |
| **Residual risk** | No known bypass. Session ownership is enforced at the broker level on every operation. |

### T3: Broker Compromise

**Threat:** An attacker gains code execution within the broker process.

| Aspect | Detail |
|--------|--------|
| **Current mitigation** | The CA private key is isolated in the signer process. The signer restricts callers to broker UID 999 via `SO_PEERCRED`, has no network access (`AF_UNIX` only), and runs with `MemoryDenyWriteExecute`, all capabilities dropped, and a syscall allowlist. An attacker in the broker process cannot extract the CA key. |
| **Residual risk** | An attacker with broker code execution can: (1) request certificates from the signer within policy constraints, (2) read plaintext credentials in `/var/lib/ephyr/services.json`, (3) read plaintext credentials for federated MCP servers in `/var/lib/ephyr/remotes.json`, (4) read or truncate audit logs, (5) modify host/service/remote state, (6) sign arbitrary CTT-E task tokens using the in-memory delegation key. The attacker is still bounded by policy (the signer enforces duration caps and principal restrictions independently), but has full access to all configured backend credentials and can forge task tokens within the delegation certificate's validity period. |
| **Planned** | Credential encryption at rest with a derived key. Remote audit log shipping so the tamper window is bounded. |

### T4: Signer Compromise

**Threat:** An attacker obtains the Ed25519 CA private key.

| Aspect | Detail |
|--------|--------|
| **Current mitigation** | The key file is owned by the signer service user with permissions 0600. The signer process runs with `ProtectSystem=strict`, `MemoryDenyWriteExecute`, `NoNewPrivileges`, `CapabilityBoundingSet=` (empty), `RestrictAddressFamilies=AF_UNIX`, and `SystemCallFilter=@system-service`. It cannot be reached over the network. |
| **Residual risk** | An attacker with root access on the broker host can read `/etc/ephyr/ca_key` directly, bypassing all process isolation. With the CA key, an attacker can forge certificates for any principal on any target that trusts this CA -- the blast radius is the entire set of hosts with `TrustedUserCAKeys` pointing to this CA. |
| **Planned** | HSM or TPM-backed key storage (long-term). Key rotation tooling with automated `TrustedUserCAKeys` rollover on targets. |

### T5: Target Host Compromise via Active Session

**Threat:** An attacker compromises a managed target host and abuses currently-valid SSH certificates or active persistent sessions.

| Aspect | Detail |
|--------|--------|
| **Current mitigation** | Certificates default to 5-minute TTL. Persistent sessions idle-timeout after 5 minutes. Principals restrict which OS user the certificate authenticates as. Target-side sudoers rules and shell restrictions (rbash for read-only roles) limit what a compromised certificate can do. Duplicate certificates for the same agent+target+role are auto-revoked when a new one is issued. |
| **Residual risk** | An active certificate or persistent session can be abused until it expires. During the TTL window, the attacker has whatever access the certificate's principal grants on that host. There is no mechanism to push-revoke a certificate to the target's OpenSSH (OpenSSH does not support online CRL checking for user certificates). |
| **Planned** | Consider `RevokedKeys` file distribution for critical targets. Document forced-command and no-pty best practices for high-security targets. |

### T6: Man-in-the-Middle -- SSH

**Threat:** An attacker intercepts the SSH connection between the broker and a target host.

| Aspect | Detail |
|--------|--------|
| **Current mitigation** | None. The broker uses `ssh.InsecureIgnoreHostKey()` -- **host key verification is disabled**. |
| **Residual risk** | **Full MITM is possible on the SSH channel.** An attacker with network position between the broker and a target host can intercept, modify, or inject commands and responses. The ephemeral certificate and private key would be presented to the attacker's host. This is the most significant known gap in the current implementation. |
| **Planned** | Host key pinning in `policy.yaml` (per-target known host keys). Implement `ssh.FixedHostKey()` or a callback that validates against pinned keys. |

### T7: Man-in-the-Middle -- HTTP/TLS

**Threat:** An attacker intercepts HTTP proxy requests between the broker and backend services.

| Aspect | Detail |
|--------|--------|
| **Current mitigation** | None for TLS verification. The broker's HTTP client is configured with `InsecureSkipVerify: true` for all service connections, and federated MCP server connections also use `InsecureSkipVerify: true`. |
| **Residual risk** | An attacker with network position can intercept credential-injected HTTP requests in transit, capturing bearer tokens, API keys, and response data. This applies to both service proxy requests and federated MCP tool calls. |
| **Planned** | Per-service TLS CA configuration in `services.json`. Option to pin specific certificates or provide a custom CA bundle for internal PKI. A global `InsecureSkipVerify` toggle that defaults to `false`. |

### T8: Network Bypass -- Agent Direct Access

**Threat:** An agent connects directly to backend infrastructure, bypassing the broker's policy and audit controls.

| Aspect | Detail |
|--------|--------|
| **Current mitigation** | When agents run on the broker host, nftables UID-based rules block the agent user from reaching backend IP ranges directly. All traffic must flow through the broker. |
| **Residual risk** | This mitigation only applies to co-located agents. Remote agents connecting via MCP over TCP are constrained solely by broker policy -- if the remote agent's host has network access to backend services, no network-level enforcement prevents direct connections. The broker cannot control what happens outside its host. |
| **Planned** | Document the co-located deployment model as the recommended configuration for maximum isolation. Provide reference nftables rules and deployment guides for both models. |

### T9: Dashboard Token Leakage

**Threat:** The dashboard authentication token is exposed to unauthorized parties.

| Aspect | Detail |
|--------|--------|
| **Current mitigation** | Token comparison uses `crypto/subtle.ConstantTimeCompare` (timing-attack resistant). CORS is restricted to same-origin. Token is masked in audit logs (`first4...last4`). Dashboard implements privacy features: sensitive fields auto-hide after 5 seconds, canvas-rendered secrets (not text-selectable), page blurs on tab switch, and print CSS hides sensitive content. |
| **Residual risk** | The dashboard token is passed as a query parameter in WebSocket upgrade requests, making it visible in server access logs, proxy logs, and browser history. The token is static (does not rotate automatically). There is no session expiry or concurrent session limit for dashboard access. |
| **Planned** | WebSocket message-based authentication (token sent over the established connection, not in the URL). Token rotation support. Session expiry. |

### T10: Credential Exposure at Rest

**Threat:** Stored credentials (API tokens, service passwords) are read by an unauthorized process or after disk theft.

| Aspect | Detail |
|--------|--------|
| **Current mitigation** | `/var/lib/ephyr/services.json` and `/var/lib/ephyr/remotes.json` are owned by the broker service user with permissions 0600. The broker's systemd unit uses `ProtectSystem=strict` and `ReadWritePaths` limited to `/run/ephyr`, `/var/log/ephyr`, and `/var/lib/ephyr`. |
| **Residual risk** | Credentials are stored in plaintext JSON. Any process running as the broker user, or root, can read all stored backend credentials. Disk-level access (physical theft, snapshot, backup) exposes all credentials. MCP API keys are bcrypt-hashed, but service and remote MCP server credentials are not. |
| **Planned** | Encryption at rest using a key derived from a passphrase or hardware token, provided at service startup. Secrets management integration (e.g., HashiCorp Vault) for environments that have it. |

### T11: Audit Log Tampering

**Threat:** An attacker modifies or deletes the audit trail to cover their actions.

| Aspect | Detail |
|--------|--------|
| **Current mitigation** | Audit log (`/var/log/ephyr/audit.json`) is written in append-only mode. It is stored separately from configuration files. Logrotate manages 30-day retention. Events are also broadcast via WebSocket to connected dashboard clients (providing a real-time secondary record). |
| **Residual risk** | The broker process has write access to the audit log file and could truncate or overwrite it if compromised. Logrotated archives on the same filesystem can also be modified. There is no cryptographic integrity protection (signing, hash chaining) on log entries. |
| **Planned** | Log entry signing (HMAC or Ed25519) for tamper detection. Remote log shipping to an external SIEM or append-only log store. |

### T12: Denial of Service

**Threat:** An attacker overwhelms the broker, preventing legitimate agent access.

| Aspect | Detail |
|--------|--------|
| **Current mitigation** | Per-UID rate limiting on the Unix socket API (default: 10 requests / 60 seconds, configurable). bcrypt cost on MCP API key verification provides implicit rate limiting on authentication attempts (each comparison is computationally expensive). Global and per-agent certificate concurrency limits prevent resource exhaustion from certificate accumulation. |
| **Residual risk** | There is no rate limiting on the MCP TCP endpoint for authenticated agents beyond the per-UID Unix socket limits. A compromised API key could be used to flood the broker with tool calls. The dashboard WebSocket endpoint has a 64-message backpressure buffer per client but no connection limit. bcrypt's computational cost, while a defense against brute force, also makes the authentication endpoint itself a CPU exhaustion vector if an attacker sends many invalid keys. |
| **Planned** | Per-agent rate limiting on the MCP endpoint. Connection limits on the dashboard WebSocket. Configurable bcrypt cost with adaptive rate limiting on failed authentication attempts. |

### T13: Auth Cache Poisoning

**Threat:** An attacker manipulates the MCP auth cache to authenticate as a different agent or to extend the validity of a revoked key.

| Aspect | Detail |
|--------|--------|
| **Current mitigation** | Cache entries are keyed on SHA-256(apiKey), which is collision-resistant and irreversible. The cache stores only successful authentication results -- failed attempts are never cached. The entire cache is automatically invalidated when agents are added or removed (e.g., during policy reload). Cache entries are TTL-bounded (default 60 seconds), limiting the staleness window. |
| **Residual risk** | Within the TTL window, a revoked API key could still authenticate from cache. An agent whose `api_key_hash` is updated in policy will retain cached access until the TTL expires or a full policy reload triggers cache invalidation. |
| **Mitigation** | Set `EPHYR_AUTH_CACHE_TTL=0` in environments requiring immediate key revocation. For most deployments, the 60-second default is an acceptable tradeoff between security and performance (bcrypt is ~200ms per comparison). |

### T14: Bearer Token Replay

**Threat:** An attacker intercepts a task token (macaroon or JWT) and replays it to impersonate the original holder.

| Aspect | Detail |
|--------|--------|
| **Current mitigation** | Task tokens have short TTLs (max 1 hour) and are subject to epoch watermark revocation. Revoked tokens are immediately rejected regardless of TTL. TLS protects tokens in transit on the MCP endpoint. Ephyr Bind (v0.3) adds holder-bound tokens with DPoP-style proof-of-possession: each request must include an Ed25519 signature over a nonce, making replayed tokens useless without the holder's private key. |
| **Residual risk** | Bearer-mode tokens (without Bind) can be replayed within their TTL window if intercepted. The bind deadline window (default 30 seconds) during two-phase delegation creates a brief period where a delegated token is in bearer mode. During this window, an attacker with network access could replay the token. |
| **Mitigation** | Use Ephyr Bind (`holder_pub_key` on `task_create`, or `task_bind` for delegated tasks) for sensitive operations. Keep TTLs short. Ensure TLS is used on the MCP endpoint. |

### T15: Bind Deadline Window

**Threat:** During two-phase delegation, a 30-second unbound period exists where the delegated token is in bearer mode, before the child agent calls `task_bind`.

| Aspect | Detail |
|--------|--------|
| **Current mitigation** | The bind deadline defaults to 30 seconds. After the deadline expires, the unbound token becomes permanently invalid (tracked by `ephyr_bind_deadline_expired_total` metric). The short window limits exposure. TLS on the MCP endpoint prevents network interception during this period. |
| **Residual risk** | An attacker who obtains the token during the 30-second window (e.g., from broker memory, logs, or the parent agent's process) could use it before binding occurs. Once the child binds the token, the attacker's copy becomes useless (PoP verification will fail). |
| **Planned** | Configurable bind deadline (allow operators to reduce from 30s). Optional immediate-bind mode where the parent provides the child's public key at delegation time, eliminating the unbound window entirely. |

### T16: Body Tampering Without Bind

**Threat:** An attacker modifies the body of an MCP request in transit, altering tool call arguments (e.g., changing the target host or command in an `exec` call) without the broker detecting the modification.

| Aspect | Detail |
|--------|--------|
| **Current mitigation** | TLS on the MCP endpoint provides integrity protection for requests in transit. Ephyr Bind's PoP signature covers a nonce but does not currently include the request body in the signed payload. The broker validates all tool call arguments against RBAC policy independently, so a modified request must still pass policy evaluation. |
| **Residual risk** | If TLS is not used (e.g., plaintext HTTP on a trusted network), request bodies could be modified in transit. Even with Bind, the PoP signature does not cover the request body, so a MITM with TLS termination capability could modify arguments while preserving the PoP signature. |
| **Planned** | Include a hash of the request body in the PoP signature payload (body binding). This would detect any tampering of tool call arguments. |

### T17: Delegation Key Compromise

**Threat:** An attacker obtains the broker's ephemeral delegation key, enabling them to forge task tokens (macaroons and CTT-E JWTs).

| Aspect | Detail |
|--------|--------|
| **Current mitigation** | The delegation key is an ephemeral Ed25519 keypair generated in-memory at broker startup. It is never written to disk. The delegation certificate (signed by the signer's root CA key) authorizes this key to sign task tokens and has a limited validity period. For macaroons, the attacker would also need the HMAC root key (derived per task tree). Task tokens carry a capability envelope that bounds what they can authorize, and the existing policy pipeline still evaluates every brokered request independently. Holder-bound tokens (Ephyr Bind) provide additional protection: forged tokens without the holder's private key will fail PoP verification. |
| **Residual risk** | An attacker with broker process memory access (e.g., via /proc/pid/mem on a compromised host, or a memory dump) could extract the delegation private key and macaroon root keys, and forge task tokens within the delegation certificate's validity period. These forged tokens would pass signature verification. However, the policy engine still independently evaluates each request, so the forged token cannot exceed the agent's policy-defined permissions. Holder-bound tokens add a further barrier since the attacker would also need the holder's private key. |
| **Planned** | Delegation key rotation on a configurable interval. Shorter delegation certificate lifetimes (currently bounded by the signer's max TTL). Memory protection for the delegation key (mlock). |

---

## What is Explicitly Out of Scope

The following areas are acknowledged but not addressed by Ephyr's threat model:

| Area | Rationale |
|------|-----------|
| **Multi-tenant isolation** | Ephyr is single-tenant by design. All agents are governed by one policy file and one CA. Deployers needing tenant isolation should run separate Ephyr instances. |
| **End-to-end encryption** | Ephyr brokers access, not data. Payload confidentiality between the agent and the target is the responsibility of the transport (SSH provides this; HTTP depends on TLS configuration). |
| **Application-layer security** | What agents do with the access Ephyr grants is beyond Ephyr's control. A `read` role agent that exfiltrates data via allowed commands is an application-layer concern. |
| **Target host OS hardening** | Ephyr delivers the agent to the host with an appropriate SSH principal. The host's sudoers rules, shell restrictions, filesystem permissions, and security frameworks (SELinux, AppArmor) are the deployer's responsibility. **This is the most security-critical deployment decision.** See T18 below and [Target Setup](target-setup.md). |
| **Supply chain security** | Dependency integrity is managed via Go modules with checksums (`go.sum`). Ephyr has minimal dependencies. Build reproducibility and SBOM generation are not currently implemented. |
| **Physical security** | Physical access to the broker host or target hosts is outside Ephyr's threat model. Disk encryption is recommended but not enforced by Ephyr. |

---

## Deployment Recommendations

The following recommendations are derived from the threats enumerated above. They are ordered by impact.

### Critical

1. **Enable host key verification (T6).** The default `InsecureIgnoreHostKey` setting allows full SSH MITM. Until host key pinning is implemented, deployers should ensure the network path between the broker and all target hosts is trusted (e.g., same VLAN, no untrusted L2 neighbors). This is the highest-priority item to address.

2. **Enable TLS verification for services (T7).** Configure proper TLS certificates for internal services or deploy a private CA. Avoid relying on `InsecureSkipVerify` in environments where the network between the broker and services crosses trust boundaries.

3. **Deploy the broker on a dedicated host (T3, T4).** Run the signer and broker on a dedicated host (VM, container, bare metal, or cloud instance) with no other workloads. This limits the attack surface and ensures systemd sandboxing is the primary isolation layer, not one among many.

### High

4. **Use nftables when agents are co-located (T8).** If agents run on the broker host, configure UID-based nftables rules to block direct agent-to-backend traffic. Reference rules should drop all outbound traffic from agent UIDs except to the broker's Unix socket.

5. **Configure TLS termination in front of dashboard and MCP ports (T9, T1).** Place a reverse proxy (nginx, Traefik, Caddy) in front of `:8553` and `:8554` with TLS termination. This protects the dashboard token and MCP API keys in transit.

6. **Rotate MCP API keys regularly (T1).** Treat API keys as time-limited credentials. Rotate them on a schedule (e.g., quarterly) and immediately on suspected compromise. bcrypt hashing means rotation requires only updating the hash in `policy.yaml` and reloading (`SIGHUP`).

7. **Ship audit logs to an external system (T11).** Forward `/var/log/ephyr/audit.json` to a SIEM, syslog aggregator, or append-only object store. This bounds the tamper window to the time between log writes and external collection.

### Standard

8. **Always run signer and broker as separate systemd services (T4).** Never combine them into a single process. The signer's zero-network, minimal-privilege sandbox is the primary defense for the CA key.

9. **Use short certificate TTLs (T5).** The 5-minute default is appropriate for most workloads. Resist the temptation to increase TTLs for convenience -- every additional minute widens the window for certificate abuse after a target compromise.

10. **Use dedicated role accounts on target hosts (T5).** Configure `agent-read` (rbash, no sudo), `agent-op` (bash, limited sudo), and `agent-admin` (bash, scoped sudo) with explicit sudoers allowlists. Never map agent principals to `root`.

11. **Lock down sudoers with explicit command allowlists.** Avoid `ALL` in sudoers rules for agent principals. Enumerate exactly which commands each role needs. Use `NOPASSWD` only for specific commands, not blanket access.

12. **Keep the proxy network policy restrictive (T8).** Leave `external` set to `deny` unless specific external endpoints are required. When external access is needed, use the `external_allow` hostname glob list rather than switching to `open` mode.

13. **Back up the CA key securely (T4).** Store an offline, encrypted backup of `/etc/ephyr/ca_key`. If the key is lost, all targets must be reconfigured with a new CA. If the key is compromised, all targets must remove the old CA from `TrustedUserCAKeys` immediately.

---

## Summary of Known Weaknesses

The following table provides a consolidated view of the most significant residual risks, ordered by severity.

| # | Weakness | Severity | Boundary | Status |
|---|----------|----------|----------|--------|
| 1 | SSH host key verification disabled (`InsecureIgnoreHostKey`) | **Critical** | B2 | Open -- host key pinning planned |
| 2 | TLS certificate verification disabled (`InsecureSkipVerify`) | **High** | B3, B4 | Open -- per-service TLS CA planned |
| 3 | Backend credentials stored in plaintext JSON | **High** | -- | Open -- encryption at rest planned |
| 4 | Dashboard token in WebSocket URL query parameter | **Medium** | B5 | Open -- message-based auth planned |
| 5 | MCP API keys are bearer tokens with no secondary factor | **Medium** | B0r | Open -- mTLS/OIDC planned |
| 6 | No per-agent rate limiting on MCP TCP endpoint | **Medium** | B0r | Open -- planned |
| 7 | Audit logs lack cryptographic integrity protection | **Medium** | -- | Open -- log signing planned |
| 8 | Root on broker host can read CA key | **Low** | B1 | Accepted -- HSM/TPM long-term |
| 9 | No push-revocation for SSH certificates | **Low** | B2 | Accepted -- OpenSSH limitation |
| 10 | Network bypass possible for remote (non-co-located) agents | **Low** | B0r | Accepted -- architectural |
| 11 | Auth cache allows revoked key to authenticate for up to TTL window | **Low** | B0r | Mitigated -- TTL-bounded, auto-invalidation on policy change, disable with TTL=0 |
| 12 | Delegation key in broker memory could be extracted | **Low** | B1 | Accepted -- bounded by delegation cert validity + policy enforcement |
| 13 | Bearer token replay within TTL window | **Medium** | B0r | Mitigated -- short TTLs + watermark revocation; addressed by Ephyr Bind PoP |
| 14 | Bind deadline window (30s unbound period) | **Low** | B0r | Accepted -- TLS protects transit; deadline is configurable; unbound tokens expire |
| 15 | Body tampering without Bind | **Low** | B3 | Mitigated -- TLS provides integrity; PoP body binding enforced for holder-bound tokens via `body_hash` in `_pop` |
| 16 | Target host misconfiguration widens blast radius | **High** | B2 | Operational -- deployer responsibility; provisioning script and docs provided |

### T18: Target Host Misconfiguration

**Threat:** Ephyr controls *who* gets SSH access, *for how long*, and *with which principal*. But the principal maps to a Linux user account on the target host, and that user's capabilities are defined by the target's shell, sudoers rules, filesystem permissions, and security frameworks. A misconfigured target host can silently negate Ephyr's security model.

**Examples of misconfiguration:**
- `agent-read` has `/bin/bash` instead of `/bin/rbash` -- the "read-only" role has full shell access
- `agent-op` has `ALL=(ALL) NOPASSWD: ALL` in sudoers -- the "operator" role is effectively root
- All three role accounts map to the same Linux user -- role separation is meaningless
- Sudoers uses a deny-list instead of an allow-list -- new binaries bypass restrictions
- No `AuthorizedPrincipalsFile` configured -- any valid certificate can authenticate as any user

**Why this matters:** This is the most likely way a deployment weakens the security model without visible indicators. The broker logs will show "role=read, target=webserver" and the policy evaluation will pass, but the agent has full root access because the target's sudoers is misconfigured. Ephyr's audit trail accurately records what Ephyr authorized, but cannot report what the agent actually did on the target beyond the SSH session's stdout/stderr.

**Mitigations:**
- Use the provisioning script (`deploy/scripts/provision-target.sh`) which installs restrictive defaults, validates sudoers with `visudo`, and locks the sudoers file with `chattr +i`
- Use the Ansible playbook (`deploy/ansible/roles/ephyr-target/`) for consistent multi-host provisioning
- Use sudoers allow-lists (explicit command lists), not deny-lists (blocked commands)
- Never map agent principals to `root` or existing admin accounts
- Audit target host configuration periodically -- Ephyr cannot do this for you
- Use `/bin/rbash` for read-only roles (defense-in-depth, not a security boundary)
- Test role capabilities: `ephyr exec target --role read -- sudo -l` shows what the role can actually do

**Residual risk:** **High.** This is outside Ephyr's enforcement boundary by design. The broker issues certificates with the correct principal, but the target host is the final arbiter of what that principal can do. See [Target Setup](target-setup.md) for configuration guidance.

---

## Revision History

| Date | Author | Description |
|------|--------|-------------|
| 2026-03-12 | Initial | Initial threat model based on architecture review |
| 2026-03-14 | Update | Added T14-T16: bearer token replay, bind deadline window, body tampering; renumbered delegation key compromise to T17 |
