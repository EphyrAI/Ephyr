# Clauth Security Model

## Overview

Clauth's security model is built on defense in depth: multiple independent
layers of authentication, authorization, and isolation work together so that
the failure of any single layer does not compromise the system. The CA private
key -- the crown jewel -- is isolated in a process with no network access,
and every operation is logged to an append-only audit trail.

---

## Threat Model

| Assumption | Rationale |
|------------|-----------|
| Agents are semi-trusted | Authenticated but constrained; may be manipulated by prompt injection |
| Internal network is hostile | Lateral movement assumed; VLANs are advisory, not absolute |
| CA key is the highest-value target | Compromise means forging certificates for any host |
| Broker compromise must not yield CA key | Process isolation + Unix socket UID restriction |
| Individual hosts may be compromised | Short-lived certificates limit blast radius |
| Credentials leak through logs/APIs | All sensitive values are masked or redacted |

**Adversary tiers:**
1. **Unprivileged local user** -- can reach broker socket if in `clauth-agents`
   group, but cannot impersonate another UID (SO_PEERCRED is kernel-enforced)
2. **Compromised agent** -- has a valid session and can request certs within
   policy limits, but cannot exceed rate limits, role boundaries, or caps
3. **Network attacker** -- can reach TCP ports 8553/8554 but requires the
   dashboard token or a valid bcrypt API key to authenticate

---

## Authentication Layers

### 1. Unix Socket: SO_PEERCRED (Kernel-Verified UID)

Primary authentication for CLI/agent API. The kernel populates a `ucred`
structure via `getsockopt(SO_PEERCRED)` with the connecting process's UID,
GID, and PID. This is unforgeable from userspace -- it comes from the kernel
process table. Verified on every connection, injected into HTTP request context.

Used by both the broker (to identify agents) and the signer (to restrict
callers to broker UID 999 only).

### 2. Session Tokens: 256-bit Random

After UID verification, agents call `POST /v1/session`. The broker generates
a 32-byte token via `crypto/rand.Read` (CSPRNG), returned as 64-char hex.

- One active session per agent (new session invalidates old token)
- Cross-checked: session UID must match connection SO_PEERCRED UID
- Masked in whoami: `token[:8]...token[-8:]`

### 3. Dashboard Token: Constant-Time Comparison

TCP dashboard (`:8553`) protected by static token (set via systemd override).
Compared with `crypto/subtle.ConstantTimeCompare` to prevent timing attacks.
Static files exempt from auth. Token masked in audit logs: `first4...last4`.

### 4. MCP API Keys: bcrypt-Hashed

MCP server (`:8554`) authenticates via `X-API-Key` header. Keys stored as
bcrypt hashes in policy YAML (default cost 10). `bcrypt.CompareHashAndPassword`
is inherently constant-time per comparison.

### 5. SSH Certificates: Ed25519 Chain of Trust

Certificates signed by the CA key, verified by target OpenSSH via
`TrustedUserCAKeys`. Short-lived (default 5m, max 30m policy, 24h hard cap).
Principals restrict which OS user the cert authenticates as. Serials are
cryptographically random (8 bytes from `crypto/rand`).

---

## Authorization Model

### Policy Structure (`/etc/clauth/policy.yaml`)

Four sections: `global` (cluster limits), `agents` (per-agent identity/caps),
`roles` (role-to-principal mappings), `targets` (hosts with access rules).
Hot-reload via SIGHUP without restart.

### 8-Step Evaluation Pipeline

Every certificate request passes through these steps in order:

| Step | Check | Failure |
|------|-------|---------|
| 1 | Agent exists by UID | `unknown agent UID` |
| 2 | Target exists in policy | `unknown target` |
| 3 | Role in target's `allowed_roles` | `role not allowed on target` |
| 4 | Duration clamped to min(requested, target max, global max) | *(silent clamp)* |
| 5 | Agent concurrent certs < `max_concurrent_certs` | `at concurrent cert limit` |
| 6 | Duplicate agent+target+role check | *(auto-revokes old cert)* |
| 7 | Global active certs < `max_active_certs` | `global limit reached` |
| 8 | Auto-approve check | Approve or Pending |

Expired certs are purged before evaluation so stale entries do not affect
concurrency counts.

### Rate Limiting

Per-UID sliding window: 10 requests per 60 seconds (configurable). Applied
as HTTP middleware. Denied requests get HTTP 429 with `Retry-After` header.

### Host Access Toggles

Runtime enable/disable per host without modifying policy. Toggling off denies
new requests immediately. Dashboard toggle also revokes all active certs for
that host. State is in-memory (resets on restart).

---

## Credential Protection

### HTTP Proxy Injection

The proxy injects credentials on behalf of agents -- the agent specifies a
URL and the proxy matches it against configured services, silently adding auth:

| Auth Type | Injection |
|-----------|-----------|
| `bearer` | `Authorization: Bearer {credential}` |
| `basic` | HTTP Basic Auth (base64 encoded) |
| `header` | Custom header with optional prefix |
| `query` | Query parameter (e.g., `?api_key=...`) |
| `none` | No credentials (passthrough) |

Agent-supplied headers cannot override injected auth headers.

### Redaction

| Context | Method |
|---------|--------|
| Host config API | Credential fields replaced with `"***"` |
| Dashboard token in logs | Masked to `first4...last4` |
| Session whoami | Token masked to `[:8]...[-8:]` |
| MCP cert listing | Raw certificate excluded |
| Proxy service listing | Credential field `"***"` |

### Dashboard Privacy Mode

- SensitiveField: auto-hides after 5 seconds
- CanvasSecret: renders tokens on canvas (not text-selectable)
- Visibility blur: page blurs on tab switch
- Print CSS: hides sensitive content in print media

---

## Systemd Hardening

### Shared Directives (Both Services)

| Directive | Effect |
|-----------|--------|
| `ProtectSystem=strict` | Filesystem read-only except explicit paths |
| `ProtectHome=yes` | Home directories invisible |
| `NoNewPrivileges=yes` | Cannot escalate via setuid/capabilities |
| `PrivateTmp=yes` | Isolated /tmp namespace |
| `PrivateDevices=yes` | No /dev access |
| `ProtectKernelTunables=yes` | /proc/sys, /sys read-only |
| `ProtectKernelModules=yes` | Cannot load kernel modules |
| `RestrictNamespaces=yes` | Cannot create namespaces |
| `CapabilityBoundingSet=` | All capabilities dropped |
| `SystemCallFilter=@system-service` | Allowlisted syscalls only |
| `SystemCallErrorNumber=EPERM` | Blocked syscalls return EPERM |

### Signer-Specific

| Directive | Effect |
|-----------|--------|
| `MemoryDenyWriteExecute=yes` | No W+X memory (blocks shellcode) |
| `RestrictAddressFamilies=AF_UNIX` | No TCP/UDP/raw -- Unix only |
| `ReadWritePaths=/run/clauth` | Socket directory only |

### Broker-Specific

| Directive | Effect |
|-----------|--------|
| `RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6` | Unix + TCP |
| `ReadWritePaths=/run/clauth /var/log/clauth /var/lib/clauth` | Socket, logs, config |

---

## Network Security

### Signer: Zero Network

`RestrictAddressFamilies=AF_UNIX` blocks all TCP/UDP/raw socket creation at
the kernel level. Communication exclusively via Unix socket.

### Broker Socket

Path `/run/clauth/broker.sock`, permissions 0660, group `clauth-agents`.
Only members of the group can connect. SO_PEERCRED identifies every caller.

### HTTP Proxy Network Policy

| Parameter | Default | Description |
|-----------|---------|-------------|
| `allow_cidrs` | RFC 1918 ranges | Allowed private IP destinations |
| `deny_cidrs` | *(empty)* | Blocked CIDRs (checked first) |
| `external` | `"deny"` | Public IP access mode |
| `external_allow` | *(empty)* | Hostname globs for restricted mode |

DNS resolved with 2-second timeout. All resolved IPs must pass policy.

External modes: `deny` (block all public), `restricted` (allow-list only),
`open` (all allowed, not recommended).

### Host Firewall (nftables)

Default-drop input policy on the Clauth LXC:
- Allow SSH + dashboard (8553) + MCP (8554) from `192.168.0.0/16`
- Allow established/related + loopback
- Drop everything else

---

## Cryptographic Choices

### Ed25519 Everywhere

CA signing key, agent keypairs, MCP ephemeral keys, and certificates all use
Ed25519. Chosen for fixed key size (32 bytes), fast operations, timing-attack
resistance, and universal OpenSSH support.

### Random Values (all via `crypto/rand`)

| Value | Size | Format |
|-------|------|--------|
| Session tokens | 32 bytes (256 bits) | Hex (64 chars) |
| Certificate serials | 8 bytes (64 bits) | Hex (16 chars) |
| Request IDs | 16 bytes (128 bits) | Hex (32 chars) |
| Exec session IDs | 16 bytes (128 bits) | Hex (32 chars) |

### Hashing

- **MCP API keys:** bcrypt (`golang.org/x/crypto/bcrypt`, cost 10)
- **Dashboard token:** `crypto/subtle.ConstantTimeCompare`

---

## Audit and Compliance

### Audit Log (`/var/log/clauth/audit.json`)

Newline-delimited JSON, every security-relevant operation logged.

Key event types: `startup`, `shutdown`, `cert_issued`, `cert_denied`,
`cert_pending`, `cert_approved`, `cert_revoked`, `session_start`,
`rate_limited`, `policy_reload`, `host_toggle`, `mcp_exec`,
`mcp_session_create`, `mcp_session_close`, `http_proxy`,
`http_proxy_denied`, `anomaly_detected`.

Each entry includes: timestamp, severity (INFO/WARN/ERROR/ALERT), event type,
agent, target, role, serial, duration, reason, and arbitrary details map.

Logrotate: 30-day retention, automatic rotation.

### Activity Ring Buffer

10,000-entry circular buffer for real-time analytics. O(1) insert, filterable
queries (agent, type, target, service, time range, errors-only). Per-agent
statistics track totals, last active time, and error rates. Dashboard
integration provides top-targets, top-services, and recent entries.

### WebSocket Event Hub

All events broadcast to connected dashboard clients. 64-message buffer per
client with non-blocking send (slow clients have events dropped). 30-second
ping keepalive, 60-second pong timeout.

---

## Recommendations for Production

**Key management:** Rotate the CA key periodically. Back up securely (GPG
offline). Never copy the CA key to any other system.

**Agent isolation:** Use separate OS users per agent for true UID isolation.
Restrict shells (rbash), deny sudo/cron/at, apply process limits.

**Network:** Keep nftables active with default-drop. Use VLAN segmentation.
Keep proxy `external: "deny"` unless explicitly needed.

**Certificate hygiene:** Keep TTLs aggressive (5m default is appropriate).
Disable auto-approve for sensitive targets. Monitor audit logs for unusual
target requests, rate-limit spikes, off-hours activity, and repeated denials.

**Operations:** Review the activity dashboard regularly. Use host toggles
during maintenance. Hot-reload policy via SIGHUP (`systemctl reload
clauth-broker`). Test policy changes with the unit tests (`engine_test.go`,
`sprawl_test.go`) before production.
