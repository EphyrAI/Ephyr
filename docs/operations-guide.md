# Ephyr Operations & Troubleshooting Guide

Production operations reference for the Ephyr agent access broker.
This is the first document to reach for when on-call.

---

## 1. Quick Reference

### Key Paths

| Path | Description |
|------|-------------|
| `/etc/ephyr/ca_key` | Ed25519 CA private key (mode 0600) |
| `/etc/ephyr/policy.yaml` | Policy config (agents, targets, roles, RBAC) |
| `/var/lib/ephyr/services.json` | HTTP proxy service configs (credentials in plaintext) |
| `/var/lib/ephyr/remotes.json` | Federated MCP server configs |
| `/var/lib/ephyr/network_policy.json` | CIDR allow/deny for HTTP proxy |
| `/var/lib/ephyr/hosts.json` | Per-host runtime config (reconciled from policy) |
| `/var/log/ephyr/audit.json` | Audit log (JSON lines, append-only) |
| `/run/ephyr/signer.sock` | Signer IPC Unix socket |
| `/run/ephyr/broker.sock` | Broker Unix socket |
| `/opt/ephyr/` | Source code (Go, git repo) |
| `/usr/local/bin/ephyr-broker` | Broker binary |
| `/usr/local/bin/ephyr-signer` | Signer binary |
| `/usr/local/bin/ephyr` | CLI binary |
| `/etc/systemd/system/ephyr-signer.service` | Signer unit file |
| `/etc/systemd/system/ephyr-broker.service` | Broker unit file |
| `/etc/tmpfiles.d/ephyr.conf` | tmpfiles.d entry for /run/ephyr |

### Ports

| Port | Service | Auth |
|------|---------|------|
| 8553 | Dashboard (HTTP) | Token (`EPHYR_DASHBOARD_TOKEN`) |
| 8554 | MCP server (JSON-RPC 2.0 over HTTP) | API key (bcrypt hash in policy.yaml) |

### Critical Commands

```bash
# Service management
systemctl restart ephyr-signer ephyr-broker   # Full restart (signer first)
systemctl reload ephyr-broker                   # Hot-reload policy.yaml (SIGHUP)
systemctl status ephyr-signer ephyr-broker     # Check both services

# Logs
journalctl -u ephyr-broker -f                   # Follow broker logs
journalctl -u ephyr-signer -f                   # Follow signer logs
journalctl -u ephyr-broker --since "10 min ago" # Recent broker logs
journalctl -u ephyr-signer -u ephyr-broker -n 100  # Last 100 lines, both

# Audit log
tail -f /var/log/ephyr/audit.json | jq .        # Follow audit log (pretty)
tail -20 /var/log/ephyr/audit.json | jq .        # Last 20 events

# Quick health check
curl -s http://localhost:8553/v1/dashboard/status \
  -H "Authorization: Bearer $DASHBOARD_TOKEN" | jq .

# Metrics
curl -s http://localhost:8553/v1/metrics \
  -H "Authorization: Bearer $DASHBOARD_TOKEN"

# MCP health (requires API key)
curl -s -X POST http://localhost:8554/mcp \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <API_KEY>" \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","clientInfo":{"name":"health-check","version":"1.0"}}}'
```

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `EPHYR_POLICY` | (flag: `--policy`) | Path to policy.yaml |
| `EPHYR_SIGNER_SOCKET` | (flag: `--signer-socket`) | Signer Unix socket path |
| `EPHYR_LISTEN` | (flag: `--listen`) | Broker Unix socket path |
| `EPHYR_AUDIT_LOG` | (flag: `--audit-log`) | Audit log file path |
| `EPHYR_DASHBOARD_LISTEN` | `:8553` | Dashboard TCP listen address |
| `EPHYR_DASHBOARD_TOKEN` | (none) | Dashboard authentication token |
| `EPHYR_DASHBOARD_DIR` | embedded | Dashboard static files directory |
| `EPHYR_MCP_LISTEN` | (none) | MCP server TCP listen address (e.g. `:8554`) |
| `EPHYR_ADMIN_UIDS` | `0` | Comma-separated UIDs for admin access |
| `EPHYR_AUTH_CACHE_TTL` | `60s` | Auth cache TTL (0 to disable) |
| `EPHYR_SOCKET_GROUP` | (none) | Group for broker socket permissions |
| `EPHYR_BROKER_UID` | (none) | Broker UID (set in signer unit) |

### System Users and Groups

| User/Group | UID/GID | Purpose |
|------------|---------|---------|
| `ephyr-broker` | 999 | Runs both signer and broker processes |
| `ephyr-agents` | (group) | Socket access group; agent users added here |
| Agent UID | 1000 | Blocked from backend IPs by nftables |

---

## 2. Service Management

### Architecture

Ephyr runs as two cooperating systemd services:

1. **ephyr-signer** -- Holds the CA private key. Accepts delegation and signing
   requests over a Unix socket at `/run/ephyr/signer.sock`. Restricted to
   `AF_UNIX` only (no network access). Must start first.

2. **ephyr-broker** -- Policy engine, MCP server, HTTP proxy, dashboard, and
   audit. Connects to signer via its Unix socket. Listens on TCP ports 8553
   (dashboard) and 8554 (MCP). Handles all agent-facing operations.

Both run as user `ephyr-broker`. The runtime directory `/run/ephyr/` is
managed by `tmpfiles.d` (not `RuntimeDirectory`), configured at
`/etc/tmpfiles.d/ephyr.conf`:

```
d /run/ephyr 0755 ephyr-broker ephyr-agents -
```

The broker unit has `Requires=ephyr-signer.service` and
`After=ephyr-signer.service`, so systemd enforces ordering on normal start.

### Starting Services

```bash
# Normal start (systemd handles ordering)
systemctl start ephyr-signer ephyr-broker

# Enable on boot
systemctl enable ephyr-signer ephyr-broker
```

### Stopping Services

```bash
# Stop broker first, then signer
systemctl stop ephyr-broker ephyr-signer
```

Stopping the signer while the broker is running will cause delegation rotation
and certificate signing to fail. The broker will log errors but remain
running. Active SSH sessions are unaffected until their certificates expire.

### Restarting Services

**Order matters: always restart signer before broker.**

```bash
# Full restart
systemctl restart ephyr-signer ephyr-broker
```

Do NOT restart them in the wrong order. If the broker starts before the signer
socket is ready, the initial delegation request will fail and the broker will
exit with a fatal error.

If you accidentally restarted only the broker and it failed:

```bash
# Check signer is up
systemctl is-active ephyr-signer

# If signer is down, bring both up in order
systemctl restart ephyr-signer && sleep 1 && systemctl restart ephyr-broker
```

### Checking Health

```bash
# Both services should be "active (running)"
systemctl status ephyr-signer ephyr-broker

# Check broker is listening
ss -tlnp | grep -E '855[34]'

# Check Unix sockets exist
ls -la /run/ephyr/

# Dashboard health endpoint
curl -s http://localhost:8553/v1/dashboard/status \
  -H "Authorization: Bearer $DASHBOARD_TOKEN" | jq '.status'

# Check delegation key is valid
curl -s http://localhost:8553/v1/metrics \
  -H "Authorization: Bearer $DASHBOARD_TOKEN" | grep delegation_cert_age
```

### Log Access

```bash
# Follow broker logs (most useful)
journalctl -u ephyr-broker -f

# Follow signer logs
journalctl -u ephyr-signer -f

# Both together
journalctl -u ephyr-signer -u ephyr-broker -f

# Filter by time range
journalctl -u ephyr-broker --since "2026-03-13 10:00:00" --until "2026-03-13 11:00:00"

# Only errors
journalctl -u ephyr-broker -p err

# Structured audit log (separate from journalctl)
# Each line is a complete JSON object
tail -f /var/log/ephyr/audit.json | jq .

# Filter audit log for specific agent
tail -1000 /var/log/ephyr/audit.json | jq 'select(.agent == "claude")'

# Filter audit log for specific event type
tail -1000 /var/log/ephyr/audit.json | jq 'select(.event_type == "cert_issued")'

# Filter for errors and alerts
tail -1000 /var/log/ephyr/audit.json | jq 'select(.severity == "ERROR" or .severity == "ALERT")'

# Count events by type in last N lines
tail -5000 /var/log/ephyr/audit.json | jq -r '.event_type' | sort | uniq -c | sort -rn
```

### Hot-Reload Policy (No Restart)

The broker supports hot-reloading `policy.yaml` via SIGHUP. This reloads
agents, targets, roles, rate limits, and RBAC templates without dropping
connections or clearing state.

```bash
# Hot-reload (preferred for policy changes)
systemctl reload ephyr-broker

# Verify reload succeeded
journalctl -u ephyr-broker --since "1 min ago" | grep -i reload

# Expected log line on success:
# [policy] reloaded policy from /etc/ephyr/policy.yaml (3 targets, 1 agent)
```

What hot-reload does:
- Reloads policy.yaml (agents, targets, roles, RBAC)
- Refreshes the MCP authenticator with updated agent API key hashes
- Re-resolves RBAC permissions for all agents
- Updates rate limiter configuration

What hot-reload does NOT change:
- Dashboard token (requires restart)
- MCP listen address (requires restart)
- Signer socket path (requires restart)
- Audit log path (requires restart)
- Auth cache TTL (requires restart)

If the reload fails (e.g., YAML syntax error), the broker keeps the previous
configuration and logs the error. It does not crash.

---

## 3. Monitoring

### Prometheus Metrics Endpoint

```bash
curl -s http://localhost:8553/v1/metrics \
  -H "Authorization: Bearer $DASHBOARD_TOKEN"
```

The endpoint returns Prometheus exposition format (`text/plain; version=0.0.4`).
Authentication uses the dashboard token.

### Available Metrics

**Latency Histograms** (7 buckets: 100us, 500us, 1ms, 5ms, 10ms, 50ms, +Inf):

| Metric | Description |
|--------|-------------|
| `ephyr_token_sign_seconds` | Task token signing latency (macaroon or legacy CTT-E) |
| `ephyr_token_validate_seconds` | Token validation latency |
| `ephyr_watermark_check_seconds` | Revocation watermark check latency |
| `ephyr_envelope_check_seconds` | Capability envelope check latency |
| `ephyr_policy_eval_seconds` | Policy evaluation latency |
| `ephyr_ssh_cert_seconds` | SSH certificate signing latency (IPC to signer) |
| `ephyr_delegation_ipc_seconds` | Delegation IPC latency |
| `ephyr_exec_e2e_seconds` | End-to-end exec latency (includes SSH) |

**Counters:**

| Metric | Description |
|--------|-------------|
| `ephyr_tasks_created_total` | Total tasks created |
| `ephyr_tokens_signed_total` | Total task tokens signed (macaroon + legacy CTT-E) |
| `ephyr_tokens_validated_total` | Total tokens validated |
| `ephyr_tokens_rejected_total` | Total tokens rejected |
| `ephyr_watermark_revocations_total` | Total watermark revocations |
| `ephyr_delegation_rotations_total` | Total delegation cert rotations |
| `ephyr_legacy_requests_total` | Requests without CTT (legacy mode) |
| `ephyr_auth_cache_hits_total` | Auth cache hits (bcrypt bypassed) |
| `ephyr_auth_cache_misses_total` | Auth cache misses (bcrypt required) |
| `ephyr_macaroons_minted_total` | Macaroon tokens minted (root + delegated) |
| `ephyr_macaroons_verified_total` | Macaroon tokens verified successfully |
| `ephyr_macaroons_rejected_total` | Macaroon tokens rejected (bad HMAC, expired, bad caveats) |
| `ephyr_pop_verified_total` | Proof-of-possession signatures verified (Bind) |
| `ephyr_pop_rejected_total` | Proof-of-possession signatures rejected (Bind) |
| `ephyr_bind_deadline_expired_total` | Delegated tokens expired before binding |

**Gauges:**

| Metric | Description |
|--------|-------------|
| `ephyr_tasks_active` | Currently active tasks |
| `ephyr_active_watermarks` | Number of active revocation watermarks |
| `ephyr_delegation_cert_age_seconds` | Seconds since current delegation cert was issued |
| `ephyr_delegation_certs_held` | Number of delegation certs in memory (1 or 2) |

### Key Metrics to Alert On

| Metric | Condition | Severity | Meaning |
|--------|-----------|----------|---------|
| `ephyr_tokens_rejected_total` | Rate > 5/min | Warning | Possible credential compromise or misconfiguration |
| `ephyr_delegation_cert_age_seconds` | > 3600 | Critical | Delegation cert not rotating (signer may be down) |
| `ephyr_delegation_certs_held` | 0 | Critical | No delegation cert -- task identity broken |
| `ephyr_auth_cache_misses_total` / (`hits` + `misses`) | > 0.5 sustained | Warning | Cache not effective; check TTL or key rotation |
| `ephyr_ssh_cert_seconds` p99 | > 0.05 (50ms) | Warning | Signer IPC is slow; check signer health |
| `ephyr_exec_e2e_seconds` p99 | > 10s | Warning | SSH exec latency is high; check target host health |
| `ephyr_active_watermarks` | > 100 | Info | Many revocations active; check for runaway task creation |
| `ephyr_pop_rejected_total` | Rate > 5/min | Warning | Possible token replay or holder key mismatch |
| `ephyr_bind_deadline_expired_total` | Rate > 2/min | Warning | Delegated tokens expiring before bind -- child agents may be slow to start |
| `ephyr_macaroons_rejected_total` | Rate > 10/min | Warning | Invalid macaroons presented -- possible token forgery or corruption |

### Grafana Dashboard Suggestions

**Panel 1: Request Rate (Counter rate)**
```
rate(ephyr_tokens_validated_total[5m])
rate(ephyr_tokens_rejected_total[5m])
rate(ephyr_auth_cache_hits_total[5m])
rate(ephyr_auth_cache_misses_total[5m])
```

**Panel 2: Latency Heatmap (Histogram)**
```
rate(ephyr_token_validate_seconds_bucket[5m])
rate(ephyr_exec_e2e_seconds_bucket[5m])
rate(ephyr_ssh_cert_seconds_bucket[5m])
```

**Panel 3: Task Lifecycle (Gauge + Counter rate)**
```
ephyr_tasks_active
rate(ephyr_tasks_created_total[5m])
rate(ephyr_watermark_revocations_total[5m])
```

**Panel 4: Delegation Health (Gauge)**
```
ephyr_delegation_cert_age_seconds
ephyr_delegation_certs_held
rate(ephyr_delegation_rotations_total[5m])
```

**Panel 5: Auth Cache Efficiency (Derived)**
```
rate(ephyr_auth_cache_hits_total[5m]) /
  (rate(ephyr_auth_cache_hits_total[5m]) + rate(ephyr_auth_cache_misses_total[5m]))
```

**Panel 6: Macaroon Operations (Counter rate)**
```
rate(ephyr_macaroons_minted_total[5m])
rate(ephyr_macaroons_verified_total[5m])
rate(ephyr_macaroons_rejected_total[5m])
```

**Panel 7: Proof-of-Possession / Bind (Counter rate)**
```
rate(ephyr_pop_verified_total[5m])
rate(ephyr_pop_rejected_total[5m])
rate(ephyr_bind_deadline_expired_total[5m])
```

### Health Checks

For external monitoring (Uptime Kuma, etc.):

**Dashboard health (HTTP 200 with valid token):**
```bash
curl -sf http://BROKER_HOST:8553/v1/dashboard/status \
  -H "Authorization: Bearer $DASHBOARD_TOKEN" > /dev/null
```

**MCP health (JSON-RPC initialize handshake):**
```bash
curl -sf -X POST http://BROKER_HOST:8554/mcp \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <API_KEY>" \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","clientInfo":{"name":"healthcheck","version":"1.0"}}}' \
  | jq -e '.result.protocolVersion' > /dev/null
```

**Systemd watchdog (already configured):**
Both units use `Restart=on-failure` with `RestartSec=5` and burst limits
(signer: 3 in 60s, broker: 5 in 60s).

---

## 4. Auth Cache Operations

### How It Works

The MCP authenticator uses an in-memory cache to avoid repeated bcrypt
comparisons (bcrypt is intentionally slow -- ~100ms per comparison at
cost 10).

1. Agent sends API key in `Authorization: Bearer <key>` header.
2. Cache lookup: compute `SHA-256(apiKey)` as fingerprint, check cache.
3. **Cache hit**: If a valid (non-expired) entry exists, return the cached
   agent identity immediately. Bcrypt is skipped entirely.
4. **Cache miss**: Iterate all registered agents, compare API key against
   each agent's bcrypt hash. On match, cache the result keyed on
   `SHA-256(apiKey)` with the configured TTL.

Cache entries are keyed on SHA-256 of the raw API key -- never the key itself.
Entries expire after `EPHYR_AUTH_CACHE_TTL` (default 60 seconds).

The cache is invalidated entirely when:
- An agent is added or removed (policy reload via SIGHUP)
- The authenticator is reconfigured

### Tuning TTL

Set via environment variable in the broker's systemd drop-in:

```bash
# Create or edit drop-in
systemctl edit ephyr-broker

# Add under [Service]:
# Environment=EPHYR_AUTH_CACHE_TTL=120s
```

Then restart the broker:
```bash
systemctl restart ephyr-signer ephyr-broker
```

**Recommended TTL values:**

| Environment | TTL | Rationale |
|-------------|-----|-----------|
| Production (stable) | `60s` (default) | Good balance of performance and freshness |
| High-throughput | `300s` | Fewer bcrypt ops under sustained load |
| Development | `10s` | Faster iteration when changing API keys |
| Security audit | `0` | Disable cache entirely; every request hits bcrypt |
| Post-incident | `0` | Ensure revoked keys take effect immediately |

### When to Disable

Set `EPHYR_AUTH_CACHE_TTL=0` to disable the cache:
- During a security investigation (ensures key changes take effect instantly)
- When debugging authentication failures (eliminates cache as a variable)
- After revoking/rotating an API key (until you confirm the old key is rejected)

After disabling, expect ~100ms added latency per MCP request (bcrypt cost 10).

### Monitoring Cache Performance

```bash
# Get cache hit/miss counts from Prometheus metrics
curl -s http://localhost:8553/v1/metrics \
  -H "Authorization: Bearer $DASHBOARD_TOKEN" \
  | grep auth_cache

# Expected output:
# ephyr_auth_cache_hits_total 1234
# ephyr_auth_cache_misses_total 56

# Calculate hit ratio
curl -s http://localhost:8553/v1/metrics \
  -H "Authorization: Bearer $DASHBOARD_TOKEN" \
  | grep auth_cache | awk '/hits/{h=$2} /misses/{m=$2} END{if(h+m>0) printf "Hit ratio: %.1f%%\n", h/(h+m)*100; else print "No data"}'
```

A healthy cache hit ratio is above 90%. If misses are high:
- Check if agents are rotating API keys frequently
- Verify TTL is not set too low
- Check if policy reloads are happening too often (each reload clears cache)

---

## 5. Task Identity Operations

### Overview

Tasks provide scoped identity for agent work. Each task gets a macaroon-based
task token (or a legacy CTT-E JWT) signed by the broker's delegation key.
Tasks have ULIDs, lineage tracking, capability envelopes, and TTLs (max 1 hour).

### Creating Tasks (via MCP)

Tasks are created through the `task_create` MCP tool:

```bash
# Create a task via MCP
curl -s -X POST http://localhost:8554/mcp \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <API_KEY>" \
  -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "tools/call",
    "params": {
      "name": "task_create",
      "arguments": {
        "description": "Deploy monitoring stack update",
        "ttl": "30m"
      }
    }
  }' | jq .
```

Response includes:
- `task_id` -- ULID identifying the task
- `token` -- macaroon (`mac_` prefix) or JWT for authenticating subsequent requests
- `expires_at` -- When the task expires
- `envelope` -- Capability boundaries (targets, roles, services, remotes, methods)

### Listing Active Tasks

```bash
# List all tasks for the calling agent
curl -s -X POST http://localhost:8554/mcp \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <API_KEY>" \
  -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "tools/call",
    "params": {
      "name": "task_list",
      "arguments": {}
    }
  }' | jq .
```

### Inspecting a Task

```bash
# Get detailed info on a specific task
curl -s -X POST http://localhost:8554/mcp \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <API_KEY>" \
  -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "tools/call",
    "params": {
      "name": "task_info",
      "arguments": {
        "task_id": "<ULID>"
      }
    }
  }' | jq .
```

The response includes:
- Full task details (ID, root ID, parent ID, depth, lineage)
- Remaining TTL
- Revocation status

### Revoking a Task

Revoking a task sets a watermark that invalidates all tokens issued for that
task and any child tasks (cascading revocation).

```bash
# Revoke a task
curl -s -X POST http://localhost:8554/mcp \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <API_KEY>" \
  -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "tools/call",
    "params": {
      "name": "task_revoke",
      "arguments": {
        "task_id": "<ULID>"
      }
    }
  }' | jq .
```

### Emergency Revocation Procedure

If an agent's task token is compromised:

1. **Revoke the specific task** (if you know the task ID):
   ```bash
   # Via MCP tool as shown above
   ```

2. **Rotate the agent's API key** to prevent new task creation:
   ```bash
   # Generate new bcrypt hash
   htpasswd -nbBC 10 "" "new-api-key-here" | cut -d: -f2

   # Edit policy.yaml and update the agent's api_key_hash
   vim /etc/ephyr/policy.yaml

   # Hot-reload (invalidates auth cache too)
   systemctl reload ephyr-broker
   ```

3. **Verify old key is rejected:**
   ```bash
   curl -s -X POST http://localhost:8554/mcp \
     -H "Content-Type: application/json" \
     -H "Authorization: Bearer <OLD_API_KEY>" \
     -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' \
     | jq .error
   # Should return an authentication error
   ```

4. **Check audit log for unauthorized access attempts:**
   ```bash
   tail -1000 /var/log/ephyr/audit.json \
     | jq 'select(.severity == "WARN" or .severity == "ERROR")'
   ```

### Inspecting a Macaroon Token

Use the `ephyr inspect` CLI command to display a macaroon's caveat chain,
holder binding status, and effective envelope:

```bash
ephyr inspect --token "mac_..."
```

This shows:
- Root task ULID (macaroon identifier)
- Caveat chain with each delegation's constraints
- Effective envelope after all caveats are applied
- Holder binding status (bound/unbound, deadline if applicable)
- Token expiry and remaining TTL

This is useful for debugging delegation attenuation and verifying that
caveats were applied correctly during multi-hop delegation.

### Verifying Delegation Key Status

The delegation key is what the broker uses to sign task tokens (macaroons
and legacy CTT-E). It rotates
automatically (default: every 50 minutes, with 1-hour TTL).

```bash
# Check delegation cert age and count
curl -s http://localhost:8553/v1/metrics \
  -H "Authorization: Bearer $DASHBOARD_TOKEN" \
  | grep -E 'delegation_(cert_age|certs_held|rotations)'

# Expected healthy output:
# ephyr_delegation_cert_age_seconds <value < 3600>
# ephyr_delegation_certs_held 1 or 2
# ephyr_delegation_rotations_total <incrementing count>
```

- `cert_age > 3600`: The delegation cert has expired. Signer may be down.
  Restart signer, then broker.
- `certs_held = 0`: No delegation cert loaded. Task creation will fail.
  Restart both services.
- `certs_held = 2`: Normal during rotation overlap. Old cert is kept for
  in-flight token validation.

---

## 6. Policy Management

### Policy File Structure

The policy file at `/etc/ephyr/policy.yaml` has four top-level sections:

```yaml
# Global settings
global:
  max_active_certs: 50      # Max concurrent SSH certs across all agents
  default_ttl: "5m"          # Default cert TTL
  max_ttl: "30m"             # Maximum allowed cert TTL
  rate_limit:
    requests_per_window: 60   # Requests per agent per window
    window_seconds: 60        # Rate limit window

# Role definitions (map role name -> SSH principal)
roles:
  read:
    principal: "agent-read"
    description: "Read-only access"
  operator:
    principal: "agent-op"
    description: "Operational commands"
  admin:
    principal: "agent-admin"
    description: "Administrative access"

# SSH targets
targets:
  web-server:
    host: "10.0.1.10"
    port: 22
    vlan: 100
    allowed_roles: [read, operator, admin]
    max_ttl: "10m"
    auto_approve: true
    description: "Production Docker host"

# RBAC templates (reusable permission sets)
templates:
  monitoring:
    ssh:
      "*":
        roles: [read]
    services:
      grafana:
        methods: [GET]
    dashboard: "viewer"

  full-ops:
    ssh:
      "*":
        roles: [read, operator]
    services:
      "*":
        methods: [GET, POST, PUT, PATCH, DELETE]
    remotes:
      "*": {}
    dashboard: "operator"

# Agent definitions
agents:
  claude:
    uid: 1000
    max_concurrent_certs: 20
    api_key_hash: "$2a$10$..."
    inherits: [full-ops]          # Inherit from template(s)
    ssh:                           # Override/extend SSH access
      web-server:
        roles: [read, operator, admin]
    services:                      # Override/extend service access
      github:
        methods: [GET, POST, PUT, PATCH, DELETE]
    remotes:
      demo-tools: {}
    dashboard: "admin"
```

### Adding a New Agent

1. Generate an API key and its bcrypt hash:
   ```bash
   # Generate a random API key
   openssl rand -base64 32
   # Output: e.g., MoKz9p04QrQ/vL8XZXE4S93t96I/N+sVV1601MgJKU8=

   # Generate bcrypt hash (cost 10)
   htpasswd -nbBC 10 "" "MoKz9p04QrQ/vL8XZXE4S93t96I/N+sVV1601MgJKU8=" | cut -d: -f2
   # Output: $2y$10$...
   ```

2. Add the agent to `policy.yaml`:
   ```yaml
   agents:
     new-agent:
       uid: 1001
       max_concurrent_certs: 10
       api_key_hash: "$2y$10$..."
       inherits: [monitoring]
       dashboard: "viewer"
   ```

3. If the agent needs nftables isolation, add output drop rules:
   ```bash
   nft add rule inet filter output meta skuid 1001 ip daddr 10.0.1.10 drop
   # ... repeat for each backend IP
   ```

4. Add the agent's system user to the `ephyr-agents` group:
   ```bash
   usermod -aG ephyr-agents <username>
   ```

5. Hot-reload:
   ```bash
   systemctl reload ephyr-broker
   ```

### Adding a New Target

1. Add the target to `policy.yaml` under `targets:`:
   ```yaml
   targets:
     new-host:
       host: "10.0.1.50"
       port: 22
       vlan: 100
       allowed_roles: [read, operator]
       max_ttl: "10m"
       auto_approve: true
       description: "New host description"
   ```

2. Deploy the CA public key to the target host:
   ```bash
   # Extract CA public key
   ssh-keygen -y -f /etc/ephyr/ca_key > /tmp/ca_key.pub

   # Copy to target
   scp /tmp/ca_key.pub root@10.0.1.50:/etc/ssh/

   # On target, add to sshd_config:
   # TrustedUserCAKeys /etc/ssh/ca_key.pub

   # Reload sshd on target
   ssh root@10.0.1.50 'systemctl reload sshd'

   # Clean up
   rm /tmp/ca_key.pub
   ```

3. Create principal-based users on the target (if not existing):
   ```bash
   ssh root@10.0.1.50 '
     useradd -r -s /bin/rbash agent-read 2>/dev/null
     useradd -r -s /bin/bash agent-op 2>/dev/null
     useradd -r -s /bin/bash agent-admin 2>/dev/null
   '
   ```

4. Hot-reload:
   ```bash
   systemctl reload ephyr-broker
   ```

5. Update nftables if agents should be blocked from direct access:
   ```bash
   nft add rule inet filter output meta skuid 1000 ip daddr 10.0.1.50 drop
   ```

### Adding a New Role

1. Add the role to `policy.yaml` under `roles:`:
   ```yaml
   roles:
     deployer:
       principal: "agent-deploy"
       description: "Deployment operations"
   ```

2. Reference the role in target `allowed_roles` and agent `ssh` sections.

3. Create the corresponding principal user on target hosts.

4. Hot-reload:
   ```bash
   systemctl reload ephyr-broker
   ```

### RBAC Configuration

RBAC uses a template-inheritance model:

- **Templates** define reusable permission sets
- **Agents** inherit from one or more templates via `inherits: [template1, template2]`
- **Agent-level overrides** take precedence over inherited values
- **Wildcards**: `"*"` matches all targets/services/remotes
- **Legacy mode**: Agents with no RBAC fields get full access (backward compatible)
- **Dashboard levels**: `none`, `viewer`, `operator`, `admin`

RBAC is enforced at:
- SSH exec/session: target access + role restrictions
- HTTP proxy: service access + method filtering
- MCP federation: remote access + tool restrictions
- Task creation: envelope is built from resolved permissions

### Hot-Reload vs Restart

| Change | Hot-Reload | Requires Restart |
|--------|------------|-----------------|
| Add/remove agent | Yes | No |
| Change agent API key hash | Yes | No |
| Add/remove target | Yes | No |
| Change target settings | Yes | No |
| Add/remove role | Yes | No |
| Change rate limits | Yes | No |
| RBAC template changes | Yes | No |
| Dashboard token | No | Yes |
| MCP listen address | No | Yes |
| Auth cache TTL | No | Yes |
| Audit log path | No | Yes |

### Common Policy Mistakes

**Wrong bcrypt prefix**: `$2a$` and `$2y$` both work. `$2b$` also works.
Do not use plain SHA-256 or MD5 hashes.

**Misspelled role name**: If an agent references a role not defined in `roles:`,
exec requests for that role will fail with "role not in your allowed roles."

**Missing target in RBAC SSH section**: If an agent's RBAC SSH section does not
include a target (and does not use wildcard `"*"`), the agent cannot access that
target even if the target itself lists the role.

**TTL too long**: `max_ttl` in global must be >= each target's `max_ttl`.
Agent cert requests exceeding the target's `max_ttl` are capped silently.

**Rate limit too aggressive**: Default is 60 requests per 60 seconds per agent.
A typical MCP interaction (initialize + tools/list + exec) is 3 requests.
High-frequency automation may need 200+.

---

## 7. Certificate Management

### CA Key

The CA key at `/etc/ephyr/ca_key` is an Ed25519 private key. It is the root
of trust for all SSH certificates. The signer process holds it in memory and
never exposes it over the network.

**Backup the CA key:**
```bash
# Copy to offline storage (USB, vault, etc.)
cp /etc/ephyr/ca_key /secure/backup/ephyr-ca-key-$(date +%Y%m%d)

# Verify the backup
ssh-keygen -y -f /secure/backup/ephyr-ca-key-* > /dev/null && echo "OK"
```

**CA key rotation:**

Rotating the CA key requires redeploying the new public key to all target hosts.
This is a disruptive operation.

1. Generate a new CA key:
   ```bash
   ssh-keygen -t ed25519 -f /etc/ephyr/ca_key.new -N "" -C "ephyr-ca-$(date +%Y%m%d)"
   ```

2. Deploy the new public key to all targets:
   ```bash
   ssh-keygen -y -f /etc/ephyr/ca_key.new > /tmp/ca_key_new.pub
   # For each target: append to TrustedUserCAKeys or replace
   ```

3. Swap keys:
   ```bash
   mv /etc/ephyr/ca_key /etc/ephyr/ca_key.old
   mv /etc/ephyr/ca_key.new /etc/ephyr/ca_key
   chown ephyr-broker:ephyr-broker /etc/ephyr/ca_key
   chmod 0600 /etc/ephyr/ca_key
   ```

4. Restart services:
   ```bash
   systemctl restart ephyr-signer ephyr-broker
   ```

5. Verify:
   ```bash
   # Issue a test cert and exec
   # (via MCP tool call)
   ```

6. After confirming all targets accept new certs, remove old public keys
   from target hosts.

### SSH Certificate Lifecycle

1. Agent calls `exec` or `session_create` MCP tool
2. Broker evaluates RBAC policy for the agent/target/role combination
3. Broker generates an ephemeral Ed25519 keypair for the cert
4. Broker requests the signer to sign the public key with the CA
5. Signer returns a signed SSH certificate (validity: target's max_ttl or less)
6. Broker uses the cert + ephemeral private key for the SSH connection
7. Certificate expires after TTL; ephemeral key is discarded

Certificates are tracked in the broker's CertState. View active certs:

```bash
# Via MCP tool
curl -s -X POST http://localhost:8554/mcp \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <API_KEY>" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_certs","arguments":{}}}' \
  | jq .
```

### Delegation Certificate Rotation

The broker's delegation certificate is used to sign task tokens (macaroons
and legacy CTT-E JWTs). It rotates automatically:

- **TTL**: 1 hour (default)
- **Refresh**: Every 50 minutes (default)
- **Rollover**: Old key is kept as `prev` until all tokens signed with it expire
- **Rotation failure**: Broker keeps the old key and logs the error

The rotation loop runs in a background goroutine. On each rotation:
1. New Ed25519 keypair is generated
2. Public key is sent to signer via IPC for delegation certification
3. Old key moves to `prevPrivateKey` for graceful rollover
4. `DelegationRotations` metric increments

Monitor rotation health:
```bash
# Should see rotation events roughly every 50 minutes
journalctl -u ephyr-broker | grep delegation | tail -10
```

### Verifying Certificate Chain

```bash
# Check the CA public key
ssh-keygen -y -f /etc/ephyr/ca_key

# On a target host, verify the TrustedUserCAKeys matches
ssh root@<target> 'cat /etc/ssh/ca_key.pub'

# Both should output the same Ed25519 public key
```

---

## 8. HTTP Proxy Operations

### Overview

The proxy engine handles HTTP requests on behalf of agents with automatic
credential injection. Services are configured in `/var/lib/ephyr/services.json`.
Network policy is in `/var/lib/ephyr/network_policy.json`.

### Adding a Service

Services can be added via the dashboard API:

```bash
curl -s -X POST http://localhost:8553/v1/dashboard/services \
  -H "Authorization: Bearer $DASHBOARD_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "new-service",
    "url_prefix": "http://10.0.1.50:8080",
    "auth_type": "bearer",
    "credential": "my-secret-token",
    "description": "New service description",
    "enabled": true,
    "max_response_kb": 1024,
    "timeout": 30
  }' | jq .
```

Valid `auth_type` values:
- `bearer` -- Sets `Authorization: Bearer <credential>`
- `basic` -- Sets Basic auth with `username` + `credential` (password)
- `header` -- Sets `<token_header>: <token_prefix><credential>`
- `query` -- Appends `<token_header>=<credential>` as query parameter
- `none` -- No credentials injected

### Removing a Service

```bash
curl -s -X DELETE http://localhost:8553/v1/dashboard/services/new-service \
  -H "Authorization: Bearer $DASHBOARD_TOKEN" | jq .
```

### Toggling a Service On/Off

```bash
curl -s -X POST http://localhost:8553/v1/dashboard/services/gitea/toggle \
  -H "Authorization: Bearer $DASHBOARD_TOKEN" | jq .
```

Disabled services reject all proxy requests with "service is disabled."

### Credential Rotation for Proxied Services

1. Generate or obtain the new credential for the upstream service.

2. Update the service config:
   ```bash
   curl -s -X PUT http://localhost:8553/v1/dashboard/services/github \
     -H "Authorization: Bearer $DASHBOARD_TOKEN" \
     -H "Content-Type: application/json" \
     -d '{
       "credential": "new_github_pat_value_here"
     }' | jq .
   ```

3. Verify the new credential works:
   ```bash
   # Via MCP tool
   curl -s -X POST http://localhost:8554/mcp \
     -H "Content-Type: application/json" \
     -H "Authorization: Bearer <API_KEY>" \
     -d '{
       "jsonrpc":"2.0","id":1,
       "method":"tools/call",
       "params":{
         "name":"http_request",
         "arguments":{"url":"https://api.github.com/user","method":"GET"}
       }
     }' | jq '.result.content[0].text | fromjson | .status_code'
   # Should return 200
   ```

### Network Policy

The network policy file `/var/lib/ephyr/network_policy.json` controls what
the proxy can reach:

```json
{
  "allow_cidrs": ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"],
  "deny_cidrs": [],
  "external": "restricted",
  "external_allow": ["api.github.com", "*.github.com", "*.githubusercontent.com"]
}
```

- `allow_cidrs`: Private IP ranges the proxy may access
- `deny_cidrs`: Explicitly blocked ranges (evaluated first)
- `external`: Policy for public IPs (`open`, `restricted`, `deny`)
- `external_allow`: Hostname glob patterns for `restricted` mode

Changes to `network_policy.json` require a broker restart (not hot-reloadable):
```bash
systemctl restart ephyr-signer ephyr-broker
```

### Testing Proxy Connectivity

```bash
# Test a configured service
curl -s -X POST http://localhost:8554/mcp \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <API_KEY>" \
  -d '{
    "jsonrpc":"2.0","id":1,
    "method":"tools/call",
    "params":{
      "name":"http_request",
      "arguments":{
        "url":"http://10.0.1.10:3001/api/status-page/heartbeat/test",
        "method":"GET"
      }
    }
  }' | jq '.result.content[0].text | fromjson | {status_code, service, duration_ms}'

# List all configured services
curl -s -X POST http://localhost:8554/mcp \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <API_KEY>" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_services","arguments":{}}}' \
  | jq '.result.content[0].text | fromjson'
```

---

## 9. Federation Operations

### Overview

MCP federation allows Ephyr to aggregate tools from remote MCP servers.
Remote tools appear namespaced as `{remote_name}.{tool_name}` (e.g.,
`demo-tools.roll_dice`). Federation state is persisted in
`/var/lib/ephyr/remotes.json`.

### Adding a Remote MCP Server

```bash
curl -s -X POST http://localhost:8553/v1/dashboard/remotes \
  -H "Authorization: Bearer $DASHBOARD_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "my-tools",
    "url": "http://10.0.1.80:8560/mcp",
    "auth_type": "none",
    "description": "My custom MCP tools",
    "enabled": true,
    "timeout": 30,
    "refresh_seconds": 60,
    "max_response_kb": 1024
  }' | jq .
```

Name constraints: alphanumeric and hyphens only, max 50 characters.

After adding, the federator performs an asynchronous MCP handshake
(initialize + tools/list + resources/list) to discover available tools.

### Removing a Remote

```bash
curl -s -X DELETE http://localhost:8553/v1/dashboard/remotes/my-tools \
  -H "Authorization: Bearer $DASHBOARD_TOKEN" | jq .
```

### Toggling Remotes On/Off

```bash
curl -s -X POST http://localhost:8553/v1/dashboard/remotes/demo-tools/toggle \
  -H "Authorization: Bearer $DASHBOARD_TOKEN" | jq .
```

Disabled remotes are skipped by the refresh loop and their tools are not
available to agents.

### Checking Federation Status

```bash
# Via MCP tool
curl -s -X POST http://localhost:8554/mcp \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <API_KEY>" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_remotes","arguments":{}}}' \
  | jq '.result.content[0].text | fromjson'

# Via dashboard API
curl -s http://localhost:8553/v1/dashboard/remotes \
  -H "Authorization: Bearer $DASHBOARD_TOKEN" | jq .
```

### Debugging Federation Connectivity

If a remote shows status `error` or `disconnected`:

1. **Check the remote is reachable from the LXC:**
   ```bash
   curl -s http://10.0.1.80:8560/mcp \
     -X POST -H "Content-Type: application/json" \
     -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","clientInfo":{"name":"debug","version":"1.0"}}}'
   ```

2. **Check network policy allows the remote's IP:**
   ```bash
   cat /var/lib/ephyr/network_policy.json | jq .allow_cidrs
   ```

3. **Check nftables is not blocking the broker:**
   ```bash
   nft list ruleset | grep -A5 output
   # Broker runs as UID 999 -- should NOT be blocked
   # Agent UID 1000 IS blocked (by design)
   ```

4. **Check broker logs for federation errors:**
   ```bash
   journalctl -u ephyr-broker | grep federation | tail -20
   ```

5. **Check the remote state in detail:**
   ```bash
   curl -s http://localhost:8553/v1/dashboard/remotes \
     -H "Authorization: Bearer $DASHBOARD_TOKEN" \
     | jq '.[] | select(.name == "demo-tools")'
   ```

The federation refresh loop uses exponential backoff for errored remotes:
10s, 30s, 60s, 120s, 300s (capped). After fixing the issue, toggle the
remote off and on to reset the error count and trigger immediate rediscovery.

---

## 10. Troubleshooting

### "Agent can't authenticate"

Symptoms: MCP requests return 401 or JSON-RPC error "invalid API key."

Checklist:

1. **Verify the API key is correct:**
   ```bash
   # Check what key the agent is sending (from their config)
   # Then manually test it
   curl -s -X POST http://localhost:8554/mcp \
     -H "Content-Type: application/json" \
     -H "Authorization: Bearer <THE_KEY>" \
     -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' | jq .
   ```

2. **Check the bcrypt hash in policy.yaml:**
   ```bash
   grep api_key_hash /etc/ephyr/policy.yaml
   # Verify the hash matches the key:
   python3 -c "
   import bcrypt
   key = b'<THE_KEY>'
   hash = b'<THE_HASH>'
   print('Match' if bcrypt.checkpw(key, hash) else 'NO MATCH')
   "
   ```

3. **Check if auth cache is stale (if key was recently changed):**
   ```bash
   # Temporarily disable cache
   # Or wait for TTL to expire (default 60s)
   # Or reload policy (clears cache)
   systemctl reload ephyr-broker
   ```

4. **Check the agent is registered:**
   ```bash
   grep -A5 "agents:" /etc/ephyr/policy.yaml
   ```

5. **Check MCP port is listening:**
   ```bash
   ss -tlnp | grep 8554
   ```

6. **Check nftables is not blocking the client:**
   ```bash
   nft list ruleset | grep -A10 input
   # Port 8554 should be open for 192.168.0.0/16
   ```

### "Task creation fails"

Symptoms: `task_create` returns "task identity not available" or signing error.

Checklist:

1. **Check delegation key is healthy:**
   ```bash
   curl -s http://localhost:8553/v1/metrics \
     -H "Authorization: Bearer $DASHBOARD_TOKEN" \
     | grep delegation
   # delegation_certs_held should be >= 1
   # delegation_cert_age_seconds should be < 3600
   ```

2. **Check signer is running:**
   ```bash
   systemctl is-active ephyr-signer
   ```

3. **Check signer socket exists:**
   ```bash
   ls -la /run/ephyr/signer.sock
   ```

4. **Check broker logs for delegation errors:**
   ```bash
   journalctl -u ephyr-broker | grep -i delegation | tail -10
   ```

5. **If signer was restarted, restart broker too:**
   ```bash
   systemctl restart ephyr-signer ephyr-broker
   ```

### "SSH exec times out"

Symptoms: `exec` tool returns timeout error or takes >30 seconds.

Checklist:

1. **Check the target host is reachable:**
   ```bash
   ping -c 1 <target_ip>
   ssh -o ConnectTimeout=5 agent-read@<target_ip> 'echo ok'
   ```

2. **Check the target host's sshd is accepting certificate auth:**
   ```bash
   ssh <target_ip> 'grep TrustedUserCAKeys /etc/ssh/sshd_config'
   ```

3. **Check the principal user exists on the target:**
   ```bash
   ssh <target_ip> 'id agent-read && id agent-op'
   ```

4. **Check the target is enabled in the broker:**
   ```bash
   curl -s -X POST http://localhost:8554/mcp \
     -H "Content-Type: application/json" \
     -H "Authorization: Bearer <API_KEY>" \
     -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_targets","arguments":{}}}' \
     | jq '.result.content[0].text | fromjson | .[] | {name, enabled}'
   ```

5. **Check the audit log for cert issuance:**
   ```bash
   tail -50 /var/log/ephyr/audit.json | jq 'select(.event_type == "cert_issued" or .event_type == "cert_denied")'
   ```

6. **Check the command timeout setting:**
   The default is 30s, max is 300s. Pass `"timeout": 120` in the exec args
   for long-running commands.

### "Dashboard shows stale data"

Symptoms: Dashboard shows old agent activity or host states.

Checklist:

1. **Check the WebSocket connection:**
   Open browser developer tools, Network tab, filter WS. The dashboard uses
   a WebSocket at `/ws` on port 8553 that pushes state every 2 seconds.

2. **Check the broker's event hub:**
   ```bash
   journalctl -u ephyr-broker | grep -i websocket | tail -5
   ```

3. **Hard-refresh the dashboard:**
   Clear browser cache or use Ctrl+Shift+R.

4. **Check the broker is still running:**
   ```bash
   systemctl is-active ephyr-broker
   ```

### "Metrics not updating"

Symptoms: Prometheus scrape returns the same values repeatedly.

Checklist:

1. **Verify metrics endpoint responds:**
   ```bash
   curl -s http://localhost:8553/v1/metrics \
     -H "Authorization: Bearer $DASHBOARD_TOKEN" | head -20
   ```

2. **Trigger some activity to increment counters:**
   ```bash
   # Call tools/list to generate auth cache activity
   curl -s -X POST http://localhost:8554/mcp \
     -H "Content-Type: application/json" \
     -H "Authorization: Bearer <API_KEY>" \
     -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
   ```

3. **Check Prometheus scrape config:**
   Ensure the target is `http://BROKER_HOST:8553/v1/metrics` and the
   `Authorization` header is being sent.

4. **Check if the broker was recently restarted:**
   All metrics reset to zero on restart (they are in-memory atomics).

### "Delegation key not rotating"

Symptoms: `ephyr_delegation_cert_age_seconds` keeps growing past 3600.

Checklist:

1. **Check signer is running and healthy:**
   ```bash
   systemctl status ephyr-signer
   journalctl -u ephyr-signer --since "1 hour ago"
   ```

2. **Check signer socket is accessible:**
   ```bash
   ls -la /run/ephyr/signer.sock
   # Should be owned by ephyr-broker:ephyr-agents
   ```

3. **Check broker logs for rotation failures:**
   ```bash
   journalctl -u ephyr-broker | grep "rotation failed" | tail -5
   ```

4. **Force rotation by restarting:**
   ```bash
   systemctl restart ephyr-signer ephyr-broker
   ```
   This triggers a fresh delegation request at startup.

### Common Error Messages

| Error Message | Cause | Fix |
|---------------|-------|-----|
| `initial delegation request failed` | Signer not running or socket missing | Start signer, then broker |
| `delegation cert has expired` | Rotation failed and cert TTL passed | Restart both services |
| `no agents registered` | Policy has no agents section | Check policy.yaml |
| `invalid API key` | Key doesn't match any agent's bcrypt hash | Verify key and hash |
| `unknown target: X` | Target not in policy.yaml | Add target and reload |
| `role "X" is not allowed on target "Y"` | Target's `allowed_roles` doesn't include role | Update policy.yaml |
| `role "X" is not in your allowed roles` | Agent's RBAC doesn't grant that role | Update agent RBAC |
| `access denied to target "X"` | Agent RBAC blocks this target | Add target to agent's SSH section |
| `target "X" is currently disabled` | Host toggled off via dashboard | Re-enable via dashboard |
| `proxy: policy denied` | Network policy blocks the URL | Update network_policy.json |
| `proxy: service "X" is disabled` | Service toggled off | Re-enable via dashboard |
| `exec subsystem is not available` | ExecPool not initialized | Check broker startup logs |
| `task identity not available` | No delegation cert (signer issue) | Restart signer + broker |
| `rate_limited` | Agent exceeded request quota | Wait or increase rate_limit in policy |
| `task %s was revoked at %s` | Token's lineage contains revoked task | Create a new task |

---

## 11. Backup & Recovery

### What to Back Up

**Critical (must restore for operation):**

| Item | Path | Notes |
|------|------|-------|
| CA private key | `/etc/ephyr/ca_key` | Root of trust. Without this, all target hosts need new CA key deployed. |
| Policy config | `/etc/ephyr/policy.yaml` | Agent definitions, targets, RBAC. Can be rebuilt but tedious. |
| Service configs | `/var/lib/ephyr/services.json` | Contains plaintext credentials for proxied services. |
| Remote configs | `/var/lib/ephyr/remotes.json` | Federation server definitions. |
| Network policy | `/var/lib/ephyr/network_policy.json` | Proxy CIDR allow/deny rules. |
| Host configs | `/var/lib/ephyr/hosts.json` | Runtime host config (reconciled from policy). |

**Important (recommended to back up):**

| Item | Path | Notes |
|------|------|-------|
| Audit log | `/var/log/ephyr/audit.json` | Compliance trail. Can grow large. |
| nftables rules | `nft list ruleset` output | Network isolation rules. |
| Systemd overrides | `/etc/systemd/system/ephyr-broker.service.d/` | Environment variable overrides. |
| Source code | `/opt/ephyr/` | Git repo, can be re-cloned. |

### What is Ephemeral (No Backup Needed)

| Item | Notes |
|------|-------|
| Delegation keys | Regenerated on each broker startup |
| Auth cache | In-memory, rebuilt on first request |
| Task state | In-memory, tasks expire (max 1h TTL) |
| Revocation watermarks | In-memory, GC'd after max task TTL |
| Active SSH certificates | In-memory, expire per TTL (max 30m) |
| Active SSH sessions | In-memory, broken on restart |
| Runtime sockets | Recreated by tmpfiles.d on boot |

### Backup Script

```bash
#!/bin/bash
# Ephyr backup script -- run as root
BACKUP_DIR="/backup/ephyr/$(date +%Y%m%d-%H%M%S)"
mkdir -p "$BACKUP_DIR"

# Critical files
cp /etc/ephyr/ca_key "$BACKUP_DIR/"
cp /etc/ephyr/policy.yaml "$BACKUP_DIR/"
cp /var/lib/ephyr/services.json "$BACKUP_DIR/"
cp /var/lib/ephyr/remotes.json "$BACKUP_DIR/"
cp /var/lib/ephyr/network_policy.json "$BACKUP_DIR/"
cp /var/lib/ephyr/hosts.json "$BACKUP_DIR/" 2>/dev/null

# Systemd overrides
cp -r /etc/systemd/system/ephyr-broker.service.d "$BACKUP_DIR/" 2>/dev/null
cp -r /etc/systemd/system/ephyr-signer.service.d "$BACKUP_DIR/" 2>/dev/null

# nftables
nft list ruleset > "$BACKUP_DIR/nftables.conf"

# Permissions
chmod 0600 "$BACKUP_DIR/ca_key"
chmod 0600 "$BACKUP_DIR/services.json"
chmod -R 0700 "$BACKUP_DIR"

echo "Backup complete: $BACKUP_DIR"
ls -la "$BACKUP_DIR"
```

### Recovery Procedure

From a backup to a fresh Debian 12 LXC:

1. **Install Go and build Ephyr:**
   ```bash
   # Install Go 1.24+
   wget https://go.dev/dl/go1.24.1.linux-amd64.tar.gz
   tar -C /usr/local -xzf go1.24.1.linux-amd64.tar.gz
   export PATH=$PATH:/usr/local/go/bin

   # Clone or copy source
   cp -r /backup/ephyr-source /opt/ephyr
   cd /opt/ephyr
   make install
   ```

2. **Create system user and directories:**
   ```bash
   make install-user
   ```

3. **Restore configuration:**
   ```bash
   cp /backup/ca_key /etc/ephyr/ca_key
   cp /backup/policy.yaml /etc/ephyr/policy.yaml
   chown ephyr-broker:ephyr-broker /etc/ephyr/ca_key
   chmod 0600 /etc/ephyr/ca_key
   chmod 0640 /etc/ephyr/policy.yaml

   cp /backup/services.json /var/lib/ephyr/
   cp /backup/remotes.json /var/lib/ephyr/
   cp /backup/network_policy.json /var/lib/ephyr/
   cp /backup/hosts.json /var/lib/ephyr/ 2>/dev/null
   chown ephyr-broker:ephyr-agents /var/lib/ephyr/*.json
   chmod 0640 /var/lib/ephyr/*.json
   ```

4. **Restore systemd units and overrides:**
   ```bash
   make install-systemd
   cp -r /backup/ephyr-broker.service.d /etc/systemd/system/ 2>/dev/null
   systemctl daemon-reload
   ```

5. **Restore nftables:**
   ```bash
   nft -f /backup/nftables.conf
   ```

6. **Start services:**
   ```bash
   systemctl enable --now ephyr-signer ephyr-broker
   ```

7. **Verify:**
   ```bash
   systemctl status ephyr-signer ephyr-broker
   curl -s http://localhost:8553/v1/dashboard/status \
     -H "Authorization: Bearer $DASHBOARD_TOKEN" | jq .
   ```

---

## 12. Upgrade Procedure

### Build New Binaries

```bash
cd /opt/ephyr

# Pull latest code
git pull origin main

# Build
make build

# Verify binaries
./bin/ephyr-broker --version 2>/dev/null || echo "Check build output"
./bin/ephyr-signer --version 2>/dev/null || echo "Check build output"
```

### Pre-Upgrade Checks

```bash
# Run unit tests
make test

# Check for breaking changes in policy format
diff <(git show HEAD~1:configs/policy.yaml 2>/dev/null) /etc/ephyr/policy.yaml

# Backup current binaries
cp /usr/local/bin/ephyr-broker /usr/local/bin/ephyr-broker.bak
cp /usr/local/bin/ephyr-signer /usr/local/bin/ephyr-signer.bak
cp /usr/local/bin/ephyr /usr/local/bin/ephyr.bak
```

### Rolling Restart

```bash
# Install new binaries (overwrites old ones)
make install

# Restart signer first, then broker
systemctl restart ephyr-signer
sleep 2
systemctl restart ephyr-broker
```

This causes a brief interruption:
- Active SSH sessions using existing certs continue (certs are already signed)
- New SSH cert requests fail during the restart window (~2-5 seconds)
- MCP connections are dropped and must reconnect
- Dashboard WebSocket connections are dropped and auto-reconnect
- Auth cache is cleared (first post-restart request will be slower)
- Delegation key is regenerated (old tokens remain valid until they expire)

### Post-Upgrade Verification

```bash
# 1. Check services are running
systemctl status ephyr-signer ephyr-broker

# 2. Check delegation key was established
curl -s http://localhost:8553/v1/metrics \
  -H "Authorization: Bearer $DASHBOARD_TOKEN" \
  | grep delegation_certs_held
# Should show 1

# 3. Test MCP handshake
curl -s -X POST http://localhost:8554/mcp \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <API_KEY>" \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","clientInfo":{"name":"upgrade-check","version":"1.0"}}}' \
  | jq '.result.protocolVersion'
# Should return "2025-03-26"

# 4. Test exec
curl -s -X POST http://localhost:8554/mcp \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <API_KEY>" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"exec","arguments":{"target":"web-server","role":"read","command":"hostname"}}}' \
  | jq '.result.content[0].text | fromjson | .exit_code'
# Should return 0

# 5. Check dashboard loads
curl -sf http://localhost:8553/ > /dev/null && echo "Dashboard OK"

# 6. Check audit log for startup event
tail -5 /var/log/ephyr/audit.json | jq 'select(.event_type == "startup")'
```

### Rollback Procedure

If the upgrade causes issues:

```bash
# Restore old binaries
cp /usr/local/bin/ephyr-broker.bak /usr/local/bin/ephyr-broker
cp /usr/local/bin/ephyr-signer.bak /usr/local/bin/ephyr-signer
cp /usr/local/bin/ephyr.bak /usr/local/bin/ephyr

# Restart with old binaries
systemctl restart ephyr-signer
sleep 2
systemctl restart ephyr-broker

# Verify
systemctl status ephyr-signer ephyr-broker
```

If the policy format changed between versions and the old binary cannot load
the new policy, restore the old policy too:

```bash
cp /backup/policy.yaml /etc/ephyr/policy.yaml
systemctl reload ephyr-broker
```

---

## 13. Integration Testing

### Running the Smoke Test Suite

The integration tests live at `/opt/ephyr/test/integration/smoke_test.go`
and require a running broker instance. They test the MCP protocol end-to-end.

```bash
cd /opt/ephyr

# Run integration tests (requires running broker)
/usr/local/go/bin/go test -tags integration -v -timeout 120s ./test/integration/

# Run with custom endpoint (default: http://localhost:8554/mcp)
EPHYR_MCP_ENDPOINT="http://BROKER_HOST:8554/mcp" \
EPHYR_MCP_KEY="<API_KEY>" \
EPHYR_DASH_ENDPOINT="http://BROKER_HOST:8553" \
EPHYR_DASH_TOKEN="$DASHBOARD_TOKEN" \
  /usr/local/go/bin/go test -tags integration -v -timeout 120s ./test/integration/

# Run a specific test
/usr/local/go/bin/go test -tags integration -v -run TestTaskLifecycle ./test/integration/
```

### Test Inventory (8 tests)

| Test | What It Validates |
|------|-------------------|
| `TestMCPInitialize` | MCP handshake, protocol version 2025-03-26 |
| `TestToolsList` | tools/list returns expected tool count |
| `TestLegacyToolsStillWork` | Core tools (list_targets, exec, etc.) work without tasks |
| `TestTaskLifecycle` | task_create, task_info, task_list, task_revoke full cycle |
| `TestTaskValidation` | Invalid inputs rejected (empty description, bad TTL, etc.) |
| `TestMetricsEndpoint` | Prometheus metrics endpoint returns valid data |
| `TestPerformanceBench` | Latency benchmarks for key operations |
| `TestSummary` | Prints performance report (always passes) |

### Interpreting Results

```
--- PASS: TestMCPInitialize (0.01s)
    smoke_test.go:120:   [PASS] mcp_initialize - server=ephyr protocol=2025-03-26 (5.23ms)
--- PASS: TestTaskLifecycle (0.05s)
    smoke_test.go:250:   [PASS] task_create - task_id=01JQXYZ... (12.45ms)
    smoke_test.go:260:   [PASS] task_info - remaining_ttl=29m59s (3.21ms)
    smoke_test.go:275:   [PASS] task_revoke - revoked=01JQXYZ... (4.87ms)
```

Key things to check:
- All tests should PASS
- Latencies should be reasonable (MCP ops < 50ms, exec < 10s)
- `TestPerformanceBench` reports p50/p95/p99 latencies

### Performance Benchmark Baseline

Expected latencies for a healthy system (LXC on R430):

| Operation | p50 | p95 | p99 |
|-----------|-----|-----|-----|
| MCP initialize | < 5ms | < 10ms | < 20ms |
| tools/list | < 3ms | < 8ms | < 15ms |
| task_create | < 10ms | < 20ms | < 30ms |
| task_info | < 3ms | < 8ms | < 15ms |
| task_revoke | < 5ms | < 10ms | < 20ms |
| list_targets | < 3ms | < 8ms | < 15ms |
| exec (simple command) | < 2s | < 5s | < 8s |

If latencies are significantly above these baselines:
- Check system load on the LXC (`top`, `vmstat 1`)
- Check signer IPC latency: `grep delegation_ipc /v1/metrics` output
- Check target host SSH responsiveness: `time ssh agent-read@<target> 'echo ok'`

### Running Unit Tests

```bash
cd /opt/ephyr

# All unit tests with race detection
/usr/local/go/bin/go test -race ./...

# With coverage report
make cover
# Opens coverage.html

# Specific package
/usr/local/go/bin/go test -v ./internal/broker/
/usr/local/go/bin/go test -v ./internal/policy/
/usr/local/go/bin/go test -v ./internal/token/
```

---

## Appendix: nftables Rules Reference

Current nftables ruleset for agent isolation:

```
table inet filter {
    chain input {
        type filter hook input priority filter; policy drop;
        ct state established,related accept
        iif "lo" accept
        ip protocol icmp accept
        ip6 nexthdr ipv6-icmp accept
        tcp dport 22 accept                                    # SSH
        ip saddr 192.168.0.0/16 tcp dport 8553 accept         # Dashboard
        ip saddr 192.168.0.0/16 tcp dport 8554 accept         # MCP
    }

    chain forward {
        type filter hook forward priority filter; policy drop;
    }

    chain output {
        type filter hook output priority filter; policy accept;
        meta skuid 1000 ip daddr 10.0.1.10 drop                 # Block agent -> web-server
        meta skuid 1000 ip daddr 10.0.1.20 drop                # Block agent -> app-server
        meta skuid 1000 ip daddr 10.0.1.30 drop                # Block agent -> blog-server
        meta skuid 1000 ip daddr 10.0.1.40 drop                # Block agent -> git-server
        meta skuid 1000 ip daddr 10.0.2.10 drop                # Block agent -> staging
    }
}
```

The output chain blocks UID 1000 (agent) from directly connecting to backend
hosts. The broker (UID 999) is unrestricted and proxies all agent requests.
This ensures agents can only reach backends through Ephyr's audited paths.

To add a new backend to the block list:
```bash
nft add rule inet filter output meta skuid 1000 ip daddr <IP> drop
```

To persist nftables rules across reboots:
```bash
nft list ruleset > /etc/nftables.conf
systemctl enable nftables
```
