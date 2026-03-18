# Configuration Reference

Complete reference for all Ephyr configuration options, covering the policy
file, environment variables, CLI flags, target provisioning, service proxy
configuration, and network policy.

---

## Policy File (policy.yaml)

The policy file is the central configuration that controls which agents exist,
what roles are available, which targets can be accessed, and what limits apply.
It is loaded at startup and can be hot-reloaded by sending SIGHUP to the
broker process (or running `systemctl reload ephyr-broker`).

Default path: `/etc/ephyr/policy.yaml`

**Initial generation:** Run `sudo ephyr init` to generate a working policy.yaml
with example agents, roles, and targets. The init wizard creates all required
directories, the CA key, and systemd units in one step. Use `--dev` for
development defaults.

### Full Annotated Example

```yaml
# Ephyr Policy -- full reference example
# Hot-reload: send SIGHUP to the broker, or systemctl reload ephyr-broker

global:
  max_active_certs: 10      # Maximum certificates active across ALL agents
  default_ttl: "5m"         # Default certificate lifetime when agent omits duration
  max_ttl: "30m"            # Hard ceiling on any certificate TTL
  rate_limit:
    requests_per_window: 10  # Max requests per agent per sliding window
    window_seconds: 60       # Sliding window duration in seconds

agents:
  claude:
    uid: 1000                # Linux UID (matched via SO_PEERCRED on Unix socket)
    max_concurrent_certs: 5  # Per-agent active cert limit
    api_key_hash: "$2a$..."  # bcrypt hash for MCP API key authentication
    description: "Claude Code agent on command VM"

roles:
  read:
    principal: "agent-read"  # SSH principal (maps to target user account)
    description: "Read-only filesystem access"
    shell: "/bin/rbash"      # Restricted shell for read-only roles
    sudo: false              # No sudo access
  operator:
    principal: "agent-op"
    description: "Service management access"
    shell: "/bin/bash"
    sudo:                    # List of allowed sudo commands
      - "/usr/bin/systemctl status *"
      - "/usr/bin/systemctl restart *"
      - "/usr/bin/journalctl *"
      - "/usr/bin/docker ps *"
      - "/usr/bin/docker logs *"
  admin:
    principal: "agent-admin"
    description: "Full administrative access"
    shell: "/bin/bash"
    sudo:
      - "/usr/bin/systemctl *"
      - "/usr/bin/docker *"
      - "/usr/bin/journalctl *"

targets:
  webserver:
    host: "10.0.1.10"
    port: 22
    vlan: 100
    allowed_roles: [read, operator]
    max_ttl: "15m"           # Override global max for this target
    auto_approve: true
    force_command: ""         # Optional: restrict cert to a specific command
    description: "Production web server"
```

### global Section

| Field | Type | Default | Required | Description |
|-------|------|---------|----------|-------------|
| max_active_certs | int | 10 | No | Maximum number of certificates that can be active simultaneously across all agents. When this limit is reached, new requests are denied until existing certs expire or are revoked. |
| default_ttl | string (Go duration) | "5m" | No | Default certificate lifetime used when an agent does not specify a duration in its request. Must be less than or equal to max_ttl. Examples: "5m", "1h", "30s". |
| max_ttl | string (Go duration) | "30m" | No | Hard ceiling on any certificate lifetime. Requested durations are silently clamped to this value. Target-level max_ttl can be lower but never higher. |
| rate_limit.requests_per_window | int | 10 | No | Maximum number of certificate requests a single agent can make within one sliding window. Excess requests receive HTTP 429. |
| rate_limit.window_seconds | int | 60 | No | Duration of the sliding rate limit window in seconds. |

**Validation rules:**
- default_ttl must be parseable as a Go duration.
- max_ttl must be parseable as a Go duration.
- default_ttl must not exceed max_ttl (startup fails otherwise).

### agents Section

Each key under agents is the agent's logical name (e.g., "claude"). The name
is used in audit logs, session tracking, and MCP authentication.

| Field | Type | Default | Required | Description |
|-------|------|---------|----------|-------------|
| uid | int | (none) | **Yes** | Linux UID of the agent process. Used for identity verification via SO_PEERCRED on the Unix socket. Each agent must have a unique UID. |
| max_concurrent_certs | int | 3 | No | Maximum number of certificates this agent can hold simultaneously. When reached, new requests are denied. If the agent re-requests for the same target+role, the old cert is auto-revoked first. |
| api_key_hash | string | "" | No | bcrypt hash of the agent's API key for MCP (TCP) authentication. If empty, the agent cannot use MCP. See the MCP Setup section in the Deployment Guide for generation instructions. |
| description | string | "" | No | Human-readable description shown in dashboards and audit logs. |
| inherits | list of strings | [] | No | List of template names to inherit permissions from. Templates are merged left-to-right, then agent-level overrides are applied. See the RBAC section below. |
| ssh | map | (none) | No | Per-target SSH permissions. Keys are target names or `"*"` (wildcard). Each value has `roles` (list) and `auto_approve` (bool). See RBAC section. |
| services | map | (none) | No | Per-service HTTP proxy permissions. Keys are service names or `"*"`. Each value has `methods` (list of HTTP methods). See RBAC section. |
| remotes | map | (none) | No | Per-remote MCP federation permissions. Keys are remote names or `"*"`. Values are objects (currently empty, reserved for tool-level restrictions). See RBAC section. |
| dashboard | string | "" | No | Dashboard access level: `"none"`, `"viewer"`, `"operator"`, or `"admin"`. Empty or unset means no explicit dashboard access. |

**Validation rules:**
- At least one agent must be defined (startup fails otherwise).
- No two agents may share the same uid (startup fails on duplicate).
- All template names in `inherits` must reference defined templates.

**Backwards compatibility:** Agents that omit all RBAC fields (`inherits`, `ssh`, `services`, `remotes`, `dashboard`) operate in legacy mode with full access to all targets, services, and remotes. This preserves pre-RBAC behavior for existing deployments.

### roles Section

Each key under roles is the role's logical name (e.g., "read", "operator").
Role names are referenced by targets in their allowed_roles lists.

| Field | Type | Default | Required | Description |
|-------|------|---------|----------|-------------|
| principal | string | (none) | **Yes** | SSH principal name embedded in the certificate. This maps to a user account on the target host via AuthorizedPrincipalsFile. Example: "agent-read" maps to the agent-read system user. Must be a valid Linux username: 1-32 characters, lowercase alphanumeric, hyphens, and underscores, starting with a lowercase letter or underscore. |
| description | string | "" | No | Human-readable description of what this role can do. |
| shell | string | "/bin/bash" | No | Login shell for the role's user account on target hosts. Use `/bin/rbash` for restricted (read-only) roles. Must be an absolute path (starts with `/`). The provisioning script uses this value when creating role accounts. |
| sudo | bool or list of strings | (none) | No | Sudoers configuration for the role account. `false` or omitted means no sudo access. `true` grants unrestricted sudo (`ALL`) — a warning is logged at startup. A list of strings specifies allowed commands (e.g., `["/usr/bin/systemctl status *", "/usr/bin/docker ps *"]`). Empty strings in the list are rejected. |
| system | bool | true | No | Whether to create the role as a system user (useradd --system). Set to `false` for regular user accounts. |

**Validation rules:**
- Every role referenced in a target's allowed_roles must be defined here.
- principal must not be empty and must be a valid Linux username.
- shell (if set) must be an absolute path starting with `/`.
- sudo entries must not be empty strings.
- `sudo: true` triggers a startup warning (wide-open sudo).

### targets Section

Each key under targets is the target's logical name (e.g., "webserver").
This name is used in CLI commands, MCP tool calls, and audit logs.

| Field | Type | Default | Required | Description |
|-------|------|---------|----------|-------------|
| host | string | (none) | **Yes** | IP address or hostname of the target. Must not be empty. |
| port | int | 22 | No | SSH port on the target host. |
| vlan | int | 0 | No | VLAN ID for informational/dashboard display. Not enforced by the broker. |
| allowed_roles | list of strings | [] | No | List of role names from the roles section that may access this target. An agent can only request a cert for this target using one of these roles. |
| max_ttl | string (Go duration) | (global max_ttl) | No | Maximum certificate lifetime for this specific target. Must be less than or equal to the global max_ttl. If unset, the global value applies. |
| auto_approve | bool | false | No | When true, certificate requests for this target are automatically approved without manual intervention. When false, requests enter a "pending" state. |
| force_command | string | "" | No | If set, the issued certificate includes an SSH force-command critical option, restricting the session to only this command. |
| command_filter | bool | false | No | Enable command filtering for this target. When disabled (default), there is zero overhead (~3.9ns). When enabled, commands are checked against `command_deny` and `command_allow` patterns before the SSH connection is established. |
| command_deny | list of strings | [] | No | Deny-list: block commands matching these patterns (substring or glob). Evaluated only when `command_filter: true`. |
| command_allow | list of strings | [] | No | Allow-list: only permit commands matching these patterns. Takes precedence over `command_deny` when both are set (more restrictive). Evaluated only when `command_filter: true`. |
| auto_revoke_on_deny | bool | false | No | When true and a command is denied, the target is automatically disabled for all agents. An admin must re-enable the target from the dashboard or API. |
| description | string | "" | No | Human-readable description for dashboards and audit logs. |
| host_key | string | "" | No | SSH public key in authorized_keys format for host key pinning (T6). When set, the broker verifies the target's host key on every connection. Mismatches are rejected and logged as ALERT. |
| host_key_fingerprint | string | "" | No | SHA256 fingerprint of the expected host key (e.g., `SHA256:nThbg6kX...`). Alternative to `host_key` — only the fingerprint is compared. |

The global `host_key_strict` option (under `global:`) requires every target to have at least one of `host_key` or `host_key_fingerprint` configured. When enabled, connections to unpinned targets are rejected.

For detailed command filtering configuration including pattern syntax, deny-list vs allow-list modes, and security considerations, see [Command filtering in Target Setup](target-setup.md#command-filtering).

**Validation rules:**
- host must not be empty or contain whitespace.
- No two targets may share the same host:port combination.
- All entries in allowed_roles must reference defined roles.
- max_ttl (if set) must not exceed global max_ttl.

### TTL Clamping Logic

When a certificate request is evaluated, the final duration is determined by:

```
effective_ttl = min(requested_duration, target.max_ttl, global.max_ttl)
```

If the agent omits the duration, global.default_ttl is used as the starting
value. The signer also enforces a hard cap of 24 hours regardless of policy.

### Duplicate Certificate Handling

If an agent requests a certificate for the same target+role combination and
already has an active cert for that combination, the old certificate is
automatically revoked before issuing the new one. This prevents the agent from
consuming its max_concurrent_certs limit with stale certificates.

---

## RBAC (Per-Agent Permissions)

Ephyr supports fine-grained, per-agent access control across SSH targets,
HTTP proxy services, MCP federation, and the dashboard. Permissions are defined
in `policy.yaml` using a template inheritance model.

### Templates

Templates define reusable permission sets. Define them under the `templates:`
key in policy.yaml.

```yaml
templates:
  monitoring:
    description: "Read-only monitoring"
    ssh:
      "*":
        roles: [read]
        auto_approve: true
    services:
      grafana:
        methods: [GET]
      uptime-kuma:
        methods: [GET]
    remotes: {}
    dashboard: "viewer"

  full-ops:
    description: "Operator-level access to everything"
    ssh:
      "*":
        roles: [read, operator]
        auto_approve: true
    services:
      "*":
        methods: [GET, POST, PUT, PATCH, DELETE]
    remotes:
      "*": {}
    dashboard: "operator"
```

### Template Fields

| Field | Type | Description |
|-------|------|-------------|
| description | string | Human-readable description of the template's purpose. |
| ssh | map | Per-target SSH permissions. Keys are target names or `"*"` (wildcard). |
| ssh.{target}.roles | list of strings | SSH roles the agent may use on this target. Intersected with the target's `allowed_roles` at evaluation time. |
| ssh.{target}.auto_approve | bool | Whether certificate requests for this target are auto-approved. |
| services | map | Per-service HTTP proxy permissions. Keys are service names or `"*"`. |
| services.{service}.methods | list of strings | Allowed HTTP methods (e.g., `[GET, POST]`). Empty or omitted means all methods. |
| remotes | map | Per-remote MCP federation permissions. Keys are remote names or `"*"`. |
| dashboard | string | Dashboard access level: `none`, `viewer`, `operator`, `admin`. |

### Per-Agent RBAC Configuration

Agents inherit from templates and add overrides:

```yaml
agents:
  claude:
    uid: 1000
    max_concurrent_certs: 20
    api_key_hash: "$2a$10$..."
    inherits: [full-ops]
    ssh:
      webserver:
        roles: [read, operator, admin]
        auto_approve: true
    services:
      github:
        methods: [GET, POST, PUT, PATCH, DELETE]
      grafana:
        methods: [GET]
    remotes:
      demo-tools: {}
    dashboard: "admin"
```

### Permission Resolution

When an agent inherits from templates and also defines its own permissions,
the following resolution rules apply:

1. **Template merging** -- If `inherits` lists multiple templates, they are
   merged left-to-right. For SSH, services, and remotes, a key defined in a
   later template overwrites the same key from an earlier one. The `dashboard`
   field from the last template that sets it wins.

2. **Agent overrides** -- Any `ssh`, `services`, `remotes`, or `dashboard`
   fields defined directly on the agent override the corresponding inherited
   values for the same key. Keys not overridden by the agent are preserved
   from templates.

3. **SSH role intersection** -- The agent's effective SSH roles for a target
   are the intersection of:
   - The roles listed in the agent's resolved `ssh` block for that target
   - The `allowed_roles` defined on the target in the `targets` section
   An agent cannot gain a role that the target does not allow.

4. **Service allow-list** -- Only services explicitly listed (by name or via
   `"*"` wildcard) in the resolved permissions are accessible. Method
   restrictions further limit what the agent can do.

5. **Remote allow-list** -- Only remotes explicitly listed (by name or via
   `"*"` wildcard) are accessible for federation tool calls.

6. **Legacy mode** -- Agents that omit all RBAC fields operate with full
   access to all targets (using the target's `allowed_roles`), all services,
   and all remotes. This preserves backwards compatibility.

### Wildcard Entries

The `"*"` key is a wildcard that matches all targets, services, or remotes:

```yaml
ssh:
  "*":
    roles: [read]
    auto_approve: true
```

This grants the `read` role on every target that has `read` in its
`allowed_roles`. Specific target overrides take precedence over the wildcard.

### Dashboard Access Levels

| Level | Description |
|-------|-------------|
| `none` | No dashboard access. API calls return 403. |
| `viewer` | Read-only. Can view hosts, services, sessions, audit log. Cannot toggle or modify. |
| `operator` | Can toggle hosts/services/remotes on/off, revoke certificates. |
| `admin` | Full access including settings, host config changes, and terminal. |

### Discovery Filtering

The `list_targets`, `list_services`, and `list_remotes` MCP tools
automatically filter their results based on the calling agent's resolved
permissions. An agent only sees resources it is allowed to access.

### Example: Complete Policy with RBAC

```yaml
global:
  max_active_certs: 50
  default_ttl: "5m"
  max_ttl: "30m"
  rate_limit:
    requests_per_window: 60
    window_seconds: 60

roles:
  read:
    principal: "agent-read"
    description: "Read-only access"
    shell: "/bin/rbash"
    sudo: false
  operator:
    principal: "agent-op"
    description: "Operational commands"
    sudo:
      - "/usr/bin/systemctl status *"
      - "/usr/bin/systemctl restart *"
      - "/usr/bin/docker ps *"
      - "/usr/bin/docker logs *"
  admin:
    principal: "agent-admin"
    description: "Administrative access"
    sudo:
      - "/usr/bin/systemctl *"
      - "/usr/bin/docker *"
      - "/usr/bin/journalctl *"

targets:
  web-server:
    host: "10.0.1.10"
    port: 22
    allowed_roles: [read, operator, admin]
    auto_approve: true
  database:
    host: "10.0.1.20"
    port: 22
    allowed_roles: [read, operator]
    auto_approve: false

templates:
  monitoring:
    description: "Read-only monitoring"
    ssh:
      "*":
        roles: [read]
        auto_approve: true
    services:
      grafana:
        methods: [GET]
    remotes: {}
    dashboard: "viewer"

  full-ops:
    description: "Full operator access"
    ssh:
      "*":
        roles: [read, operator]
        auto_approve: true
    services:
      "*":
        methods: [GET, POST, PUT, PATCH, DELETE]
    remotes:
      "*": {}
    dashboard: "operator"

agents:
  claude:
    uid: 1000
    max_concurrent_certs: 20
    api_key_hash: "$2a$10$..."
    inherits: [full-ops]
    ssh:
      web-server:
        roles: [read, operator, admin]
        auto_approve: true
    services:
      github:
        methods: [GET, POST, PUT, PATCH, DELETE]
    dashboard: "admin"

  scraper:
    uid: 1001
    max_concurrent_certs: 3
    inherits: [monitoring]
    dashboard: "none"
```

In this example:
- **claude** inherits `full-ops` (read+operator on all targets, all services, all remotes), then overrides `web-server` to add `admin`, adds `github` to services, and sets dashboard to `admin`. Note: claude gets `admin` on `web-server` because the target allows it, but only `read+operator` on `database` because that target does not list `admin` in `allowed_roles`.
- **scraper** inherits `monitoring` (read-only SSH, GET on grafana, no remotes, viewer dashboard), then overrides dashboard to `none`.

---

## Environment Variables

All environment variables have corresponding CLI flags. The flag takes
precedence if both are set.

### Broker (ephyr broker / ephyr-broker)

| Variable | Default | Description |
|----------|---------|-------------|
| EPHYR_POLICY | /etc/ephyr/policy.yaml | Path to the policy YAML file. |
| EPHYR_SIGNER_SOCKET | /run/ephyr/signer.sock | Path to the signer's IPC Unix socket. |
| EPHYR_LISTEN | /run/ephyr/broker.sock | Path for the broker's own Unix socket (agent API). |
| EPHYR_AUDIT_LOG | /var/log/ephyr/audit.json | Path to the append-only JSON audit log file. |
| EPHYR_ADMIN_UIDS | 0 | Comma-separated list of UIDs allowed to perform admin operations (e.g., host toggle). Default is root only. |
| EPHYR_DASHBOARD_LISTEN | :8553 | TCP bind address for the web dashboard. Set to empty to disable. |
| EPHYR_DASHBOARD_TOKEN | (auto-generated) | Bearer token for dashboard API authentication. If empty, a random 48-hex-char token is generated at startup and logged (first 4 and last 4 chars only). |
| EPHYR_DASHBOARD_DIR | /opt/ephyr/dashboard | Directory containing static dashboard files (index.html, etc.). |
| EPHYR_MCP_LISTEN | :8554 | TCP bind address for the MCP JSON-RPC endpoint. Set to empty to disable. |
| EPHYR_SOCKET_GROUP | ephyr-agents | Unix group name for the broker socket. The socket is chown'd to this group with 0660 permissions so group members can connect. |
| EPHYR_AUTH_CACHE_TTL | 60s | TTL for the MCP API key authentication cache. Accepts Go duration strings (e.g., `"30s"`, `"2m"`, `"0"`). Set to `"0"` to disable caching entirely -- every MCP request will perform a full bcrypt comparison. The cache avoids repeated bcrypt work for the same API key within the TTL window. |
| EPHYR_POP_CLOCK_SKEW | 30s | Maximum allowed clock skew for proof-of-possession timestamp validation (Ephyr Bind). Accepts Go duration strings. PoP proofs with timestamps outside `now +/- skew` are rejected. Increase if agents and broker clocks are loosely synchronized. |

### Signer (ephyr signer / ephyr-signer)

| Variable | Default | Description |
|----------|---------|-------------|
| EPHYR_CA_KEY | /etc/ephyr/ca_key | Path to the Ed25519 CA private key file. |
| EPHYR_SOCKET | /run/ephyr/signer.sock | Unix socket path for the signer's IPC listener. |
| EPHYR_BROKER_UID | -1 (any) | UID allowed to connect to the signer socket. Set to the ephyr-broker user's UID (e.g., 999) to restrict access. -1 allows any caller. |

### BrokerConfig Struct Reference

The `BrokerConfig` struct in `internal/broker/server.go` maps directly to the
environment variables above. The `AuthCacheTTL` field controls the auth cache:

| Field | Type | Env Variable | Default | Description |
|-------|------|-------------|---------|-------------|
| `AuthCacheTTL` | `time.Duration` | `EPHYR_AUTH_CACHE_TTL` | 60s | TTL for cached MCP authentication results. Set to 0 to disable. When set to a negative sentinel value (-1), caching is explicitly disabled. |

The cache uses SHA-256 fingerprints of API keys as cache keys (the raw key is
never stored in the cache). Cache entries are automatically invalidated when
agents are added or removed from the policy.

---

## CLI Flags

### ephyr broker

```
  -policy PATH             Policy YAML file (env: EPHYR_POLICY)
  -signer-socket PATH      Signer IPC socket (env: EPHYR_SIGNER_SOCKET)
  -listen PATH             Broker API socket (env: EPHYR_LISTEN)
  -audit-log PATH          Audit log file (env: EPHYR_AUDIT_LOG)
  -admin-uid UID           Admin UID, repeatable (env: EPHYR_ADMIN_UIDS)
  -dashboard-listen ADDR   Dashboard TCP address (env: EPHYR_DASHBOARD_LISTEN)
  -dashboard-token TOKEN   Dashboard API token (env: EPHYR_DASHBOARD_TOKEN)
  -dashboard-dir DIR       Dashboard static files (env: EPHYR_DASHBOARD_DIR)
  -mcp-listen ADDR         MCP TCP address (env: EPHYR_MCP_LISTEN)
  -socket-group GROUP      Socket group name (env: EPHYR_SOCKET_GROUP)
  -auth-cache-ttl DUR      Auth cache TTL (env: EPHYR_AUTH_CACHE_TTL, default 60s, 0 disables)
  -pop-clock-skew DUR      PoP timestamp skew tolerance (env: EPHYR_POP_CLOCK_SKEW, default 30s)
  -version                 Print version and exit
```

The -admin-uid flag can be repeated to allow multiple admin UIDs:
```bash
ephyr broker -admin-uid 0 -admin-uid 1000
```

The legacy `ephyr-broker` binary accepts the same flags and is functionally identical.

### ephyr signer

```
  -ca-key PATH             CA private key file (env: EPHYR_CA_KEY)
  -socket PATH             IPC Unix socket (env: EPHYR_SOCKET)
  -broker-uid UID          Allowed caller UID (env: EPHYR_BROKER_UID)
```

The legacy `ephyr-signer` binary accepts the same flags and is functionally identical.

### ephyr (Agent CLI)

All subcommands accept these global flags:

```
  --socket PATH            Broker socket (default: /run/ephyr/broker.sock)
  --config-dir DIR         Config directory (default: ~/.ephyr)
```

Subcommand-specific flags:

**init:**
```
  --force                  Overwrite existing keypair
```

**request / ssh / exec:**
```
  -t, --target HOST        Target host name (required)
  -r, --role ROLE          Role to request (required)
  -d, --duration DUR       Certificate duration (default: 5m)
```

**exec** additionally requires -- followed by the remote command:
```bash
ephyr exec -t myhost -r operator -- systemctl status nginx
```

**status:** No additional flags. Lists active certificates with TTL remaining.

**targets:** No additional flags. Lists available targets with roles and approval mode.

**whoami:** No additional flags. Shows agent name, UID, session info.

**inspect:**
```
  --token TOKEN          Macaroon token to inspect (mac_ prefix)
```
Displays macaroon caveat chain, holder binding status, and effective envelope
for a given task token. Useful for debugging delegation attenuation and
verifying that caveats were applied correctly.

---

## Target Host Provisioning

Each SSH target must be configured to accept certificates signed by the
Ephyr CA. This involves five components.

### 1. CA Public Key

Copy the CA public key to the target host:

```bash
# On the Ephyr broker host:
scp /etc/ephyr/ca_key.pub root@target:/etc/ssh/ephyr_ca.pub
```

### 2. sshd_config

Add these directives to /etc/ssh/sshd_config on the target:

```
TrustedUserCAKeys /etc/ssh/ephyr_ca.pub
AuthorizedPrincipalsFile /etc/ssh/auth_principals/%u
```

TrustedUserCAKeys tells sshd to trust certificates signed by this CA.
AuthorizedPrincipalsFile maps user accounts to allowed principals using
per-user files (%u expands to the username).

### 3. Role Accounts

Create a system account for each role that needs access:

```bash
# Read-only role: restricted shell (rbash), no home directory
useradd -r -s /bin/rbash -M agent-read

# Operator role: standard bash shell
useradd -r -s /bin/bash -M agent-op

# Admin role: standard bash shell
useradd -r -s /bin/bash -M agent-admin
```

Using rbash for the read role prevents directory changes and restricts
command execution to commands in PATH.

### 4. Principal Files

Create a file for each role account in /etc/ssh/auth_principals/:

```bash
mkdir -p /etc/ssh/auth_principals

echo "agent-read"  > /etc/ssh/auth_principals/agent-read
echo "agent-op"    > /etc/ssh/auth_principals/agent-op
echo "agent-admin" > /etc/ssh/auth_principals/agent-admin

chmod 644 /etc/ssh/auth_principals/*
```

Each file contains the principal name(s) that are allowed to log in as that
user. The principal in the certificate must match an entry in the file for
the target user.

### 5. Sudoers Configuration

Configure sudo access per role as needed:

```bash
# /etc/sudoers.d/ephyr-agent-op
agent-op ALL=(ALL) NOPASSWD: /usr/bin/systemctl status *, \
                             /usr/bin/systemctl restart *, \
                             /usr/bin/docker ps, \
                             /usr/bin/docker logs *

# /etc/sudoers.d/ephyr-agent-admin
agent-admin ALL=(ALL) NOPASSWD: ALL
```

Lock sudoers files with chattr to prevent modification:

```bash
chmod 440 /etc/sudoers.d/ephyr-agent-*
chattr +i /etc/sudoers.d/ephyr-agent-*
```

After all changes, restart sshd:

```bash
systemctl restart sshd
```

---

## Service Configuration (services.json)

The HTTP proxy subsystem allows MCP agents to make authenticated HTTP requests
to internal and external services. Service configurations are stored in
/var/lib/ephyr/services.json and can be managed via the dashboard API or
directly in the file.

### File Format

```json
{
  "gitea": {
    "name": "Gitea",
    "url_prefix": "http://gitea.example.local:3000",
    "auth_type": "bearer",
    "credential": "your-api-token",
    "description": "Git hosting",
    "allowed_paths": ["/api/v1/"],
    "allowed_methods": ["GET", "POST", "PUT", "DELETE"],
    "max_response_kb": 1024,
    "timeout": 30,
    "headers": {}
  }
}
```

### ServiceConfig Fields

| Field | Type | Default | Required | Description |
|-------|------|---------|----------|-------------|
| name | string | (none) | **Yes** | Human-readable service name. Also used as the map key. |
| url_prefix | string | (none) | **Yes** | Base URL for the service. Requests matching this prefix are routed to this service and have credentials injected. Longest prefix match wins when multiple services could match. |
| auth_type | string | "none" | No | Credential injection method. One of: bearer, basic, header, query, none. |
| token_header | string | "Authorization" | No | Custom header name for header auth type, or query parameter name for query auth type. |
| token_prefix | string | "" | No | Prefix prepended to the credential value for header auth type (e.g., "token "). |
| username | string | "" | No | Username for basic auth type. |
| credential | string | "" | No | Token, password, or API key. Redacted as "***" in all API responses. |
| allowed_paths | list of strings | [] (all) | No | Glob patterns restricting which URL paths the agent may access. Empty means all paths allowed. Uses path.Match syntax. |
| allowed_methods | list of strings | [] (all) | No | HTTP methods the agent may use. Empty means all methods allowed. Case-insensitive comparison. |
| max_response_kb | int | 1024 | No | Maximum response body size in KB. Responses exceeding this are truncated and the result is flagged with truncated: true. |
| timeout | int | 30 | No | Request timeout in seconds. Capped at 120 seconds. The agent may request a shorter timeout but not longer. |
| description | string | "" | No | Human-readable description shown in service listings. |
| headers | map of string to string | {} | No | Extra static headers injected into every request to this service. |
| tls_verify | bool | false | No | Enable TLS certificate verification for HTTPS services. When false (default), `InsecureSkipVerify` is used for backward compatibility. When true, certificates are validated against the system CA store or a custom CA. |
| tls_ca | string | "" | No | Path to a PEM file containing one or more CA certificates. Used when `tls_verify` is true and the service uses a private/internal CA not in the system store. |
| tls_ca_inline | string | "" | No | Inline PEM-encoded CA certificate(s). Alternative to `tls_ca` for environments where a file path is not convenient (e.g., container deployments). Both `tls_ca` and `tls_ca_inline` can be used together; certificates from both sources are added to the pool. |
| tls_fingerprint | string | "" | No | SHA-256 fingerprint of the expected leaf certificate (hex-encoded). Accepts formats: `SHA256:aa:bb:...`, `sha256:aa:bb:...`, `aa:bb:...`, or `aabb...`. When set and `tls_verify` is true, the broker pins to this specific certificate in addition to CA validation. |

### TLS Verification

Each service gets its own HTTP client with independent TLS configuration.
When `tls_verify` is false (the default), the broker uses `InsecureSkipVerify`
for backward compatibility. When `tls_verify` is true, the broker validates
the server certificate chain.

**Example: HTTPS service with system CA:**
```json
{
  "portainer": {
    "name": "portainer",
    "url_prefix": "https://portainer.internal:9443",
    "auth_type": "bearer",
    "credential": "your-token",
    "tls_verify": true
  }
}
```

**Example: HTTPS service with custom CA and fingerprint pinning:**
```json
{
  "internal-api": {
    "name": "internal-api",
    "url_prefix": "https://api.internal:8443",
    "auth_type": "bearer",
    "credential": "your-token",
    "tls_verify": true,
    "tls_ca": "/etc/ephyr/certs/internal-ca.pem",
    "tls_fingerprint": "SHA256:ab:cd:ef:01:23:45:67:89:ab:cd:ef:01:23:45:67:89:ab:cd:ef:01:23:45:67:89:ab:cd:ef:01:23:45:67:89"
  }
}
```

**Startup warnings:** The broker logs a warning at startup for any HTTPS
service with `tls_verify: false`, referencing threat model item T7. This
helps identify services that should be migrated to verified TLS.

### Auth Types

**bearer** -- Adds an Authorization: Bearer header:
```json
{
  "auth_type": "bearer",
  "credential": "ghp_xxxxxxxxxxxx"
}
```
Resulting header: Authorization: Bearer ghp_xxxxxxxxxxxx

**basic** -- Adds HTTP Basic Auth (base64-encoded username:password):
```json
{
  "auth_type": "basic",
  "username": "admin",
  "credential": "secretpassword"
}
```

**header** -- Adds a custom header with optional prefix:
```json
{
  "auth_type": "header",
  "token_header": "X-API-Key",
  "token_prefix": "",
  "credential": "my-api-key-value"
}
```
Resulting header: X-API-Key: my-api-key-value

With a prefix:
```json
{
  "auth_type": "header",
  "token_header": "Authorization",
  "token_prefix": "token ",
  "credential": "giteaTokenHere"
}
```
Resulting header: Authorization: token giteaTokenHere

**query** -- Appends the credential as a URL query parameter:
```json
{
  "auth_type": "query",
  "token_header": "api_key",
  "credential": "my-secret-key"
}
```
Resulting URL: original-url?api_key=my-secret-key

**none** -- No credentials injected. Use for unauthenticated services or
when the agent provides its own headers:
```json
{
  "auth_type": "none"
}
```

### Credential Security

- Credentials are stored in plaintext in services.json (file mode 0600).
- All API responses redact the credential field to "***".
- Agents cannot see the actual credentials through any API endpoint.
- Credentials are only used server-side during request proxying.
- Agents cannot override injected Authorization headers via custom headers.

### Dashboard Service CRUD API

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | /v1/dashboard/services | List all services (credentials redacted) |
| GET | /v1/dashboard/services/{name} | Get a single service |
| PUT | /v1/dashboard/services/{name} | Create or update a service |
| DELETE | /v1/dashboard/services/{name} | Remove a service |

---

## Network Policy

The proxy engine enforces a network policy that controls which destinations
agents can reach. The default policy allows all RFC 1918 private addresses
and denies external (public internet) access.

### Default Policy

```json
{
  "allow_cidrs": ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"],
  "deny_cidrs": [],
  "external": "deny",
  "external_allow": []
}
```

### NetworkPolicy Fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| allow_cidrs | list of strings | ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"] | CIDR ranges the proxy may reach for private IPs. If non-empty, private IPs must match at least one entry. If empty, all private IPs are allowed. |
| deny_cidrs | list of strings | [] | CIDR ranges that are always denied. Evaluated before allow rules. Use to block sensitive subnets (e.g., management VLAN). |
| external | string | "deny" | Policy for public (non-RFC 1918) IPs. Options: "open" (allow all), "restricted" (allow only matching hostnames), "deny" (block all). |
| external_allow | list of strings | [] | Hostname glob patterns allowed when external is "restricted". Uses path.Match syntax (e.g., "*.github.com", "api.openai.com"). |

### Evaluation Order

1. DNS resolution of the target hostname (2-second timeout).
2. All resolved IPs are checked; every IP must pass policy.
3. Deny CIDRs are checked first -- any match means the request is denied.
4. For private IPs: if allow_cidrs is set, the IP must match at least one.
5. For public IPs: the external policy is applied.

### Examples

Block management VLAN while allowing all other private ranges:
```json
{
  "allow_cidrs": ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"],
  "deny_cidrs": ["192.168.10.0/24"],
  "external": "deny"
}
```

Allow specific external APIs:
```json
{
  "external": "restricted",
  "external_allow": ["api.github.com", "*.openai.com"]
}
```

---

## Host Configuration (hosts.json)

The broker maintains a persistent host configuration file at
/var/lib/ephyr/hosts.json for dashboard-managed settings that go beyond
the policy file (SSH credentials for terminal, OS info, display settings).

On startup, any targets defined in policy.yaml that do not have an existing
entry in hosts.json are seeded with defaults from the policy. Existing
entries are never overwritten by the policy seed.

### HostConfig Fields

| Field | Type | Description |
|-------|------|-------------|
| name | string | Host identifier (matches target name in policy). |
| host | string | IP address or hostname. Validated: no whitespace. |
| port | int | SSH port (1-65535). |
| vlan | int | VLAN ID (1-4094). |
| ssh_user | string | SSH username for dashboard terminal connections. |
| ssh_key_path | string | Path to SSH private key for terminal connections. |
| ssh_password | string | SSH password (redacted as "***" in API responses). |
| allowed_roles | list of strings | Roles allowed for this host. |
| max_ttl | string | Maximum certificate TTL (Go duration format). |
| default_ttl | string | Default certificate TTL (Go duration format). |
| auto_approve | bool | Whether requests are auto-approved. |
| description | string | Human-readable description. |
| os | string | Operating system label (e.g., "Debian 12"). |

### Dashboard Host Config API

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | /v1/dashboard/config/hosts | List all host configs (passwords redacted) |
| GET | /v1/dashboard/config/hosts/{name} | Get a single host config |
| PUT | /v1/dashboard/config/hosts/{name} | Create or update (merge) a host config |
| DELETE | /v1/dashboard/config/hosts/{name} | Remove a host config |
| GET | /v1/dashboard/config/roles | List all defined roles from policy |

Updates use merge semantics: only non-zero fields in the request body are
applied to the existing config. To explicitly clear a string field, send an
empty string. Boolean fields are always applied (can toggle off).

---

## Signal Handling

| Signal | Effect |
|--------|--------|
| SIGHUP | Hot-reload policy from disk. If the new file is invalid, the existing policy is preserved and an error is logged. The rate limiter is also reconfigured. |
| SIGTERM | Graceful shutdown: stop accepting new connections, wait up to 5 seconds for in-flight requests, shut down dashboard (3 second timeout), clean up sockets, close audit log. |
| SIGINT | Same as SIGTERM. |

---

## MCP Tools Reference

The MCP endpoint exposes these tools via JSON-RPC 2.0 at POST /mcp on the
TCP address configured by EPHYR_MCP_LISTEN (default :8554):

| Tool | Description | Required Args |
|------|-------------|---------------|
| list_targets | List available SSH targets and their allowed roles. | (none) |
| exec | Execute a command on a target host via SSH certificate auth. | target, role, command |
| session_create | Create a persistent SSH session for multiple commands. | target, role |
| session_close | Close a persistent SSH session. | session_id |
| list_sessions | List active persistent SSH sessions. | (none) |
| list_certs | List active SSH certificates for the authenticated agent. | (none) |
| http_request | Make an HTTP request through the authenticated proxy. | url |
| list_services | List configured proxy services with credential injection info. | (none) |
| list_remotes | List federated MCP servers and their available tools. | (none) |
| task_create | Create a task with scoped identity and macaroon token. | description |
| task_delegate | Delegate a child task with attenuated capabilities. | parent_task_id, description |
| task_info | Get task details, envelope, and lineage. | task_id |
| task_list | List active tasks for this agent. | (none) |
| task_revoke | Revoke a task and cascade to all children. | task_id |
| task_bind | Bind a delegated token to a holder key (two-phase PoP binding). | task_id, holder_pub_key |

MCP protocol version: 2025-03-26 (Streamable HTTP transport).

Federated tools from remote MCP servers appear as `{server}.{tool}` (e.g.,
`demo-tools.roll_dice`). These are discovered automatically via `list_remotes`
and proxied transparently by the broker.

Authentication: Authorization: Bearer <api-key> header on every request.
The API key is validated against bcrypt hashes in the policy file's
agent api_key_hash fields.

---

## Dashboard API Endpoints

All dashboard endpoints require a Bearer token (set via EPHYR_DASHBOARD_TOKEN).
Static files (/ and /static/*) are served without authentication.

### Core

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | /v1/health | Health check |
| GET | /v1/certs | List active certificates |
| GET | /v1/targets | List policy targets |

### Dashboard

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | /v1/dashboard/summary | System overview (uptime, counts, signer status) |
| GET | /v1/dashboard/hosts | List hosts with status and session counts |
| GET | /v1/dashboard/sessions | List active certificate sessions with TTL |
| GET | /v1/dashboard/audit?limit=50&type=grant | Query audit log (newest entries) |
| POST | /v1/dashboard/hosts/{name}/toggle | Enable/disable host access (revokes certs on disable) |
| POST | /v1/dashboard/sessions/{serial}/revoke | Revoke an active certificate |
| GET | /v1/events | WebSocket event stream (real-time updates) |
| GET | /v1/dashboard/terminal | WebSocket SSH terminal proxy |

### Activity Monitoring

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | /v1/dashboard/activity | Recent activity entries |
| GET | /v1/dashboard/activity/summary | Activity statistics |
| GET | /v1/dashboard/activity/agent/{name} | Per-agent activity |
