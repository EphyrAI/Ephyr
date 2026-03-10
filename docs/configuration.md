# Configuration Reference

Complete reference for all Clauth configuration options, covering the policy
file, environment variables, CLI flags, target provisioning, service proxy
configuration, and network policy.

---

## Policy File (policy.yaml)

The policy file is the central configuration that controls which agents exist,
what roles are available, which targets can be accessed, and what limits apply.
It is loaded at startup and can be hot-reloaded by sending SIGHUP to the
broker process (or running `systemctl reload clauth-broker`).

Default path: `/etc/clauth/policy.yaml`

### Full Annotated Example

```yaml
# Clauth Policy -- full reference example
# Hot-reload: send SIGHUP to the broker, or systemctl reload clauth-broker

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
  operator:
    principal: "agent-op"
    description: "Service management access"
  admin:
    principal: "agent-admin"
    description: "Full administrative access"

targets:
  webserver:
    host: "192.168.100.10"
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

**Validation rules:**
- At least one agent must be defined (startup fails otherwise).
- No two agents may share the same uid (startup fails on duplicate).

### roles Section

Each key under roles is the role's logical name (e.g., "read", "operator").
Role names are referenced by targets in their allowed_roles lists.

| Field | Type | Default | Required | Description |
|-------|------|---------|----------|-------------|
| principal | string | (none) | **Yes** | SSH principal name embedded in the certificate. This maps to a user account on the target host via AuthorizedPrincipalsFile. Example: "agent-read" maps to the agent-read system user. |
| description | string | "" | No | Human-readable description of what this role can do. |

**Validation rules:**
- Every role referenced in a target's allowed_roles must be defined here.
- principal must not be empty.

### targets Section

Each key under targets is the target's logical name (e.g., "docker-host").
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
| description | string | "" | No | Human-readable description for dashboards and audit logs. |

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

## Environment Variables

All environment variables have corresponding CLI flags. The flag takes
precedence if both are set.

### Broker (clauth-broker)

| Variable | Default | Description |
|----------|---------|-------------|
| CLAUTH_POLICY | /etc/clauth/policy.yaml | Path to the policy YAML file. |
| CLAUTH_SIGNER_SOCKET | /run/clauth/signer.sock | Path to the signer's IPC Unix socket. |
| CLAUTH_LISTEN | /run/clauth/broker.sock | Path for the broker's own Unix socket (agent API). |
| CLAUTH_AUDIT_LOG | /var/log/clauth/audit.json | Path to the append-only JSON audit log file. |
| CLAUTH_ADMIN_UIDS | 0 | Comma-separated list of UIDs allowed to perform admin operations (e.g., host toggle). Default is root only. |
| CLAUTH_DASHBOARD_LISTEN | :8553 | TCP bind address for the web dashboard. Set to empty to disable. |
| CLAUTH_DASHBOARD_TOKEN | (auto-generated) | Bearer token for dashboard API authentication. If empty, a random 48-hex-char token is generated at startup and logged (first 4 and last 4 chars only). |
| CLAUTH_DASHBOARD_DIR | /opt/clauth/dashboard | Directory containing static dashboard files (index.html, etc.). |
| CLAUTH_MCP_LISTEN | :8554 | TCP bind address for the MCP JSON-RPC endpoint. Set to empty to disable. |
| CLAUTH_SOCKET_GROUP | clauth-agents | Unix group name for the broker socket. The socket is chown'd to this group with 0660 permissions so group members can connect. |

### Signer (clauth-signer)

| Variable | Default | Description |
|----------|---------|-------------|
| CLAUTH_CA_KEY | /etc/clauth/ca_key | Path to the Ed25519 CA private key file. |
| CLAUTH_SOCKET | /run/clauth/signer.sock | Unix socket path for the signer's IPC listener. |
| CLAUTH_BROKER_UID | -1 (any) | UID allowed to connect to the signer socket. Set to the clauth-broker user's UID (e.g., 999) to restrict access. -1 allows any caller. |

---

## CLI Flags

### clauth-broker

```
  -policy PATH             Policy YAML file (env: CLAUTH_POLICY)
  -signer-socket PATH      Signer IPC socket (env: CLAUTH_SIGNER_SOCKET)
  -listen PATH             Broker API socket (env: CLAUTH_LISTEN)
  -audit-log PATH          Audit log file (env: CLAUTH_AUDIT_LOG)
  -admin-uid UID           Admin UID, repeatable (env: CLAUTH_ADMIN_UIDS)
  -dashboard-listen ADDR   Dashboard TCP address (env: CLAUTH_DASHBOARD_LISTEN)
  -dashboard-token TOKEN   Dashboard API token (env: CLAUTH_DASHBOARD_TOKEN)
  -dashboard-dir DIR       Dashboard static files (env: CLAUTH_DASHBOARD_DIR)
  -mcp-listen ADDR         MCP TCP address (env: CLAUTH_MCP_LISTEN)
  -socket-group GROUP      Socket group name (env: CLAUTH_SOCKET_GROUP)
  -version                 Print version and exit
```

The -admin-uid flag can be repeated to allow multiple admin UIDs:
```bash
clauth-broker -admin-uid 0 -admin-uid 1000
```

### clauth-signer

```
  -ca-key PATH             CA private key file (env: CLAUTH_CA_KEY)
  -socket PATH             IPC Unix socket (env: CLAUTH_SOCKET)
  -broker-uid UID          Allowed caller UID (env: CLAUTH_BROKER_UID)
```

### clauth (Agent CLI)

All subcommands accept these global flags:

```
  --socket PATH            Broker socket (default: /run/clauth/broker.sock)
  --config-dir DIR         Config directory (default: ~/.clauth)
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
clauth exec -t myhost -r operator -- systemctl status nginx
```

**status:** No additional flags. Lists active certificates with TTL remaining.

**targets:** No additional flags. Lists available targets with roles and approval mode.

**whoami:** No additional flags. Shows agent name, UID, session info.

---

## Target Host Provisioning

Each SSH target must be configured to accept certificates signed by the
Clauth CA. This involves five components.

### 1. CA Public Key

Copy the CA public key to the target host:

```bash
# On the Clauth broker host:
scp /etc/clauth/ca_key.pub root@target:/etc/ssh/clauth_ca.pub
```

### 2. sshd_config

Add these directives to /etc/ssh/sshd_config on the target:

```
TrustedUserCAKeys /etc/ssh/clauth_ca.pub
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
# /etc/sudoers.d/clauth-agent-op
agent-op ALL=(ALL) NOPASSWD: /usr/bin/systemctl status *, \
                             /usr/bin/systemctl restart *, \
                             /usr/bin/docker ps, \
                             /usr/bin/docker logs *

# /etc/sudoers.d/clauth-agent-admin
agent-admin ALL=(ALL) NOPASSWD: ALL
```

Lock sudoers files with chattr to prevent modification:

```bash
chmod 440 /etc/sudoers.d/clauth-agent-*
chattr +i /etc/sudoers.d/clauth-agent-*
```

After all changes, restart sshd:

```bash
systemctl restart sshd
```

---

## Service Configuration (services.json)

The HTTP proxy subsystem allows MCP agents to make authenticated HTTP requests
to internal services. Service configurations are stored in
/var/lib/clauth/services.json and can be managed via the dashboard API or
directly in the file.

### File Format

```json
{
  "gitea": {
    "name": "Gitea",
    "url_prefix": "http://192.168.100.54:3000",
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
/var/lib/clauth/hosts.json for dashboard-managed settings that go beyond
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
TCP address configured by CLAUTH_MCP_LISTEN (default :8554):

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

MCP protocol version: 2025-03-26 (Streamable HTTP transport).

Authentication: Authorization: Bearer <api-key> header on every request.
The API key is validated against bcrypt hashes in the policy file's
agent api_key_hash fields.

---

## Dashboard API Endpoints

All dashboard endpoints require a Bearer token (set via CLAUTH_DASHBOARD_TOKEN).
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
