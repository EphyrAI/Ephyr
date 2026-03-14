# Ephyr MCP Integration Guide

How to connect AI agents to Ephyr infrastructure operations via the Model Context
Protocol (MCP).

---

## What is MCP?

The Model Context Protocol (MCP) is a structured tool interface for large language
models. It uses JSON-RPC 2.0 over HTTP to expose server-side "tools" that any
compatible AI agent can discover and call. Ephyr implements MCP Streamable HTTP
transport (protocol version `2025-03-26`), exposing infrastructure
operations -- SSH command execution, session management, and authenticated HTTP
proxying -- as tools that agents can invoke programmatically.

The key benefit: agents do not need SSH keys, credentials, or direct network access
to target hosts. Ephyr handles ephemeral certificate generation, credential
injection, and audit logging transparently.

---

## Architecture

```
┌─────────────────────┐
│   AI Agent          │
│   (Claude Code)     │
└────────┬────────────┘
         │ JSON-RPC 2.0 / HTTP
         │ Authorization: Bearer <api-key>
         ▼
┌─────────────────────────────────────────────┐
│   Ephyr Broker (port 8554)                 │
│                                             │
│   ┌───────────┐  ┌──────────────────────┐   │
│   │ MCP Router│  │ Resource Provider    │   │
│   │           │  │                      │   │
│   │ tools/*   │  │ resources/list       │   │
│   │ resources │  │ resources/read       │   │
│   └─────┬─────┘  └──────────┬───────────┘   │
│         │                   │               │
│   ┌─────▼─────┐  ┌─────────▼───────────┐   │
│   │ Tool      │  │ Proxy Engine        │   │
│   │ Handlers  │  │                     │   │
│   │           │  │ Credential Injection│   │
│   │ exec      │  │ Network Policy      │   │
│   │ session_* │  │ Activity Tracking   │   │
│   │ list_*    │  └─────────┬───────────┘   │
│   │ http_*    │            │               │
│   └─────┬─────┘            │               │
│         │                  ▼               │
│   ┌─────▼─────┐  ┌────────────────────┐   │
│   │ SSH Exec  │  │ External Services  │   │
│   │ Engine    │  │ (GitHub, Gitea,    │   │
│   └─────┬─────┘  │  Portainer, etc.) │   │
│         │        └────────────────────┘   │
└─────────┼────────────────────────────────┘
          │ Unix socket IPC
          ▼
┌─────────────────────┐
│   Ephyr Signer     │
│                     │
│   Ed25519 CA Key    │
│   Certificate Gen   │
└─────────┬───────────┘
          │ Ephemeral SSH cert
          ▼
┌─────────────────────┐
│   Target Hosts      │
│                     │
│   target-1          │
│   target-2          │
│   target-3          │
└─────────────────────┘
```

**Data flow for tool calls:**

1. Agent sends `tools/call` with API key.
2. Broker validates key, checks policy (rate limits, allowed roles).
3. For `exec`/`session_*`: broker requests ephemeral cert from signer via Unix
   socket, then SSHs to target host with the short-lived certificate.
4. For `http_request`: broker resolves the service, injects stored credentials,
   proxies the HTTP request, and strips credentials from the response.
5. Results returned as JSON-RPC response with `content` array.

**Data flow for resource reads:**

1. Agent sends `resources/read` with a `ephyr://` URI.
2. Broker dynamically generates Markdown content from live policy, config, and
   state data.
3. Content returned as a `text` resource in the JSON-RPC response.

---

## Setup

### 1. Generate API Key

On the Ephyr broker host, generate a bcrypt hash for the agent's API key:

```bash
# Generate a random key
openssl rand -base64 32 > /etc/ephyr/mcp_api_key

# Hash it for policy.yaml
htpasswd -nbBC 10 "" "$(cat /etc/ephyr/mcp_api_key)" | cut -d: -f2
```

### 2. Configure Policy

Add the API key hash and MCP settings to `/etc/ephyr/policy.yaml`:

```yaml
agents:
  claude:
    uid: 1000
    api_key_hash: "$2a$10$..."   # bcrypt hash from step 1
    max_concurrent_certs: 5
    description: "Claude Code agent"

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

targets:
  app-server:
    host: "10.0.1.10"
    port: 22
    allowed_roles: [read, operator, admin]
    auto_approve: true
  web-server:
    host: "10.0.1.20"
    port: 22
    allowed_roles: [read, operator]
    auto_approve: true
  blog-server:
    host: "10.0.1.30"
    port: 22
    allowed_roles: [read, operator]
    auto_approve: true
```

Reload the broker to apply:

```bash
systemctl reload ephyr-broker
```

### 3. Configure Client

Add the MCP server to your AI agent's configuration. For Claude Code, edit
`~/.claude/projects/<project>/settings.json`:

```json
{
  "mcpServers": {
    "ephyr": {
      "type": "url",
      "url": "http://BROKER_HOST:8554/mcp",
      "headers": {
        "Authorization": "Bearer YOUR_API_KEY"
      }
    }
  }
}
```

### 4. Verify Connection

The agent should be able to initialize and list tools:

```bash
curl -X POST http://BROKER_HOST:8554/mcp \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {
      "protocolVersion": "2025-03-26",
      "capabilities": {},
      "clientInfo": { "name": "test", "version": "1.0" }
    }
  }'
```

---

## MCP Protocol Flow

### Standard Flow

1. **Initialize** -- Client sends `initialize` with protocol version and capabilities.
   Server responds with its capabilities (tools and resources supported).

2. **Notification** -- Client sends `notifications/initialized` to confirm.

3. **List tools** -- Client sends `tools/list` to discover available tools.

4. **Call tools** -- Client sends `tools/call` with tool name and arguments.
   Server executes and returns results.

5. **List resources** (optional) -- Client sends `resources/list` to discover
   available resources. Server returns URIs, names, and descriptions.

6. **Read resources** (optional) -- Client sends `resources/read` with a resource
   URI. Server returns structured content about the requested topic.

### Initialize

**Request:**

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "initialize",
  "params": {
    "protocolVersion": "2025-03-26",
    "capabilities": {},
    "clientInfo": {
      "name": "claude-code",
      "version": "1.0.0"
    }
  }
}
```

**Response:**

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "protocolVersion": "2025-03-26",
    "capabilities": {
      "tools": {
        "listChanged": false
      },
      "resources": {
        "listChanged": false
      }
    },
    "serverInfo": {
      "name": "ephyr-broker",
      "version": "0.1.0"
    }
  }
}
```

The `capabilities` object declares both `tools` and `resources` support. The
`listChanged: false` indicates the available tools and resources are static for
the lifetime of the connection.

### List Tools

**Request:**

```json
{
  "jsonrpc": "2.0",
  "id": 2,
  "method": "tools/list",
  "params": {}
}
```

**Response:** Returns array of 10 tool definitions with names, descriptions, and
JSON Schema for input parameters. See "Available Tools" below for details.

### Call Tool

**Request:**

```json
{
  "jsonrpc": "2.0",
  "id": 3,
  "method": "tools/call",
  "params": {
    "name": "exec",
    "arguments": {
      "target": "web-server",
      "role": "read",
      "command": "uptime"
    }
  }
}
```

**Response:**

```json
{
  "jsonrpc": "2.0",
  "id": 3,
  "result": {
    "content": [
      {
        "type": "text",
        "text": "{\"stdout\": \" 14:32:01 up 12 days, ...\", \"stderr\": \"\", \"exit_code\": 0}"
      }
    ]
  }
}
```

### List Resources

**Request:**

```json
{
  "jsonrpc": "2.0",
  "id": 4,
  "method": "resources/list",
  "params": {}
}
```

**Response** (showing 2 of 7 resources):

```json
{
  "jsonrpc": "2.0",
  "id": 4,
  "result": {
    "resources": [
      {
        "uri": "ephyr://overview",
        "name": "System Overview",
        "description": "High-level summary of broker capabilities, targets, services, and agent permissions",
        "mimeType": "text/markdown"
      },
      {
        "uri": "ephyr://targets",
        "name": "SSH Targets",
        "description": "Available SSH targets with hosts, ports, allowed roles, TTLs, auto-approve status",
        "mimeType": "text/markdown"
      }
    ]
  }
}
```

All 7 resources are documented in the "MCP Resources" section below.

### Read Resource

**Request:**

```json
{
  "jsonrpc": "2.0",
  "id": 5,
  "method": "resources/read",
  "params": { "uri": "ephyr://overview" }
}
```

**Response:**

```json
{
  "jsonrpc": "2.0",
  "id": 5,
  "result": {
    "contents": [{
      "uri": "ephyr://overview",
      "mimeType": "text/markdown",
      "text": "# Ephyr System Overview\n\n## Available SSH Targets (3)\n..."
    }]
  }
}
```

The `text` field contains Markdown-formatted content generated dynamically from
live broker state. See "MCP Resources" below for full content examples.

---

## Available Tools

### 1. `list_targets`

Lists SSH targets available to the authenticated agent, including connection
details and allowed roles.

**Parameters:** None

**Example call:**

```json
{
  "name": "list_targets",
  "arguments": {}
}
```

**Response:**

```json
{
  "content": [
    {
      "type": "text",
      "text": "[{\"name\": \"web-server\", \"host\": \"10.0.1.10\", \"port\": 22, \"roles\": [\"read\", \"operator\", \"admin\"], \"ttl\": 300, \"auto_approve\": true}, {\"name\": \"app-server\", \"host\": \"10.0.1.20\", \"port\": 22, \"roles\": [\"read\", \"operator\"], \"ttl\": 300, \"auto_approve\": true}, {\"name\": \"blog-server\", \"host\": \"10.0.1.30\", \"port\": 22, \"roles\": [\"read\", \"operator\"], \"ttl\": 300, \"auto_approve\": true}]"
    }
  ]
}
```

**Notes:**
- Returns only targets the authenticated agent is allowed to access per policy.
- The `ttl` is the certificate lifetime in seconds.
- `auto_approve: true` means no manual approval step is required.

---

### 2. `exec`

Executes a command on a target host via an ephemeral SSH certificate. This is
the primary tool for infrastructure operations.

**Parameters:**

| Parameter   | Type   | Required | Description |
|-------------|--------|----------|-------------|
| `target`    | string | Yes      | Target name (e.g., `web-server`, `app-server`, `blog-server`) |
| `role`      | string | Yes      | Role to use: `read`, `operator`, or `admin` |
| `command`   | string | Yes      | Shell command to execute |
| `session_id`| string | No       | Reuse a persistent session (see `session_create`) |

**Example call (one-shot):**

```json
{
  "name": "exec",
  "arguments": {
    "target": "web-server",
    "role": "read",
    "command": "docker ps --format '{{.Names}}: {{.Status}}' | head -10"
  }
}
```

**Example call (with session):**

```json
{
  "name": "exec",
  "arguments": {
    "target": "web-server",
    "role": "operator",
    "command": "docker restart tandoor-web",
    "session_id": "ses_abc123"
  }
}
```

**Response:**

```json
{
  "content": [
    {
      "type": "text",
      "text": "{\"stdout\": \"grafana: Up 12 days\\ninfluxdb: Up 12 days\\n...\", \"stderr\": \"\", \"exit_code\": 0}"
    }
  ]
}
```

**Execution flow (one-shot):**

1. Generate ephemeral Ed25519 keypair (in-memory, never written to disk).
2. Request certificate from signer via Unix socket IPC.
3. Signer signs the public key with the CA, returns certificate.
4. SSH to target using ephemeral key + certificate.
5. Execute command, capture stdout/stderr/exit code.
6. Return results; ephemeral key is discarded.

**Execution flow (session):**

1. Look up existing persistent SSH connection by `session_id`.
2. Open new channel on the existing connection.
3. Execute command, capture results.
4. Return results; connection remains open for reuse.

**Validation:**
- `target` must be in the agent's allowed target list.
- `role` must be in the agent's allowed roles AND the target's allowed roles.
- `command` must not be empty.
- `session_id`, if provided, must reference an active session owned by this agent.

**Role mapping:**

| Role     | SSH Principal | Shell | Typical use |
|----------|--------------|-------|-------------|
| read     | agent-read   | rbash | Status checks, log viewing, non-destructive queries |
| operator | agent-op     | bash  | Service restarts, config changes, deployments |
| admin    | agent-admin  | bash  | System administration, package management, user ops |

---

### 3. `session_create`

Opens a persistent SSH connection to a target host. Subsequent `exec` calls
with the returned `session_id` reuse this connection, avoiding the ~850ms
overhead of certificate generation and SSH handshake on each call.

**Parameters:**

| Parameter | Type   | Required | Description |
|-----------|--------|----------|-------------|
| `target`  | string | Yes      | Target name |
| `role`    | string | Yes      | Role to use |

**Example call:**

```json
{
  "name": "session_create",
  "arguments": {
    "target": "web-server",
    "role": "operator"
  }
}
```

**Response:**

```json
{
  "content": [
    {
      "type": "text",
      "text": "{\"session_id\": \"ses_a1b2c3d4\", \"target\": \"web-server\", \"role\": \"operator\", \"created\": \"2026-03-10T14:30:00Z\", \"idle_timeout\": \"5m0s\"}"
    }
  ]
}
```

**Validation:**
- Same target/role checks as `exec`.
- Maximum 5 concurrent sessions per agent (configurable in policy).
- Sessions auto-close after 5 minutes of idle time.

---

### 4. `session_close`

Closes a persistent SSH session and releases the connection.

**Parameters:**

| Parameter    | Type   | Required | Description |
|--------------|--------|----------|-------------|
| `session_id` | string | Yes      | Session ID to close |

**Example call:**

```json
{
  "name": "session_close",
  "arguments": {
    "session_id": "ses_a1b2c3d4"
  }
}
```

**Response:**

```json
{
  "content": [
    {
      "type": "text",
      "text": "{\"closed\": true, \"session_id\": \"ses_a1b2c3d4\"}"
    }
  ]
}
```

**Validation:**
- `session_id` must reference an active session owned by this agent.
- Closing a session that has already been closed returns an error.

---

### 5. `list_sessions`

Lists all active persistent SSH sessions for the authenticated agent.

**Parameters:** None

**Example call:**

```json
{
  "name": "list_sessions",
  "arguments": {}
}
```

**Response:**

```json
{
  "content": [
    {
      "type": "text",
      "text": "[{\"session_id\": \"ses_a1b2c3d4\", \"target\": \"web-server\", \"role\": \"operator\", \"created\": \"2026-03-10T14:30:00Z\", \"last_used\": \"2026-03-10T14:32:15Z\", \"idle_timeout\": \"5m0s\"}]"
    }
  ]
}
```

**Notes:**
- Only shows sessions belonging to the authenticated agent.
- `last_used` updates on every `exec` call that uses the session.

---

### 6. `list_certs`

Lists active (non-expired) SSH certificates issued to the authenticated agent.

**Parameters:** None

**Example call:**

```json
{
  "name": "list_certs",
  "arguments": {}
}
```

**Response:**

```json
{
  "content": [
    {
      "type": "text",
      "text": "[{\"serial\": \"1741612200\", \"target\": \"web-server\", \"principal\": \"agent-op\", \"issued\": \"2026-03-10T14:30:00Z\", \"expires\": \"2026-03-10T14:35:00Z\", \"remaining\": \"3m42s\"}]"
    }
  ]
}
```

**Notes:**
- Expired certificates are automatically pruned and not shown.
- The `remaining` field is computed at response time.

---

### 7. `http_request`

Makes an HTTP request through the authenticated proxy. Ephyr injects the
appropriate credentials for the target service -- the agent never sees tokens,
passwords, or API keys.

**Parameters:**

| Parameter | Type   | Required | Description |
|-----------|--------|----------|-------------|
| `url`     | string | Yes      | Full URL to request (must match a configured service) |
| `method`  | string | No       | HTTP method (default: `GET`) |
| `headers` | object | No       | Additional request headers |
| `body`    | string | No       | Request body (for POST/PUT/PATCH) |

**Example call (GET):**

```json
{
  "name": "http_request",
  "arguments": {
    "url": "https://api.github.com/repos/YOUR_ORG/YOUR_REPO/commits?per_page=5",
    "method": "GET"
  }
}
```

**Example call (POST):**

```json
{
  "name": "http_request",
  "arguments": {
    "url": "http://UPTIME_KUMA_HOST:3001/api/status-page/default",
    "method": "GET"
  }
}
```

**Response:**

```json
{
  "content": [
    {
      "type": "text",
      "text": "{\"status_code\": 200, \"headers\": {\"content-type\": \"application/json\"}, \"body\": \"[{\\\"sha\\\": \\\"abc123\\\", ...}]\"}"
    }
  ]
}
```

**Credential injection types:**

| Type    | Behavior |
|---------|----------|
| bearer  | Adds `Authorization: Bearer <token>` header |
| basic   | Adds `Authorization: Basic <base64>` header |
| header  | Adds custom header with optional prefix (e.g., `X-Api-Key: <value>`) |
| query   | Appends credential as query parameter |
| none    | No credentials injected (unauthenticated proxy) |

**Validation:**
- URL must match a configured service's URL prefix.
- URL must be allowed by the network policy (RFC 1918 + explicitly allowed domains).
- Method must be a valid HTTP method.
- Response bodies larger than 1MB are truncated.

---

### 8. `list_services`

Lists HTTP proxy services configured in the broker, showing what web services
are available for proxying.

**Parameters:** None

**Example call:**

```json
{
  "name": "list_services",
  "arguments": {}
}
```

**Response:**

```json
{
  "content": [
    {
      "type": "text",
      "text": "[{\"name\": \"github\", \"url_prefix\": \"https://api.github.com\", \"auth_type\": \"bearer\"}, {\"name\": \"gitea\", \"url_prefix\": \"http://GITEA_HOST:3000\", \"auth_type\": \"header\"}, {\"name\": \"portainer\", \"url_prefix\": \"https://PORTAINER_HOST:9443\", \"auth_type\": \"bearer\"}, {\"name\": \"grafana\", \"url_prefix\": \"http://GRAFANA_HOST:3030\", \"auth_type\": \"bearer\"}, {\"name\": \"uptime-kuma\", \"url_prefix\": \"http://UPTIME_KUMA_HOST:3001\", \"auth_type\": \"none\"}, {\"name\": \"homepage\", \"url_prefix\": \"http://HOMEPAGE_HOST:3000\", \"auth_type\": \"none\"}, {\"name\": \"broker-api\", \"url_prefix\": \"http://BROKER_API_HOST:8550\", \"auth_type\": \"none\"}]"
    }
  ]
}
```

**Notes:**
- Credentials are never included in the response -- only auth type is shown.
- Service configuration is managed via `/var/lib/ephyr/services.json` or
  the dashboard's Services view.

---

### 9. `list_remotes`

Lists federated MCP servers configured in the broker, showing available
remote servers and their tools.

**Parameters:** None

**Example call:**

```json
{
  "name": "list_remotes",
  "arguments": {}
}
```

**Response:**

```json
{
  "content": [
    {
      "type": "text",
      "text": "[{\"name\": \"demo-tools\", \"url\": \"http://REMOTE_HOST:8560/mcp\", \"status\": \"connected\", \"tools\": 5}]"
    }
  ]
}
```

**Notes:**
- Returns only remotes the authenticated agent is allowed to access per RBAC policy.
- Federated tools from remotes appear as `{server}.{tool}` (e.g., `demo-tools.roll_dice`).
- Remote configuration is managed via `/var/lib/ephyr/remotes.json` or
  the dashboard's MCP Servers view.

---

### 10. `{server}.{tool}` (Federated Tools)

Calls a tool on a federated remote MCP server. The broker proxies the call
transparently, injecting credentials if configured.

**Parameters:** Vary by remote tool (discovered via `list_remotes` or `tools/list`).

**Notes:**
- Federated tools are namespaced: `{remote_name}.{tool_name}`.
- All federated calls are audited and tracked in the activity log.
- The agent never communicates directly with the remote server.

---

## MCP Resources

Resources are a read-only discovery mechanism in MCP. Unlike tools, which perform
actions, resources provide structured information that agents can read to understand
the system they are connected to. Ephyr exposes 7 resources under the `ephyr://`
URI scheme.

### Why Resources Matter

When an AI agent connects to Ephyr via MCP, it has no inherent knowledge of what
targets exist, what roles are available, or what services can be proxied. Without
resources, the agent would need hardcoded documentation or trial-and-error tool
calls to discover the environment.

Resources solve this with **agent self-discovery**: on first connection, the agent
reads `ephyr://overview` and immediately understands the full scope of available
infrastructure. This is the recommended bootstrap pattern for any MCP client
integration.

### Available Resources

#### `ephyr://overview` -- System Overview

High-level summary of everything the broker offers. This is the recommended first
resource for any agent to read after initialization.

**Content includes:**
- Broker version and capabilities
- Number of available SSH targets (with names, hosts, and allowed roles)
- Number of configured HTTP proxy services
- Agent's own permissions (name, roles, max certs, auto-approve status)
- Quick-start guidance for common operations

**Example content** (abbreviated):

```markdown
# Ephyr System Overview
## Available SSH Targets (3)
| Target | Host | Roles | TTL | Auto-approve |
| web-server | TARGET_HOST:22 | read, operator, admin | 5m | yes |
| app-server | TARGET_HOST:22 | read, operator | 5m | yes |
| blog-server | TARGET_HOST:22 | read, operator | 5m | yes |
## HTTP Proxy Services (7)
github, gitea, portainer, grafana, uptime-kuma, homepage, broker-api
## Your Permissions
Agent: claude | Roles: read, operator, admin | Max certs: 5 | Auto-approve: yes
## Quick Start
1. Run a command: exec with target, role, and command
2. For multiple commands: session_create then exec with session_id
3. Access web services: http_request with the service URL
```

---

#### `ephyr://targets` -- SSH Targets

Detailed information about each SSH target the agent can access.

**Content includes:**
- Target name, hostname, port
- Allowed roles and their SSH principals
- Certificate TTL and auto-approve status
- Host description and purpose

**Example content** (abbreviated):

```markdown
# SSH Targets
## web-server
Host: TARGET_HOST:22 | Roles: read, operator, admin | TTL: 5m | Auto-approve: yes
## app-server
Host: TARGET_HOST:22 | Roles: read, operator | TTL: 5m | Auto-approve: yes
## blog-server
Host: TARGET_HOST:22 | Roles: read, operator | TTL: 5m | Auto-approve: yes
```

---

#### `ephyr://services` -- HTTP Proxy Services

Detailed information about each configured HTTP proxy service.

**Content includes:**
- Service name and URL prefix
- Authentication type (bearer, basic, header, query, none)
- Description and usage notes
- Example URLs for common API endpoints

**Example content** (abbreviated):

```markdown
# HTTP Proxy Services
Credentials injected automatically -- never provide tokens or API keys.
| Service | URL Prefix | Auth |
| github | https://api.github.com | bearer |
| gitea | http://GITEA_HOST:3000 | header |
| portainer | https://PORTAINER_HOST:9443 | bearer |
| grafana | http://GRAFANA_HOST:3030 | bearer |
| uptime-kuma | http://UPTIME_KUMA_HOST:3001 | none |
| homepage | http://HOMEPAGE_HOST:3000 | none |
| broker-api | http://BROKER_API_HOST:8550 | none |
```

---

#### `ephyr://roles` -- Roles & Permissions

Explains the role hierarchy and what each role can do.

**Content includes:**
- Role name and corresponding SSH principal
- Shell type (rbash vs bash)
- Intended use cases
- Escalation notes

**Example content** (abbreviated):

```markdown
# Roles & Permissions
## read (SSH: agent-read) -- rbash
Status checks, log viewing, non-destructive queries
## operator (SSH: agent-op) -- bash
Service restarts, config changes, Docker operations
## admin (SSH: agent-admin) -- bash
Full system access, package management (targets must explicitly allow)
## Guidance
Start with read, escalate to operator/admin only when needed.
```

---

#### `ephyr://status` -- Agent Status

Shows the authenticated agent's current state -- active certificates, open
sessions, and recent activity. This resource is agent-specific: each agent
sees only its own data.

**Content includes:**
- Active certificate count and details
- Open session count and details
- Recent activity log (last 10 entries)

**Example content** (abbreviated):

```markdown
# Agent Status: claude
## Active Certificates (1)
| Serial | Target | Principal | Expires | Remaining |
| 1741612200 | web-server | agent-op | 2026-03-10T14:35:00Z | 3m42s |
## Open Sessions (1)
| Session ID | Target | Role | Idle |
| ses_a1b2c3d4 | web-server | operator | 47s |
## Recent Activity
- 14:32:15 exec web-server (operator): docker ps -- exit 0
- 14:30:00 session_create web-server -- ses_a1b2c3d4
```

---

#### `ephyr://tools` -- Tools Reference

Quick-reference card for all 14 MCP tools. Designed for agents that want a
compact cheat-sheet without reading full documentation.

**Content includes:**
- Tool name, required parameters, optional parameters
- One-line description
- Minimal usage example for each tool

**Example content** (abbreviated):

```markdown
# Tools Quick Reference
| Tool | Required Params | Optional | Description |
| exec | target, role, command | session_id | Run command on target |
| session_create | target, role | | Open persistent SSH connection |
| session_close | session_id | | Close persistent session |
| list_sessions | (none) | | List active sessions |
| list_targets | (none) | | List available targets |
| list_certs | (none) | | List active certificates |
| http_request | url | method, headers, body | Proxied HTTP request |
| list_services | (none) | | List proxy services |
| list_remotes | (none) | | List federated MCP servers |
```

---

#### `ephyr://remotes` -- Federated MCP Servers

Lists configured federated MCP servers, their connection status, and
available tools.

**Content includes:**
- Remote server name and URL
- Connection status and tool count
- Available tools from each remote
- Usage examples for federated tool calls

**Example content** (abbreviated):

```markdown
# Federated MCP Servers
## demo-tools
URL: http://REMOTE_HOST:8560/mcp | Status: connected | Tools: 5
Available tools: roll_dice, get_time, reverse_text, word_count, base_convert
Usage: Call as demo-tools.roll_dice, demo-tools.get_time, etc.
```

---

### Resource Protocol Details

Resources use two JSON-RPC methods:

**`resources/list`** -- Returns the full catalog of available resources. Takes no
parameters. The response includes each resource's URI, human-readable name,
description, and MIME type. All Ephyr resources return `text/markdown`.

**`resources/read`** -- Returns the content of a single resource. Takes one
parameter: `uri` (string). The URI must match one of the URIs returned by
`resources/list`.

**Error handling:**

- Unknown URI returns JSON-RPC error code `-32602` (invalid params) with
  message `"unknown resource URI"`.
- Resources that depend on agent identity (like `ephyr://status`) use the
  same API key authentication as tool calls.

**Caching:** Resource content is generated dynamically on each read from live
policy configuration and runtime state. Clients should not cache resource content
for extended periods -- the data reflects the current system state.

### Self-Discovery Pattern

The recommended bootstrap sequence for a new agent connection:

```
1. initialize          -- establish MCP session
2. resources/list      -- discover available resources
3. resources/read      -- read ephyr://overview (understand the environment)
4. tools/list          -- discover available tools
5. tools/call          -- begin operations with full context
```

This pattern is superior to starting with `tools/list` because the agent gains
contextual understanding (what targets exist, what roles mean, what services are
available) before it starts executing operations. The `ephyr://overview` resource
is specifically designed to give an agent everything it needs in a single read.

For deeper dives, the agent can read additional resources as needed:

- Before SSH operations: read `ephyr://targets` and `ephyr://roles`
- Before HTTP proxy operations: read `ephyr://services`
- To check current state: read `ephyr://status`
- For tool usage reminders: read `ephyr://tools`

---

## Performance: Sessions vs One-Shot

Every `exec` call without a `session_id` performs the full certificate lifecycle:

1. Generate ephemeral Ed25519 keypair (~1ms)
2. Sign certificate via Unix socket IPC (~5ms)
3. SSH connect + authenticate (~800ms)
4. Execute command (varies)
5. Disconnect

**One-shot latency:** ~850ms overhead per command.

With a persistent session, steps 1--3 are eliminated:

1. Open channel on existing connection (~2ms)
2. Execute command (varies)

**Session latency:** ~14ms overhead per command (60x faster).

**When to use sessions:**

- Multiple commands on the same target in sequence (e.g., diagnosing an issue)
- Batch operations (e.g., checking 10 container statuses)
- Interactive workflows where sub-second response matters

**When one-shot is fine:**

- Single commands (overhead is acceptable)
- Commands on different targets (sessions are per-target)
- Infrequent operations with long gaps between commands

**Session limits:**

- 5 concurrent sessions per agent (configurable)
- 5-minute idle timeout (auto-closes unused sessions)
- Sessions survive tool errors (a failed `exec` doesn't close the session)

---

## Example Workflows

### Workflow 1: Health Check Across All Hosts

Agent checks system health on all three targets using one-shot `exec`:

```json
// Step 1: List targets to know what's available
{"method": "tools/call", "params": {"name": "list_targets", "arguments": {}}}

// Step 2: Check each host
{"method": "tools/call", "params": {"name": "exec", "arguments": {
  "target": "web-server", "role": "read",
  "command": "uptime && free -h | head -2 && df -h / | tail -1"
}}}

{"method": "tools/call", "params": {"name": "exec", "arguments": {
  "target": "app-server", "role": "read",
  "command": "uptime && free -h | head -2 && df -h / | tail -1"
}}}

{"method": "tools/call", "params": {"name": "exec", "arguments": {
  "target": "blog-server", "role": "read",
  "command": "uptime && free -h | head -2 && df -h / | tail -1"
}}}
```

### Workflow 2: Docker Container Investigation

Agent investigates an unhealthy container using a persistent session:

```json
// Step 1: Open session
{"method": "tools/call", "params": {"name": "session_create", "arguments": {
  "target": "web-server", "role": "operator"
}}}
// Returns: {"session_id": "ses_abc123", ...}

// Step 2: Check container status
{"method": "tools/call", "params": {"name": "exec", "arguments": {
  "target": "web-server", "role": "operator", "session_id": "ses_abc123",
  "command": "docker inspect automation-n8n --format '{{.State.Health.Status}}'"
}}}

// Step 3: Check logs
{"method": "tools/call", "params": {"name": "exec", "arguments": {
  "target": "web-server", "role": "operator", "session_id": "ses_abc123",
  "command": "docker logs automation-n8n --tail 50 --since 1h"
}}}

// Step 4: Restart if needed
{"method": "tools/call", "params": {"name": "exec", "arguments": {
  "target": "web-server", "role": "operator", "session_id": "ses_abc123",
  "command": "docker restart automation-n8n"
}}}

// Step 5: Clean up
{"method": "tools/call", "params": {"name": "session_close", "arguments": {
  "session_id": "ses_abc123"
}}}
```

### Workflow 3: Application Deployment

Agent builds and deploys an application:

```json
// Step 1: Pull latest code
{"method": "tools/call", "params": {"name": "exec", "arguments": {
  "target": "web-server", "role": "operator",
  "command": "cd /opt/app && git pull origin main"
}}}

// Step 2: Build the application
{"method": "tools/call", "params": {"name": "exec", "arguments": {
  "target": "web-server", "role": "operator",
  "command": "cd /opt/app && make build"
}}}

// Step 3: Restart the service
{"method": "tools/call", "params": {"name": "exec", "arguments": {
  "target": "web-server", "role": "operator",
  "command": "sudo systemctl restart myapp"
}}}

// Step 4: Verify deployment via HTTP proxy
{"method": "tools/call", "params": {"name": "http_request", "arguments": {
  "url": "https://api.github.com/repos/YOUR_ORG/YOUR_REPO/commits?per_page=1"
}}}
```

### Workflow 4: Cross-Service Monitoring

Agent correlates data from multiple services via HTTP proxy:

```json
// Step 1: Check Uptime Kuma for current status
{"method": "tools/call", "params": {"name": "http_request", "arguments": {
  "url": "http://UPTIME_KUMA_HOST:3001/api/status-page/default"
}}}

// Step 2: Check Grafana for resource trends
{"method": "tools/call", "params": {"name": "http_request", "arguments": {
  "url": "http://GRAFANA_HOST:3030/api/dashboards/home"
}}}

// Step 3: Check Portainer for container states
{"method": "tools/call", "params": {"name": "http_request", "arguments": {
  "url": "https://PORTAINER_HOST:9443/api/endpoints"
}}}

// Step 4: Check Broker API for lab status
{"method": "tools/call", "params": {"name": "http_request", "arguments": {
  "url": "http://BROKER_API_HOST:8550/api/status"
}}}
```

### Workflow 5: Agent Self-Discovery

A new agent connects and bootstraps its understanding of the environment
before performing any operations:

```json
// Step 1: Initialize MCP session
{"method": "initialize", "params": {
  "protocolVersion": "2025-03-26",
  "capabilities": {},
  "clientInfo": {"name": "claude-code", "version": "1.0.0"}
}}

// Step 2: Discover available resources
{"method": "resources/list", "params": {}}
// Returns: 7 resources with ephyr:// URIs

// Step 3: Read the system overview to understand what's available
{"method": "resources/read", "params": {"uri": "ephyr://overview"}}
// Returns: Markdown with targets, services, agent permissions, quick-start

// Step 4: Read roles to understand permission model
{"method": "resources/read", "params": {"uri": "ephyr://roles"}}
// Returns: Markdown explaining read/operator/admin roles and when to use each

// Step 5: Check current state (any leftover sessions from previous work?)
{"method": "resources/read", "params": {"uri": "ephyr://status"}}
// Returns: Active certs, sessions, recent activity

// Step 6: Now the agent has full context -- begin operations
{"method": "tools/call", "params": {"name": "exec", "arguments": {
  "target": "web-server", "role": "read",
  "command": "docker ps --format 'table {{.Names}}\t{{.Status}}' | head -20"
}}}
```

This workflow demonstrates the self-discovery pattern: the agent reads resources
to build situational awareness before taking action. The `ephyr://overview`
resource alone provides enough context for most operations, but reading
`ephyr://roles` and `ephyr://status` gives the agent a complete picture.

---

## Security Considerations

### API Key Protection

- API keys are stored as bcrypt hashes in `policy.yaml` -- plaintext keys are
  never stored in the policy file.
- The test key file `/etc/ephyr/mcp_api_key` should be removed in production.
- Rotate API keys by generating a new hash and reloading the broker.

### Certificate Lifecycle

- Ephemeral Ed25519 keypairs are generated in memory and never written to disk.
- Certificates have a 5-minute TTL by default (configurable per target).
- The CA key (`/etc/ephyr/ca_key`) is only accessible to the signer process.
- Signer and broker communicate via Unix socket with strict file permissions.

### Network Security

- MCP port 8554 is firewalled to `192.168.0.0/16` (local network only).
- HTTP proxy enforces network policy: RFC 1918 and explicitly allowed domains.
- External access (e.g., GitHub API) requires explicit domain allowlisting in
  `/var/lib/ephyr/network_policy.json`.

### Role-Based Access Control

- Agents are restricted to roles listed in their policy configuration.
- Targets independently restrict which roles they accept.
- The effective role set is the intersection of agent roles and target roles.
- Role-to-principal mapping is fixed: `read` -> `agent-read`, `operator` ->
  `agent-op`, `admin` -> `agent-admin`.

### Audit Trail

- Every tool call and resource read is logged to `/var/log/ephyr/audit.json`.
- Audit entries include: timestamp, agent name, tool/resource, parameters,
  target, role, result status, and duration.
- Logs are rotated by logrotate (30-day retention).
- The dashboard Audit view provides real-time audit monitoring.

### Session Security

- Sessions are bound to the authenticated agent -- one agent cannot use
  another's session.
- Session IDs are cryptographically random.
- Idle sessions auto-close after 5 minutes.
- Maximum 5 concurrent sessions per agent (prevents resource exhaustion).

### Credential Isolation

- HTTP proxy credentials are stored in `/var/lib/ephyr/services.json` (0600).
- Credentials are injected by the broker at proxy time -- agents never see them.
- Credential values are redacted in all API responses, logs, and dashboard views.
- The `list_services` tool returns only auth type, never credential values.

---

## Troubleshooting

### Connection Refused on Port 8554

```bash
# Check if broker is running
systemctl status ephyr-broker

# Check if MCP is enabled and port is bound
ss -tlnp | grep 8554

# Check broker logs for startup errors
journalctl -u ephyr-broker -n 50

# Verify MCP is enabled in policy
grep -A2 'mcp:' /etc/ephyr/policy.yaml
```

### 401 Unauthorized

```bash
# Verify API key matches the hash in policy.yaml
cat /etc/ephyr/mcp_api_key

# Re-hash and compare
htpasswd -nbBC 10 "" "$(cat /etc/ephyr/mcp_api_key)" | cut -d: -f2

# Check that Authorization header format is correct
# Must be: "Bearer <key>" (with space, case-sensitive)
```

### Tool Call Returns Error

Common error responses:

| Error | Cause | Fix |
|-------|-------|-----|
| `"unknown target"` | Target name not in policy | Check `list_targets` output |
| `"role not allowed"` | Agent/target doesn't allow this role | Check policy roles |
| `"max sessions exceeded"` | 5 concurrent sessions | Close unused sessions |
| `"session not found"` | Invalid or expired session_id | Create a new session |
| `"command required"` | Empty command string | Provide a command |
| `"service not found"` | URL doesn't match any service prefix | Check `list_services` |
| `"network policy denied"` | URL blocked by CIDR/domain rules | Check network_policy.json |

### Resource Read Returns Error

| Error | Cause | Fix |
|-------|-------|-----|
| `"unknown resource URI"` | URI doesn't match any resource | Check `resources/list` output |
| `"method not found"` | Client sent wrong method name | Use `resources/read` (not `resource/read`) |

### SSH Connection Fails

```bash
# Test SSH connectivity from the LXC
ssh -o ConnectTimeout=5 agent-op@TARGET_HOST

# Check target host SSH config
# On target: verify TrustedUserCAKeys and AuthorizedPrincipalsFile
cat /etc/ssh/sshd_config | grep -E 'TrustedUserCA|AuthorizedPrincipals'

# Check if CA public key is deployed
cat /etc/ssh/ca_key.pub

# Verify principal files exist
ls -la /etc/ssh/auth_principals/
```

### Signer Communication Failure

```bash
# Check signer is running
systemctl status ephyr-signer

# Check socket exists and has correct permissions
ls -la /run/ephyr/signer.sock

# Restart both services (signer first!)
systemctl restart ephyr-signer
systemctl restart ephyr-broker
```

### High Latency on exec

- Use sessions for repeated commands (14ms vs 850ms).
- Check target host SSH server load.
- Verify signer socket is on tmpfs (should be `/run/ephyr/`).
- Check for DNS resolution delays (use IPs in host config).

### Dashboard Shows Stale Data

```bash
# The dashboard polls the broker API -- verify broker is responsive
curl -s http://BROKER_HOST:8553/v1/dashboard/activity/summary \
  -H "Authorization: Bearer YOUR_DASHBOARD_TOKEN"

# Restart broker if needed
systemctl restart ephyr-signer && systemctl restart ephyr-broker
```

---

## Task Identity Tools (v0.2)

Task identity is implemented in Phase 2a. These four tools manage task-scoped
identity using CTT-E (Execution Token) JWTs signed by the broker's delegated
key. They require the signer to support delegation (v0.2+). If the signer is
v0.1, these tools return an error indicating task identity is unavailable.

| Tool | Description |
|------|-------------|
| `task_create` | Create a task and receive a CTT-E token |
| `task_info` | Get task details, envelope, and remaining TTL |
| `task_revoke` | Revoke a task (cascading invalidation via epoch watermark) |
| `task_list` | List active tasks for this agent |

### 11. `task_create`

Creates a new root task with a scoped capability envelope derived from the
agent's RBAC permissions. The envelope lists the maximum targets, roles,
services, remotes, and methods the task can access. Wildcards in policy are
resolved to explicit literal arrays at token issuance time.

**Parameters:**

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `description` | string | Yes | -- | Human-readable task description |
| `ttl` | string | No | `"30m"` | Task TTL as Go duration (max `"1h"`) |

**Example call:**

```json
{
  "jsonrpc": "2.0",
  "id": 10,
  "method": "tools/call",
  "params": {
    "name": "task_create",
    "arguments": {
      "description": "Investigate unhealthy n8n container on dockerhost",
      "ttl": "15m"
    }
  }
}
```

**Response:**

```json
{
  "jsonrpc": "2.0",
  "id": 10,
  "result": {
    "content": [
      {
        "type": "text",
        "text": "{"task_id":"01JQXYZ1A2B3C4D5E6F7G8H9JK","token":"eyJhbGciOiJFZERTQSIsInR5cCI6IkNUVC1FIiwia2lkIjoiZGVsZWc6Li4uIn0.eyJzdWIiOiJjbGF1ZGUiLCJ0YXNrIjp7ImlkIjoiMDFKUVhZWi4uLiJ9fQ.signature","expires_at":"2026-03-13T15:15:00Z","ttl_seconds":900,"envelope":{"targets":["dockerhost","mandrake-rack","hugoblog"],"roles":["read","operator"],"services":["github","gitea","grafana"],"remotes":["demo-tools"],"methods":["GET","POST","PUT","DELETE"]}}"
      }
    ]
  }
}
```

**Key response fields:**

| Field | Description |
|-------|-------------|
| `task_id` | ULID identifier (26 characters, time-sortable) |
| `token` | Signed CTT-E JWT (EdDSA, 3 base64url segments) |
| `expires_at` | RFC3339 expiry timestamp |
| `envelope` | Resolved capability envelope (explicit targets, roles, services, remotes, methods) |

**Validation errors:**

- Missing or empty `description`: `"description is required"`
- TTL exceeds 1 hour: `"ttl cannot exceed 1h"`
- Invalid TTL format: `"invalid ttl: ..."`
- Signer lacks delegation support: `"task identity not available (signer does not support delegation)"`

---

### 12. `task_info`

Returns information about a specific task including its full object, remaining
TTL, and revocation status. If `task_id` is omitted, falls back to listing
all active tasks for the agent (same as `task_list`).

**Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `task_id` | string | No | Task ID (ULID). Omit to list all active tasks. |

**Example call:**

```json
{
  "jsonrpc": "2.0",
  "id": 11,
  "method": "tools/call",
  "params": {
    "name": "task_info",
    "arguments": {
      "task_id": "01JQXYZ1A2B3C4D5E6F7G8H9JK"
    }
  }
}
```

**Response:**

```json
{
  "jsonrpc": "2.0",
  "id": 11,
  "result": {
    "content": [
      {
        "type": "text",
        "text": "{"task":{"id":"01JQXYZ1A2B3C4D5E6F7G8H9JK","agent_name":"claude","description":"Investigate unhealthy n8n container on dockerhost","created_at":"2026-03-13T15:00:00Z","expires_at":"2026-03-13T15:15:00Z","root_id":"01JQXYZ1A2B3C4D5E6F7G8H9JK","parent_id":"","depth":0,"lineage":["01JQXYZ1A2B3C4D5E6F7G8H9JK"],"initiated_by":"ephyr:apikey:ak_claude","envelope":{"targets":["dockerhost"],"roles":["operator"],"services":[],"remotes":[],"methods":[]}},"remaining_ttl":"12m30s","is_revoked":false}"
      }
    ]
  }
}
```

**Notes:**
- `remaining_ttl` is computed at response time.
- `is_revoked` checks against the epoch watermark revocation table.
- Agents can only view their own tasks; requesting another agent's task returns
  `"access denied: task belongs to another agent"`.

---

### 13. `task_revoke`

Revokes a task and sets an epoch watermark. All tokens issued for this task are
immediately invalidated. Revocation cascades: any child tasks whose lineage
includes the revoked task ID are also invalidated via the watermark walk.

**Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `task_id` | string | Yes | Task ID to revoke |

**Example call:**

```json
{
  "jsonrpc": "2.0",
  "id": 12,
  "method": "tools/call",
  "params": {
    "name": "task_revoke",
    "arguments": {
      "task_id": "01JQXYZ1A2B3C4D5E6F7G8H9JK"
    }
  }
}
```

**Response:**

```json
{
  "jsonrpc": "2.0",
  "id": 12,
  "result": {
    "content": [
      {
        "type": "text",
        "text": "{"revoked":"01JQXYZ1A2B3C4D5E6F7G8H9JK","status":"all tokens invalidated"}"
      }
    ]
  }
}
```

**Notes:**
- Revocation is immediate and permanent for the task ID.
- The revoked task is removed from the task manager and decrements the active
  task gauge in metrics.
- Audit log records `task_revoke` event with severity WARN.

---

### 14. `task_list`

Lists all active (non-expired, non-revoked) tasks for the calling agent.
Returns a summary for each task including its remaining TTL and revocation status.

**Parameters:** None

**Example call:**

```json
{
  "jsonrpc": "2.0",
  "id": 13,
  "method": "tools/call",
  "params": {
    "name": "task_list",
    "arguments": {}
  }
}
```

**Response:**

```json
{
  "jsonrpc": "2.0",
  "id": 13,
  "result": {
    "content": [
      {
        "type": "text",
        "text": "{"tasks":[{"id":"01JQXYZ1A2B3C4D5E6F7G8H9JK","description":"Investigate unhealthy n8n container","created_at":"2026-03-13T15:00:00Z","expires_at":"2026-03-13T15:15:00Z","remaining_ttl":"12m30s","is_revoked":false},{"id":"01JQABC2D3E4F5G6H7J8K9LMNO","description":"Deploy blog update","created_at":"2026-03-13T15:02:00Z","expires_at":"2026-03-13T15:32:00Z","remaining_ttl":"27m15s","is_revoked":false}],"count":2}"
      }
    ]
  }
}
```

---

## Performance

### MCP Authentication: Auth Cache

The broker caches successful API key authentication results to avoid repeated
bcrypt comparisons on every MCP request. Cache behavior:

- **Cache key:** SHA-256 fingerprint of the API key (the raw key is never stored)
- **Default TTL:** 60 seconds (configurable via `EPHYR_AUTH_CACHE_TTL`)
- **Invalidation:** Cache is automatically cleared when agents are added or removed

**Measured latency (cold vs warm):**

| Scenario | Latency | Description |
|----------|---------|-------------|
| Cold (cache miss) | ~216ms | Full bcrypt comparison required |
| Warm (cache hit) | <1ms | SHA-256 lookup + expiry check only |

The cache reduces MCP endpoint latency by roughly 200x for repeated requests
within the TTL window. This is particularly impactful for agents making rapid
sequences of tool calls (e.g., session-based workflows with multiple `exec`
calls).

To disable the cache (e.g., in environments where immediate key revocation is
required), set `EPHYR_AUTH_CACHE_TTL=0`.

### SSH Execution: Sessions vs One-Shot

Every `exec` call without a `session_id` performs the full certificate lifecycle:

1. Generate ephemeral Ed25519 keypair (~1ms)
2. Sign certificate via Unix socket IPC (~5ms)
3. SSH connect + authenticate (~800ms)
4. Execute command (varies)
5. Disconnect

**One-shot latency:** ~850ms overhead per command.

With a persistent session, steps 1--3 are eliminated:

1. Open channel on existing connection (~2ms)
2. Execute command (varies)

**Session latency:** ~14ms overhead per command (60x faster).

### Task Identity Operations

Measured from the integration test benchmark (10 iterations each):

| Operation | Typical Latency | Notes |
|-----------|----------------|-------|
| `task_create` | ~5--10ms | Includes RBAC envelope resolution + EdDSA signing |
| `task_info` | ~2--5ms | In-memory lookup |
| `task_list` | ~2--5ms | Filters by agent name |
| `task_revoke` | ~2--5ms | Sets watermark + removes from task manager |

Task operations are significantly faster than SSH operations because they
involve no IPC to the signer (the broker signs CTT-E tokens locally using
the delegated key).
