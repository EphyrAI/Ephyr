# EPHYR.md -- Agent Reference

This file tells AI agents how to interact with Ephyr. Point your agent framework's context file here (Cline's `RULES.md`, OpenClaw's `SOUL.md`, Cursor's `.cursorrules`, etc.).

## What is Ephyr?

Ephyr is an access broker for AI agents. You connect to one MCP endpoint and get access to SSH targets, HTTP APIs, and federated MCP servers -- all through the broker. You never handle credentials directly.

## Connecting

> **Already seeing Ephyr tools?** If tools like `list_targets` and `exec` are available in your tool list, you are already connected -- skip to **First Steps**. Your MCP client was pre-configured with the broker URL and API key.

For new setups, configure your MCP client with:
- **Type:** `url`
- **URL:** `http://<broker-host>:<port>/mcp` (default port: 8554)
- **Auth:** `Authorization: Bearer <your-api-key>`

The broker URL and API key are set in your MCP client configuration (e.g., Claude Code's `settings.json`, Cursor's MCP config). Ask your administrator if you don't have them.

## First Steps

After connecting, discover what's available:

1. **Read `ephyr://overview`** -- returns a summary of all targets, services, and your permissions
2. **Call `list_targets`** -- SSH hosts you can access
3. **Call `list_services`** -- HTTP APIs available through the proxy
4. **Call `list_remotes`** -- federated MCP servers and their tools

Do NOT assume what infrastructure exists. Always discover dynamically.

## Available Tools

### SSH Execution

| Tool | Description |
|------|-------------|
| `list_targets` | List SSH targets and your allowed roles |
| `exec` | Run a command on a target host |
| `session_create` | Open a persistent SSH session (faster for multiple commands) |
| `session_close` | Close a persistent session |
| `list_sessions` | List your active sessions |
| `list_certs` | List your active SSH certificates |

**One-shot command** (~850ms):
```json
{"name": "exec", "arguments": {"target": "<name>", "role": "<role>", "command": "<shell command>"}}
```

**Persistent session** (~14ms per command after setup):
```json
{"name": "session_create", "arguments": {"target": "<name>", "role": "<role>"}}
// Returns session_id
{"name": "exec", "arguments": {"target": "<name>", "role": "<role>", "command": "<cmd>", "session_id": "<id>"}}
// When done:
{"name": "session_close", "arguments": {"session_id": "<id>"}}
```

Use sessions when running multiple commands on the same target. Always close sessions when done.

### HTTP Proxy

| Tool | Description |
|------|-------------|
| `http_request` | Make an HTTP request through the authenticated proxy |
| `list_services` | List available proxy services |

```json
{"name": "http_request", "arguments": {"url": "<full URL>", "method": "GET"}}
```

Credentials are injected automatically. You do not provide authentication. Optional: `method`, `headers` (object), `body` (string), `timeout` (seconds).

### Task Identity

| Tool | Description |
|------|-------------|
| `task_create` | Create a scoped task and receive a macaroon-based task token |
| `task_delegate` | Delegate a child task with attenuated capabilities (macaroon with added caveats) |
| `task_info` | Get task details (envelope, lineage, TTL remaining) |
| `task_list` | List your active tasks |
| `task_revoke` | Revoke a task and all its tokens (cascading to children) |
| `task_bind` | Bind a task token to a holder key for proof-of-possession |

Tasks give you **scoped, auditable identity**. When you create a task, you get back a macaroon-based task token (prefixed `mac_`) that you can use as a Bearer token instead of your API key. The task token:

- Is tied to a specific purpose (the description you provide)
- Has a short TTL (default 30 min, max 1 hour)
- Can be revoked instantly
- Creates an audit trail linking all actions back to the task

**Create a task:**
```json
{"name": "task_create", "arguments": {"description": "Deploy config update to webserver", "ttl": "30m"}}
// Returns: task_id, token (mac_...), expires_at
```

**Use the token** -- replace your API key with the returned macaroon token in the `Authorization: Bearer` header for subsequent requests. All actions performed with the task token are scoped and audited under that task.

**Check task status:**
```json
{"name": "task_info", "arguments": {"task_id": "<id>"}}
```

**Revoke when done:**
```json
{"name": "task_revoke", "arguments": {"task_id": "<id>"}}
```

**Delegate a child task (Ephyr Delegation):**
```json
{"name": "task_create", "arguments": {"description": "Coordinate blog deploy", "ttl": "30m", "can_delegate": true}}
// Returns: task_id, token (mac_...), can_delegate: true
```

```json
{"name": "task_delegate", "arguments": {
  "parent_task_id": "<parent-id>",
  "description": "Read-only check on webserver",
  "ttl": "10m",
  "envelope": {"targets": ["webserver"], "roles": ["read"], "services": [], "remotes": [], "methods": []}
}}
// Returns: task_id, parent_task_id, token (mac_...), depth, envelope
```

Delegation rules:
- Parent must have `can_delegate: true`
- Child envelope must be a subset of (or equal to) parent's -- omit to inherit parent's envelope
- Child TTL must be <= parent's remaining TTL
- Maximum delegation depth is 5
- Revoking a parent cascades to all children

Tasks are optional. API key authentication and legacy JWT tokens still work for all tools. Use tasks when you want tighter scoping, audit correlation, or time-bounded access. Macaroon tokens use a `mac_` prefix and are the default for new task creation.

### MCP Federation

| Tool | Description |
|------|-------------|
| `list_remotes` | List federated MCP servers |

Federated tools are namespaced as `{server}.{tool}`. Example: a remote named "utils" with tool "convert" is called as `utils.convert`.

### MCP Resources

| Resource URI | Contents |
|---|---|
| `ephyr://overview` | System summary with all targets, services, permissions |
| `ephyr://targets` | SSH targets with roles, TTLs, auto-approve settings |
| `ephyr://services` | Proxy services with auth types and URL prefixes |
| `ephyr://roles` | Role definitions and SSH principal mappings |
| `ephyr://status` | Your active certificates, sessions, recent activity |
| `ephyr://tools` | Tool reference with parameters and usage examples |
| `ephyr://remotes` | Federated MCP servers with tools and status |

## CLI Commands

The `ephyr` binary is a single unified tool for both administration and agent operations:

| Command | Description |
|---------|-------------|
| `ephyr init` | One-command setup wizard (CA key, policy, systemd units, start services) |
| `ephyr broker` | Run the broker process (policy engine, MCP server, dashboard) |
| `ephyr signer` | Run the signer process (CA key custody, certificate signing) |
| `ephyr exec` | Execute a command on a target via ephemeral SSH certificate |
| `ephyr inspect` | Inspect a macaroon token's caveats and effective envelope |
| `ephyr monitor` | Live monitoring of broker activity |
| `ephyr demo` | Demonstration mode |
| `ephyr version` | Print version and build information |

## Key Behaviors

- **Ephemeral access** -- SSH certificates have short TTLs (default 5 min). Service and MCP grants auto-expire. Access disappears when the task is done.
- **Credential-free** -- The broker injects all authentication. You never see passwords, tokens, or keys.
- **Audited** -- Every command, request, and action is logged.
- **Role-scoped** -- You can only use roles listed in `list_targets` for each target. Role escalation is not possible.
- **Toggleable** -- Hosts, services, and remotes can be disabled by admins. If something returns a "disabled" error, it was intentionally turned off.
- **Network-isolated** -- Direct connections to backends are blocked. All access goes through the broker.
- **Task-scoped** -- When using task tokens, all actions are correlated under a single task ID in the audit log. Tasks can be revoked to instantly cut access.

## RBAC

Your permissions are controlled by your administrator via policy. You may have:
- **Per-target SSH roles** -- different roles on different hosts (e.g., read-only on production, full access on staging)
- **Per-service HTTP methods** -- some services may be GET-only
- **Per-remote tool access** -- some federated servers or specific tools may be restricted

The discovery tools (`list_targets`, `list_services`, `list_remotes`) automatically filter results to only show what you can access. If something doesn't appear in the list, you don't have permission to use it.

## Error Handling

| Error | Meaning |
|-------|---------|
| `unknown target: X` | Target doesn't exist in policy |
| `role "X" is not permitted on target "Y"` | RBAC denies this role on this target |
| `access denied to service "X"` | RBAC denies access to this service |
| `access denied to remote "X" tool "Y"` | RBAC denies this federated tool |
| `target "X" is currently disabled` | Admin has toggled this host off |
| `remote X is disabled` | Admin has toggled this MCP server off |
| `service disabled` | Admin has toggled this service off |
| `proxy: url not allowed by network policy` | URL is outside allowed network ranges |
| `task not found` | Task ID doesn't exist or has expired |
| `task revoked` | Task was revoked; token is no longer valid |
| `token expired` | Task token TTL has elapsed |
| `envelope violation: ...` | Task token doesn't permit the requested target/service/remote |
