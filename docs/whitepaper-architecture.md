# Ephyr Architecture Whitepaper

**Version:** 0.2
**Date:** 2026-03-13
**Codebase:** ~23,000 lines Go, 3 direct dependencies

---

## Table of Contents

1. [Introduction](#1-introduction)
2. [System Architecture](#2-system-architecture)
3. [Broker Internals](#3-broker-internals)
4. [MCP Server](#4-mcp-server)
5. [HTTP Proxy Engine](#5-http-proxy-engine)
6. [MCP Federation](#6-mcp-federation)
7. [Policy Engine](#7-policy-engine)
8. [Task Identity System (v0.2)](#8-task-identity-system-v02)
9. [Dashboard](#9-dashboard)
10. [Metrics and Observability](#10-metrics-and-observability)
11. [Audit System](#11-audit-system)
12. [Performance Characteristics](#12-performance-characteristics)
13. [Deployment Topology](#13-deployment-topology)
14. [Extension Points](#14-extension-points)

---

## 1. Introduction

### 1.1 Problem Statement

AI agents require access to infrastructure -- SSH hosts, HTTP APIs, internal
services -- to perform useful work. Granting agents static credentials creates
several problems:

- **Credential sprawl.** Each agent needs SSH keys, API tokens, and service
  passwords. Rotation is manual and error-prone.
- **No audit trail.** When multiple agents share credentials, attributing
  actions to a specific agent or task is impossible.
- **Overprivileged access.** Agents receive permanent credentials with broad
  scope, violating the principle of least privilege.
- **No revocation.** Compromised credentials require manual rotation across
  all consumers.

Ephyr solves these problems by acting as an intermediary between AI agents
and infrastructure. It issues ephemeral SSH certificates, injects HTTP
credentials transparently, and maintains a complete audit trail of every
action.

### 1.2 Design Philosophy

Ephyr is built around five core principles:

**Minimal dependencies.** The entire project uses exactly three direct Go
dependencies: `gorilla/websocket` for the dashboard WebSocket, `x/crypto`
for bcrypt and SSH certificate operations, and `gopkg.in/yaml.v3` for policy
file parsing. Cryptographic primitives (ULID generation, JWT signing, Ed25519
delegation chains) are implemented from scratch using only the Go standard
library's `crypto/ed25519` and `crypto/rand`. This reduces supply chain risk
and keeps the attack surface small for a security-critical component.

**Process isolation.** The system is split into three OS processes with
distinct privilege levels. The CA private key is held by a single process
(`ephyr-signer`) that communicates exclusively over a Unix domain socket
and has no network access. The broker process handles all network-facing
operations but never touches the CA key directly. This separation means
a vulnerability in the broker's HTTP handling cannot directly compromise
the signing authority.

**Defense in depth.** Multiple independent layers enforce security:
systemd sandboxing (ProtectSystem=strict, NoNewPrivileges, capability
bounding), nftables firewall rules isolating agent UIDs from backend IPs,
Unix socket peer credential validation (SO_PEERCRED), bcrypt API key
hashing with auth result caching, per-agent RBAC with template inheritance,
and structured audit logging of every action.

**Zero-trust agent model.** Agents never see infrastructure credentials.
SSH access uses ephemeral certificates that expire in minutes. HTTP proxy
requests have credentials injected by the broker -- the agent's request
arrives without authentication headers, and the broker adds them before
forwarding. Even federated MCP calls go through the broker, which can
inject credentials for remote servers transparently.

**Graceful degradation.** The v0.2 task identity system is designed to
work alongside the v0.1 authentication model. A v0.2 broker can serve
agents that do not present CTT tokens (legacy mode), and a v0.1 signer
that does not support delegation signing will simply disable the task
identity subsystem at startup without affecting core functionality.

### 1.3 Dependency Inventory

```
github.com/gorilla/websocket v1.5.3    -- WebSocket for dashboard events
golang.org/x/crypto v0.48.0            -- bcrypt, SSH cert parsing/signing
gopkg.in/yaml.v3 v3.0.1                -- Policy YAML parsing
golang.org/x/sys v0.41.0               -- (indirect, via x/crypto)
```

No external dependencies for: ULID generation, JWT (EdDSA), token signing,
delegation certificates, epoch-based revocation, Prometheus metrics exposition,
JSON-RPC 2.0 protocol handling, MCP Streamable HTTP transport, or lock-free
histograms.

---

## 2. System Architecture

### 2.1 Three-Process Model

Ephyr runs as three separate OS processes, each with distinct responsibilities
and privilege levels:

```
+------------------------------------------------------------------+
|                         HOST (LXC / VM)                          |
|                                                                  |
|  +---------------------+      Unix Socket       +--------------+|
|  |   ephyr-signer     |<======================>|              ||
|  |                     |   /run/ephyr/          |              ||
|  |  - Ed25519 CA key   |    signer.sock          |              ||
|  |  - Sign SSH certs   |                         |   ephyr-    ||
|  |  - Sign delegation  |   SO_PEERCRED           |    broker    ||
|  |    certs             |   UID check             |              ||
|  |  - Root public key   |                         |              ||
|  |                     |                         |              ||
|  | UID: 999            |                         | UID: 999     ||
|  | NET: AF_UNIX only   |                         | NET: TCP+UNIX||
|  +---------------------+                         |              ||
|                                                  |  :8553 dash  ||
|  +---------------------+      Unix Socket       |  :8554 MCP   ||
|  |   ephyr (CLI)      |<======================>|              ||
|  |                     |   /run/ephyr/          |              ||
|  |  - Agent tool       |    broker.sock          |              ||
|  |  - Cert requests    |                         |              ||
|  |  - SSH operations   |   SO_PEERCRED           |              ||
|  |                     |   UID check             |              ||
|  | UID: 1000 (agent)   |                         +--------------+|
|  +---------------------+                                        |
+------------------------------------------------------------------+
```

**ephyr-signer** -- The key custodian. Holds the Ed25519 CA private key in
memory. Accepts signing requests over a Unix domain socket at
`/run/ephyr/signer.sock`. Validates the caller's UID via `SO_PEERCRED` to
ensure only the broker process (UID 999) can request signatures. Supports
four actions: `ping`, `sign` (SSH certificates), `sign_delegation` (v0.2
delegation certificates), and `root_public_key` (returns the CA public key
for token validation pinning). Maximum certificate lifetime is capped at
24 hours. The signer has no network sockets -- its systemd unit restricts
address families to `AF_UNIX` only.

**ephyr-broker** -- The policy engine and gateway. Listens on three
interfaces: a Unix socket for local CLI access (`/run/ephyr/broker.sock`),
TCP port 8553 for the dashboard, and TCP port 8554 for the MCP server.
Composes 13 internal subsystems to evaluate policy, manage sessions, proxy
HTTP requests, federate remote MCP servers, issue task identities, and
maintain real-time metrics. Runs as UID 999 with systemd hardening.

**ephyr (CLI)** -- The agent-facing tool. Used by AI agents (or humans)
to request certificates and execute commands. Communicates with the broker
over the Unix socket. In MCP mode, agents interact with the broker via
HTTP (port 8554) instead of the CLI.

### 2.2 Trust Boundaries

```
                        TRUST BOUNDARY 1
                     (Unix socket + SO_PEERCRED)
                              |
  +----------+     IPC        |        +-------------------+
  |  Signer  |<===============|=======>|      Broker       |
  |  CA Key  |                |        |  Policy Engine    |
  +----------+                |        |  Session Mgr      |
                              |        |  Proxy Engine     |
                        TRUST BOUNDARY 2                   |
                     (Unix socket + SO_PEERCRED)           |
                              |        |                   |
  +----------+     IPC        |        |                   |
  |   CLI    |<===============|=======>|                   |
  |  Agent   |                |        +-------------------+
  +----------+                              |         |
                                           |         |
                        TRUST BOUNDARY 3   |    TRUST BOUNDARY 4
                     (Bearer token + bcrypt)|  (Credential injection)
                              |            |         |
  +----------+    TCP :8554   |            |    +----+-----+
  | MCP      |<==============|============|    | Backend  |
  | Client   |                |            |    | Services |
  +----------+                             |    +----------+
                                           |
                        TRUST BOUNDARY 5   |
                     (Dashboard token)     |
                              |            |
  +----------+    TCP :8553   |            |
  | Browser  |<==============|============+
  | Dashboard|                |
  +----------+
```

**Boundary 1 (Signer IPC):** The signer validates caller UID via
`SO_PEERCRED` on every connection. Only UID 999 (the broker) can request
signatures. The Unix socket file permissions are set to 0660 with group
ownership matching the broker's group.

**Boundary 2 (CLI IPC):** The broker socket at `/run/ephyr/broker.sock`
uses `SO_PEERCRED` to identify the calling agent's UID. Policy evaluation
uses this UID to look up the agent and enforce per-agent constraints.

**Boundary 3 (MCP API):** Remote MCP clients authenticate via Bearer
token in the Authorization header. The broker validates the token against
bcrypt hashes stored in `policy.yaml`, with a SHA-256-keyed result cache
to avoid repeated bcrypt comparisons.

**Boundary 4 (Backend Proxy):** The broker's HTTP proxy injects credentials
when forwarding requests to backend services. Agents never see the
credentials. Network policy (CIDR allow/deny lists) controls which
destinations are reachable.

**Boundary 5 (Dashboard):** The dashboard authenticates via a token
passed as a query parameter on WebSocket upgrade and as a header on
REST API calls.

### 2.3 Network Exposure

```
+-------------------+-------------------------------------------+
|      Port         |              Exposure                     |
+-------------------+-------------------------------------------+
| signer.sock       | Unix socket only, AF_UNIX restricted      |
| broker.sock       | Unix socket only, group ephyr-agents     |
| :8553 (dashboard) | TCP, restricted to 192.168.0.0/16 by nft |
| :8554 (MCP)       | TCP, restricted to 192.168.0.0/16 by nft |
+-------------------+-------------------------------------------+
```

The nftables firewall on the LXC enforces input filtering (default drop)
and output filtering for the agent UID (1000), blocking direct access to
all backend IPs. The agent can only reach the broker on localhost; all
backend access must go through the broker's proxy.

### 2.4 Data Flow: Agent Executes a Command

```
   Agent                 Broker                Signer              Target
     |                     |                     |                    |
     |  POST /mcp          |                     |                    |
     |  tools/call: exec   |                     |                    |
     |  Bearer: <api_key>  |                     |                    |
     |-------------------->|                     |                    |
     |                     |                     |                    |
     |              1. Authenticate              |                    |
     |              (bcrypt / cache)              |                    |
     |                     |                     |                    |
     |              2. Policy eval               |                    |
     |              (target, role, RBAC)          |                    |
     |                     |                     |                    |
     |              3. Generate ephemeral         |                    |
     |                 Ed25519 keypair            |                    |
     |                     |                     |                    |
     |                     | sign(pub, principal) |                    |
     |                     |-------------------->|                    |
     |                     |                     |                    |
     |                     |    SSH certificate   |                    |
     |                     |<--------------------|                    |
     |                     |                     |                    |
     |              4. SSH dial with cert         |                    |
     |                     |------------------------------------------->
     |                     |                     |                    |
     |              5. Run command               |                    |
     |                     |------------------------------------------->
     |                     |                     |                    |
     |                     |                 stdout, stderr, exit_code |
     |                     |<------------------------------------------|
     |                     |                     |                    |
     |              6. Audit log + event hub     |                    |
     |                     |                     |                    |
     |   JSON-RPC result   |                     |                    |
     |<--------------------|                     |                    |
     |                     |                     |                    |
```

---

## 3. Broker Internals

### 3.1 Subsystem Map

The broker composes 13 internal subsystems. Each subsystem is a Go struct
with a well-defined responsibility and thread-safe API. There are no
circular dependencies between subsystems.

```
+------------------------------------------------------------------------+
|                          BrokerServer                                   |
|                                                                        |
|  +----------------+  +----------------+  +------------------+          |
|  | PolicyEngine   |  | SignerClient   |  | SessionManager   |          |
|  | (policy eval,  |  | (IPC to signer,|  | (SSH session     |          |
|  |  cert tracking,|  |  sign, ping,   |  |  lifecycle,      |          |
|  |  hot-reload)   |  |  delegation)   |  |  peer cred)      |          |
|  +----------------+  +----------------+  +------------------+          |
|                                                                        |
|  +----------------+  +----------------+  +------------------+          |
|  | CertState      |  | RateLimiter    |  | AuditLogger      |          |
|  | (active cert   |  | (per-agent     |  | (structured JSON |          |
|  |  registry,     |  |  sliding window|  |  log, multi-     |          |
|  |  expiry sweep) |  |  throttle)     |  |  writer)         |          |
|  +----------------+  +----------------+  +------------------+          |
|                                                                        |
|  +----------------+  +----------------+  +------------------+          |
|  | EventHub       |  | HostController |  | ConfigManager    |          |
|  | (WebSocket     |  | (per-host      |  | (persistent host |          |
|  |  broadcast,    |  |  enable/disable|  |  config, policy  |          |
|  |  backpressure) |  |  toggles)      |  |  reconciliation) |          |
|  +----------------+  +----------------+  +------------------+          |
|                                                                        |
|  +----------------+  +----------------+  +------------------+          |
|  | MCPServer      |  | ActivityStore  |  | ProxyEngine      |          |
|  | (JSON-RPC 2.0, |  | (ring buffer,  |  | (credential      |          |
|  |  tool dispatch,|  |  per-agent     |  |  injection, CIDR |          |
|  |  auth, SSE)    |  |  stats, query) |  |  policy, service |          |
|  +----------------+  +----------------+  |  matching)        |          |
|                                          +------------------+          |
|  +----------------+                                                    |
|  | MCPFederator   |      v0.2 Task Identity                           |
|  | (remote MCP    |  +------------------+  +------------------+       |
|  |  discovery,    |  | TaskManager      |  | DelegationManager|       |
|  |  namespacing,  |  | (ULID IDs,       |  | (ephemeral keys, |       |
|  |  proxy calls)  |  |  lineage, expiry)|  |  rotation loop)  |       |
|  +----------------+  +------------------+  +------------------+       |
|                                                                        |
|                       +------------------+  +------------------+       |
|                       | RevocationMap    |  | Metrics          |       |
|                       | (epoch watermark |  | (lock-free       |       |
|                       |  revocation, GC) |  |  histograms,     |       |
|                       +------------------+  |  Prometheus)     |       |
|                                             +------------------+       |
|                                                                        |
|                       +------------------+  +------------------+       |
|                       | GrantStore       |  | TokenIssuer/     |       |
|                       | (service/MCP     |  |  Validator       |       |
|                       |  access grants,  |  | (JWT EdDSA,      |       |
|                       |  TTL, passthru)  |  |  claim parsing)  |       |
|                       +------------------+  +------------------+       |
+------------------------------------------------------------------------+
```

### 3.2 Initialization Sequence

When the broker starts (`NewBrokerServer`), subsystems are initialized
in dependency order:

```
1.  PolicyEngine      Load policy.yaml, resolve durations, resolve RBAC perms
2.  SignerClient      Create IPC client (connection is lazy, first use dials)
3.  AuditLogger       Open audit log file for append
4.  RateLimiter       Initialize from policy global.rate_limit
5.  SessionManager    Create empty session registry
6.  CertState         Create empty cert registry, start expiry sweep goroutine
7.  EventHub          Create WebSocket client registry
8.  HostController    Create host toggle map
9.  ConfigManager     Load persisted host configs, reconcile with policy targets
10. ActivityStore     Create 10,000-entry ring buffer
11. GrantStore        Create grant registry, start cleanup goroutine
12. TaskManager       Create task registry, start cleanup goroutine (v0.2)
13. RevocationMap     Create watermark map, start GC goroutine (v0.2)
14. Metrics           Create counter/histogram structs (v0.2)
```

After `NewBrokerServer` returns, `ListenAndServe` brings up the network:

```
15. Unix socket listener    /run/ephyr/broker.sock (chmod 0660)
16. Dashboard listener      TCP :8553 (goroutine)
17. MCP listener            TCP :8554 (goroutine)
      - MCPAuthenticator    Load agent bcrypt hashes from policy
      - ExecSessionPool     Create SSH session pool (max 5 per agent)
      - ProxyEngine         Load services from /var/lib/ephyr/services.json
      - NetworkPolicy       Load CIDR rules from /var/lib/ephyr/network_policy.json
      - MCPFederator        Load remotes from /var/lib/ephyr/remotes.json
                            Start background refresh loop
18. InitTaskIdentity        Request root public key from signer (v0.2)
      - Generate broker ID
      - Create TokenIssuer and TokenValidator
      - Create DelegationManager with rotation callback
      - Request initial delegation cert from signer
      - Start rotation loop goroutine
```

### 3.3 Request Lifecycle: MCP exec Tool Call

This section traces a complete `exec` tool call from HTTP ingress to
SSH command execution and response.

```
Phase 1: MCP Protocol (mcp.go)
  1. HTTP POST /mcp arrives at MCPServer.ServeHTTP
  2. Extract Bearer token from Authorization header
  3. MCPAuthenticator.Authenticate:
       a. SHA-256 hash of API key -> cache lookup
       b. Cache hit + not expired -> return cached MCPAgent  (~<1us)
       c. Cache miss -> iterate agents, bcrypt.CompareHashAndPassword  (~216ms)
       d. On match: cache result with TTL (default 60s)
  4. Parse JSON-RPC 2.0 request envelope
  5. Route method "tools/call" to handleToolsCall

Phase 2: Tool Dispatch (mcp_tools.go)
  6. Parse MCPToolsCallParams (name="exec", arguments={...})
  7. Check if federated tool (contains dot) -> no
  8. Check if streaming tool -> no
  9. Dispatch to handleToolCall -> toolExec

Phase 3: Policy and RBAC (mcp_tools.go)
  10. Validate target exists in policy
  11. RBAC: Check agent's ResolvedAgentPerms.CanAccessTarget(target)
  12. RBAC: Check agent's GetTargetRoles(target) includes requested role
  13. Validate role is in agent's allowed roles list
  14. Validate role is in target's allowed_roles list
  15. Check host is enabled via HostController.IsEnabled

Phase 4: SSH Execution (mcp_exec.go)
  16. If session_id provided:
        ExecInSession: lookup session, verify agent ownership, run command
      Else:
        ExecOneShot: full sign-and-connect flow
  17. ExecSessionPool.signAndConnect:
        a. Look up target config and role principal from policy
        b. Generate ephemeral Ed25519 keypair (crypto/rand, never persisted)
        c. Convert public key to SSH authorized_key format
        d. IPC to signer: SignRequest{action: "sign", public_key, principals,
           duration, key_id}
        e. Signer validates, signs SSH certificate, returns base64 cert + serial
        f. Parse SSH certificate from authorized_key format
        g. Build ssh.CertSigner from (private_key, certificate)
        h. ssh.Dial to target host with certificate auth
  18. Register certificate in CertState (serial, agent, target, role, expiry)
  19. Open SSH session on connection, capture stdout/stderr
  20. Run command with timeout (timer + SIGKILL on timeout)
  21. Capture exit code (or -1 on timeout/connection error)
  22. Close SSH connection (one-shot) or update LastUsed (session)
  23. Deregister certificate from CertState (one-shot only)

Phase 5: Observability
  24. AuditLogger.LogEvent (mcp_exec event with command, exit code, duration)
  25. EventHub.Broadcast (mcp_exec event for WebSocket dashboard)
  26. ActivityStore.Record (ring buffer entry with typed metadata)
  27. Return ExecResult{stdout, stderr, exit_code, duration_ms}

Phase 6: MCP Response (mcp.go)
  28. Marshal ExecResult to JSON
  29. Wrap in MCPToolsCallResult{Content: [{type: "text", text: json}]}
  30. Wrap in jsonRPCResponse{jsonrpc: "2.0", id: <req_id>, result: ...}
  31. Write HTTP 200 with Content-Type: application/json
```

### 3.4 Concurrency Model

All subsystems use Go's standard synchronization primitives. There are
no channels used for core data flow (only for signal handling and
background goroutine lifecycle).

| Subsystem        | Lock Type      | Contention Profile                   |
|------------------|----------------|--------------------------------------|
| PolicyEngine     | `sync.RWMutex` | Read-heavy; write only on SIGHUP     |
| CertState        | `sync.RWMutex` | Moderate; add/remove on each exec    |
| SessionManager   | `sync.Mutex`   | Low; session create/close infrequent |
| ExecSessionPool  | `sync.RWMutex` | Low; session lookup per exec         |
| ActivityStore    | `sync.RWMutex` | Moderate; write on every action      |
| ProxyEngine      | `sync.RWMutex` | Read-heavy; write on service add     |
| MCPFederator     | `sync.RWMutex` | Read-heavy; write on discovery       |
| HostController   | `sync.RWMutex` | Read-heavy; write on toggle          |
| GrantStore       | `sync.RWMutex` | Moderate; issue/validate per request |
| TaskManager      | `sync.RWMutex` | Low; create/revoke infrequent        |
| RevocationMap    | `sync.RWMutex` | Read-heavy; write on revoke/GC       |
| DelegationMgr    | `sync.RWMutex` | Read-heavy; write on rotation (~1/h) |
| Metrics          | `atomic.Int64` | Lock-free; no mutex contention       |
| EventHub         | `sync.RWMutex` | Write on broadcast; read on reg/unreg|

The Metrics subsystem is entirely lock-free, using `sync/atomic.Int64`
for all counters and fixed-bucket histograms. This ensures that latency
measurement never adds latency.

---

## 4. MCP Server

### 4.1 Protocol

Ephyr implements the Model Context Protocol (MCP) version 2025-03-26
using the Streamable HTTP transport. The protocol uses JSON-RPC 2.0
over `POST /mcp`.

```
Client                                          Server
  |                                                |
  |  POST /mcp                                     |
  |  Content-Type: application/json                |
  |  Authorization: Bearer <api_key>               |
  |                                                |
  |  {"jsonrpc":"2.0","id":1,                      |
  |   "method":"initialize",                       |
  |   "params":{"protocolVersion":"2025-03-26",    |
  |     "clientInfo":{"name":"claude","version":"1"}}}
  |----------------------------------------------->|
  |                                                |
  |  200 OK                                        |
  |  {"jsonrpc":"2.0","id":1,                      |
  |   "result":{"protocolVersion":"2025-03-26",    |
  |     "capabilities":{"tools":{"listChanged":true},
  |       "resources":{"listChanged":false}},      |
  |     "serverInfo":{"name":"ephyr","version":"1.0.0"}}}
  |<-----------------------------------------------|
  |                                                |
  |  POST /mcp  (notification, no id)              |
  |  {"jsonrpc":"2.0","method":"notifications/initialized"}
  |----------------------------------------------->|
  |  204 No Content                                |
  |<-----------------------------------------------|
  |                                                |
```

**Supported methods:**
- `initialize` -- Handshake with protocol version and capability exchange
- `notifications/initialized` -- Client confirmation (no response body)
- `tools/list` -- Returns tool definitions including federated tools
- `tools/call` -- Invokes a tool with arguments, returns content blocks
- `resources/list` -- Returns resource URIs including federated resources
- `resources/read` -- Returns resource content by URI

**Error codes:**
- `-32600` -- Invalid JSON-RPC request
- `-32601` -- Method not found
- `-32602` -- Invalid parameters
- `-32603` -- Internal error

### 4.2 Tool Inventory

Ephyr exposes 14 tools (9 local v0.1 + 4 task identity v0.2 + federated):

| Tool            | Category   | Description                                 |
|-----------------|------------|---------------------------------------------|
| `list_targets`  | SSH        | List SSH targets with roles and status       |
| `exec`          | SSH        | Execute command via ephemeral SSH cert        |
| `session_create`| SSH        | Open persistent SSH session                  |
| `session_close` | SSH        | Close persistent session                     |
| `list_sessions` | SSH        | List active persistent sessions              |
| `list_certs`    | SSH        | List active SSH certificates                 |
| `http_request`  | Proxy      | HTTP request with credential injection       |
| `list_services` | Proxy      | List configured proxy services               |
| `list_remotes`  | Federation | List federated MCP servers                   |
| `task_create`   | Identity   | Create task with scoped identity (v0.2)      |
| `task_info`     | Identity   | Get task information and envelope (v0.2)     |
| `task_revoke`   | Identity   | Revoke task and cascade to children (v0.2)   |
| `task_list`     | Identity   | List active tasks for agent (v0.2)           |
| `<remote>.<tool>` | Federated | Namespaced tools from remote MCP servers   |

### 4.3 Resource Inventory

Ephyr exposes 7 resources as MCP-standard `ephyr://` URIs:

| URI                  | Content Type     | Description                       |
|----------------------|------------------|-----------------------------------|
| `ephyr://overview`  | text/markdown    | System overview and quick start   |
| `ephyr://targets`   | text/markdown    | SSH target details                |
| `ephyr://services`  | text/markdown    | HTTP proxy service details        |
| `ephyr://roles`     | text/markdown    | Role definitions and permissions  |
| `ephyr://status`    | text/markdown    | Agent's active certs and sessions |
| `ephyr://tools`     | text/markdown    | Tool reference with examples      |
| `ephyr://remotes`   | text/markdown    | Federated MCP server status       |

Resources from federated remotes are exposed with a `remote:<name>/`
URI prefix.

### 4.4 Authentication Flow

```
                    API Key Authentication
                    =====================

  API Key: "sprawl-mcp-test-key-2026"
                |
                v
  +--------------------------+
  | SHA-256(api_key)         |  <-- Never store raw key
  | = fingerprint            |
  +--------------------------+
                |
                v
  +--------------------------+
  | Cache lookup:            |
  | cache[fingerprint]       |
  |   exists && not expired? |
  +--------------------------+
        |              |
       YES            NO
        |              |
        v              v
  +----------+   +---------------------------+
  | Return   |   | For each registered agent:|
  | cached   |   |   bcrypt.Compare(         |
  | MCPAgent |   |     agent.APIKeyHash,     |
  |          |   |     api_key)              |
  | ~<1us    |   |   Match? -> cache + return|
  +----------+   |                           |
                 |   ~216ms per comparison   |
                 +---------------------------+
```

The auth cache uses SHA-256 of the API key as the cache key. This avoids
storing the raw API key in memory while providing a unique, constant-time
lookup. Cache entries have a configurable TTL (default 60 seconds,
configurable via `EPHYR_AUTH_CACHE_TTL` environment variable, or
disabled entirely with "0").

The cache is invalidated when agents are added or removed (e.g., on
policy reload), ensuring stale credentials are never served.

### 4.5 Agent Configuration in Policy

Agents are configured in `policy.yaml` with bcrypt-hashed API keys:

```yaml
agents:
  claude:
    uid: 1000
    max_concurrent_certs: 20
    description: "Claude Code agent"
    api_key_hash: "$2a$10$o3MSVZK1FYM..."
    inherits: [full-ops]
    ssh:
      docker-host:
        roles: [read, operator, admin]
    services:
      github:
        methods: [GET, POST, PUT, PATCH, DELETE]
    dashboard: "admin"
```

---

## 5. HTTP Proxy Engine

### 5.1 Architecture

The ProxyEngine intercepts HTTP requests from agents, matches them against
configured services, injects stored credentials, enforces network policy,
and forwards to the backend.

```
  Agent Request               ProxyEngine                      Backend
  (no credentials)                                             Service
       |                           |                              |
       | url, method, headers      |                              |
       |-------------------------->|                              |
       |                           |                              |
       |                 1. Parse and validate URL                |
       |                 2. Evaluate network policy (CIDR)        |
       |                 3. Match service by URL prefix           |
       |                 4. Check service enabled                 |
       |                 5. Check method restrictions             |
       |                 6. Check path restrictions               |
       |                 7. Check/issue access grant              |
       |                 8. Inject credentials:                   |
       |                    bearer -> Authorization: Bearer <tok> |
       |                    basic  -> Basic auth header           |
       |                    header -> Custom header + prefix      |
       |                    query  -> URL query parameter         |
       |                    none   -> pass through                |
       |                 9. Add agent headers (no auth override)  |
       |                10. Apply timeout (max 120s)              |
       |                           |                              |
       |                           | request + credentials        |
       |                           |----------------------------->|
       |                           |                              |
       |                           |         response             |
       |                           |<-----------------------------|
       |                           |                              |
       |                11. Cap response body (default 1MB)       |
       |                12. Audit log the request                 |
       |                13. Broadcast event to dashboard          |
       |                           |                              |
       |  ProxyResult              |                              |
       |  (status, headers, body)  |                              |
       |<--------------------------|                              |
```

### 5.2 Credential Injection

The proxy supports five authentication types, configured per-service:

| Auth Type | Header Set                          | Example                     |
|-----------|-------------------------------------|-----------------------------|
| `bearer`  | `Authorization: Bearer <credential>`| GitHub PAT                  |
| `basic`   | `Authorization: Basic <b64>`        | Username + password         |
| `header`  | `<TokenHeader>: <TokenPrefix><cred>`| Custom header (e.g., Gitea) |
| `query`   | URL param `<TokenHeader>=<cred>`    | Query-based API keys        |
| `none`    | No credentials injected             | Public endpoints            |

Critical security property: agent-supplied headers that would override
injected credentials are silently dropped. If a service uses bearer auth,
the agent cannot supply its own `Authorization` header. Similarly, if a
service uses a custom header (e.g., `X-Gitea-Token`), the agent cannot
override that header.

### 5.3 Service Configuration

Services are stored in `/var/lib/ephyr/services.json` and persisted
with atomic writes (write to `.tmp`, then rename). Each service defines:

```json
{
  "github": {
    "name": "github",
    "url_prefix": "https://api.github.com",
    "auth_type": "bearer",
    "credential": "ghp_xxx...",
    "description": "GitHub API",
    "timeout": 30,
    "max_response_kb": 1024,
    "enabled": true
  }
}
```

Service matching uses longest-prefix-match: if multiple services have
URL prefixes that match the request URL, the one with the longest prefix
wins.

### 5.4 Network Policy

The network policy controls which destinations the proxy may reach. It
operates at the IP level after DNS resolution:

```json
{
  "allow_cidrs": ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"],
  "deny_cidrs": [],
  "external": "restricted",
  "external_allow": ["*.github.com"]
}
```

Policy evaluation order:
1. Deny CIDRs -- any match in deny list blocks the request
2. Private IPs -- if allow CIDRs configured, IP must match at least one
3. Public IPs -- evaluated against the `external` policy:
   - `"open"` -- all external hosts allowed
   - `"deny"` -- all external hosts blocked (default)
   - `"restricted"` -- only hosts matching `external_allow` glob patterns

DNS resolution uses a 2-second timeout to prevent DNS-based stalling
attacks. All resolved IPs are checked (not just the first), preventing
DNS rebinding from bypassing the CIDR policy.

---

## 6. MCP Federation

### 6.1 Overview

MCP Federation allows Ephyr to aggregate tools and resources from remote
MCP servers into a single unified namespace. Remote tools appear to agents
as `<remote_name>.<tool_name>`, and calls are proxied transparently
through the broker with credential injection.

```
  Agent                Ephyr Broker              Remote MCP Server
    |                      |                            |
    |  tools/list          |                            |
    |--------------------->|                            |
    |                      |                            |
    |  [list_targets,      |                            |
    |   exec,              |                            |
    |   http_request,      |                            |
    |   demo.roll_dice,    |  <-- federated tools       |
    |   demo.get_time]     |                            |
    |<---------------------|                            |
    |                      |                            |
    |  tools/call:         |                            |
    |  demo.roll_dice      |                            |
    |--------------------->|                            |
    |                      |                            |
    |              Parse: remote="demo"                 |
    |                      tool="roll_dice"             |
    |                      |                            |
    |              RBAC: CanAccessRemote("demo",        |
    |                      "roll_dice")                 |
    |                      |                            |
    |                      |  POST /mcp                 |
    |                      |  tools/call: roll_dice     |
    |                      |  +injected credentials     |
    |                      |--------------------------->|
    |                      |                            |
    |                      |  JSON-RPC result           |
    |                      |<---------------------------|
    |                      |                            |
    |  result (proxied)    |                            |
    |<---------------------|                            |
```

### 6.2 Remote Discovery

When a remote MCP server is added, the federator performs an automatic
MCP handshake:

```
Federator                              Remote Server
    |                                       |
    |  POST /mcp                            |
    |  initialize                           |
    |----- -------------------------------->|
    |  protocol_version, capabilities       |
    |<--------------------------------------|
    |                                       |
    |  POST /mcp                            |
    |  tools/list                           |
    |-------------------------------------->|
    |  [{name, description, inputSchema}]   |
    |<--------------------------------------|
    |                                       |
    |  POST /mcp                            |
    |  resources/list                       |
    |-------------------------------------->|
    |  [{uri, name, description}]           |
    |<--------------------------------------|
    |                                       |
    Store: tools, resources, protocol       |
    Status: connected                       |
```

Discovery runs in a background refresh loop (every 5 seconds check,
per-remote refresh interval defaults to 60 seconds). Error states use
exponential backoff: 10s, 30s, 60s, 120s, 300s (capped).

### 6.3 Tool Namespacing

Remote tools are prefixed with the remote name to avoid collisions:

```
Remote "demo-tools" with tools [roll_dice, get_time, convert_base]

Federated names:
  demo-tools.roll_dice
  demo-tools.get_time
  demo-tools.convert_base
```

The `ToolPrefix` field in the remote config can override the namespace
prefix if the remote name is too long or unwieldy.

### 6.4 Remote Configuration

Remotes are stored in `/var/lib/ephyr/remotes.json`:

```json
{
  "demo-tools": {
    "name": "demo-tools",
    "url": "http://192.168.100.74:8560/mcp",
    "auth_type": "none",
    "enabled": true,
    "timeout": 30,
    "refresh_seconds": 60,
    "max_response_kb": 1024
  }
}
```

Remotes support the same five authentication types as the proxy engine
(bearer, basic, header, query, none), with credentials stored in the
config and injected on every forwarded request.

### 6.5 RBAC for Federation

Per-agent federation access is controlled in the RBAC system:

```yaml
agents:
  claude:
    remotes:
      demo-tools:
        tools: [roll_dice, get_time]   # specific tools only
      monitoring-server: {}             # all tools allowed
      "*": {}                           # wildcard: all remotes
```

When `tools` is empty or omitted, all tools on that remote are accessible.
Wildcard `"*"` grants access to all remotes and tools.

---

## 7. Policy Engine

### 7.1 Policy Structure

The policy file (`/etc/ephyr/policy.yaml`) defines all access control
rules. It has four top-level sections:

```yaml
global:                    # Cluster-wide limits
  max_active_certs: 50     # Maximum concurrent certificates system-wide
  default_ttl: "5m"        # Default certificate TTL
  max_ttl: "30m"           # Maximum certificate TTL (hard cap)
  rate_limit:
    requests_per_window: 60
    window_seconds: 60

roles:                     # SSH role definitions
  read:
    principal: "agent-read"
    description: "Read-only access"
  operator:
    principal: "agent-op"
    description: "Operational commands"

targets:                   # SSH target hosts
  docker-host:
    host: "192.168.100.100"
    port: 22
    vlan: 100
    allowed_roles: [read, operator, admin]
    max_ttl: "10m"
    auto_approve: true

templates:                 # Reusable permission sets
  monitoring:
    ssh:
      "*":
        roles: [read]
    services:
      grafana:
        methods: [GET]
    dashboard: "viewer"

agents:                    # Per-agent configuration
  claude:
    uid: 1000
    api_key_hash: "$2a$10$..."
    inherits: [full-ops]
    ssh:
      docker-host:
        roles: [read, operator, admin]
    services:
      github:
        methods: [GET, POST, PUT, PATCH, DELETE]
    dashboard: "admin"
```

### 7.2 Policy Evaluation Pipeline

The policy engine evaluates SSH certificate requests through an 8-step
pipeline:

```
  EvalRequest{AgentUID, TargetName, RoleName, Duration}
                     |
     1. Clean expired certificates (avoid stale blocks)
                     |
     2. Agent exists? (lookup by UID)
            |
         NO: DENY "unknown agent UID"
            |
     3. Target exists?
            |
         NO: DENY "unknown target"
            |
     4. Role in target's allowed_roles?
            |
         NO: DENY "role not allowed on target"
            |
     5. Clamp duration: min(requested, target.max_ttl, global.max_ttl)
                     |
     6. Agent concurrent cert count < max_concurrent_certs?
            |
         NO: DENY "at concurrent cert limit"
            |
     7. Duplicate cert? (same agent+target+role)
            |
         YES: Auto-revoke old cert (agent wants fresh one)
            |
     8. Global cert count < max_active_certs?
            |
         NO: DENY "global cert limit reached"
            |
     9. Target auto_approve?
            |
         YES: APPROVE          NO: PENDING (await manual approval)
```

The engine returns an `EvalResult` with the decision, reason, clamped
duration, and the SSH principal from the matched role definition.

### 7.3 RBAC Resolution

Permissions are resolved at policy load time (not at request time) for
performance. The resolution algorithm:

```
1. For each agent:
     a. Check if agent has ANY RBAC fields (ssh, services, remotes,
        dashboard, inherits)
     b. If no RBAC fields: LegacyMode = true (full access, backwards compatible)
     c. If RBAC fields present:
          i.   Start with empty permission sets
          ii.  Merge templates left-to-right from `inherits` list
               (first-wins per key -- earlier templates take precedence)
          iii. Overlay agent-specific settings (always win over templates)
          iv.  Intersect SSH roles with target allowed_roles
               (agent can never exceed what the target permits)
          v.   Parse dashboard level (none/viewer/operator/admin)
```

### 7.4 Wildcard Handling

The RBAC system supports wildcards (`"*"`) at the target, service, and
remote levels:

```yaml
ssh:
  "*":                    # All targets
    roles: [read]
  docker-host:            # Specific override wins
    roles: [read, operator, admin]

services:
  "*":                    # All services
    methods: [GET]
  github:                 # Specific override wins
    methods: [GET, POST]

remotes:
  "*": {}                 # All remotes, all tools
```

Resolution order for permission checks:
1. Exact match by name (e.g., `docker-host`)
2. Wildcard match (`"*"`)
3. No match -> access denied

### 7.5 Hot-Reload via SIGHUP

Sending `SIGHUP` to the broker triggers a non-disruptive policy reload:

```
  SIGHUP
    |
    v
  1. Read policy.yaml from disk
  2. Parse and validate all fields
  3. Resolve durations (default_ttl, max_ttl, target max_ttls)
  4. Resolve RBAC permissions for all agents
  5. Acquire policyMu write lock
  6. Swap policyCfg and policyEngine atomically
  7. Release lock
  8. Update rate limiter with new config
  9. Reconcile host configs with new targets
  10. Invalidate auth cache (agent hashes may have changed)
  11. Audit log: "policy_reload" event
```

Active certificates and sessions are not affected by policy reload.
New requests will be evaluated against the new policy. If the reload
fails (parse error, validation failure), the previous policy remains
in effect and the error is logged.

---

## 8. Task Identity System (v0.2)

### 8.1 Overview

The v0.2 task identity system provides scoped, revocable, hierarchical
identity for agent operations. Instead of authenticating each request
independently with an API key, agents can create "tasks" that receive
a CTT-E (Ephyr Task Token - Execution) JWT. The token carries a
capability envelope that bounds what the task can do.

```
                       Trust Chain
                       ===========

  +-------------------+
  | Root CA Key       |     Ed25519 CA private key
  | (ephyr-signer)   |     held by signer process
  +-------------------+
           |
           | signs (IPC)
           v
  +-------------------+
  | Delegation Cert   |     Ephemeral Ed25519 keypair
  | (broker-generated)|     rotated every 50 minutes
  +-------------------+     signer signs the public key
           |
           | signs (local, no IPC)
           v
  +-------------------+
  | CTT-E Token       |     JWT with EdDSA signature
  | (per-task)        |     issued per agent request
  +-------------------+     sub-millisecond signing
```

### 8.2 Delegation Lifecycle

The DelegationManager runs a continuous lifecycle of ephemeral key
generation and delegation certificate rotation:

```
  Broker Startup
       |
       v
  1. Request root public key from signer (IPC)
       |
  2. Generate ephemeral Ed25519 keypair (crypto/rand)
       |
  3. Send public key to signer for delegation signing (IPC)
       |
  4. Signer signs canonical payload:
       JSON(cert_id, broker_id, public_key, issued_at, expires_at)
       Returns: cert_id, signature, expires_at
       |
  5. Store: private_key, public_key, cert_id, signature, expiry
       |
  6. Create TokenIssuer with delegation key
       |
  7. Create TokenValidator with pinned root public key
       |
  8. Register delegation cert with validator
       |
  9. Start rotation timer (default: 50 minutes)
       |
       |  ... serving requests, signing tokens locally ...
       |
  10. Timer fires -> rotate():
        a. Move current key -> previous key (graceful rollover)
        b. Generate new ephemeral keypair
        c. Request new delegation cert from signer (IPC)
        d. Update issuer with new key
        e. Register new cert with validator
        f. Increment DelegationRotations counter
       |
  [repeat from 10]
```

The previous key is retained until its delegation cert expires. This
ensures tokens signed with the old key remain valid during the
rotation window.

### 8.3 Token Format

CTT-E tokens are JWTs with the EdDSA algorithm:

```
Header (base64url):
{
  "alg": "EdDSA",
  "typ": "CTT-E",
  "kid": "<delegation_cert_id>"
}

Payload (base64url):
{
  "iss": "ephyr:<broker_instance_id>",
  "sub": "<agent_name>",
  "aud": "ephyr-broker",
  "iat": 1741856400,
  "exp": 1741858200,
  "jti": "cte_01J5VKRM7P3QXYZ...",
  "task": {
    "id": "01J5VKRM7P3QXYZ...",
    "root_id": "01J5VKRM7P3QXYZ...",
    "parent_id": "",
    "depth": 0,
    "lineage": ["01J5VKRM7P3QXYZ..."],
    "initiated_by": "ephyr:apikey:ak_xxx",
    "description": "Check dockerhost disk usage"
  },
  "envelope": {
    "targets": ["docker-host", "hugoblog"],
    "roles": ["read", "operator"],
    "services": ["github", "grafana"],
    "remotes": ["demo-tools"],
    "methods": ["GET", "POST"]
  }
}

Signature (base64url):
  Ed25519.Sign(delegation_private_key, header_b64 + "." + payload_b64)
```

### 8.4 ULID Task Identifiers

Task IDs use ULID (Universally Unique Lexicographically Sortable
Identifier), implemented from scratch without external dependencies:

```
  01J5VKRM7P3QXYZ1234567890AB
  |---------||-----------------| 
  timestamp  randomness
  (48-bit    (80-bit
   ms Unix)   crypto/rand)

Encoding: Crockford Base32 (excludes I, L, O, U)
Format:   10 chars timestamp + 16 chars random = 26 chars total
```

Properties:
- Lexicographically sortable by creation time
- 80 bits of cryptographic randomness (collision-resistant)
- Timestamp extractable: `ULIDTime(id) -> time.Time`
- Validation: `ValidateULID(id) -> bool`
- No external dependency (no `github.com/oklog/ulid`)

### 8.5 Token Signing Flow

Token signing is local to the broker (no IPC to signer):

```
  Agent calls task_create
           |
           v
  1. Validate TTL (max 1h, default 30m)
  2. Build envelope from policy:
       a. If RBAC mode: resolve explicit targets, roles, services,
          remotes, methods from ResolvedAgentPerms
       b. If legacy mode: include all targets/roles, wildcard services
       c. Resolve wildcards to literal lists at issuance time
          (tokens never contain "*")
  3. Generate ULID task ID
  4. Create Task in TaskManager (in-memory, with cleanup goroutine)
  5. Build TaskClaims with envelope, task identity, timestamps
  6. TokenIssuer.SignCTTE:
       a. Serialize header JSON (alg, typ, kid)
       b. Serialize payload JSON (claims with Unix timestamps)
       c. Base64url encode header and payload
       d. Ed25519.Sign(delegation_private_key, header + "." + payload)
       e. Base64url encode signature
       f. Return: header.payload.signature
  7. Record in Metrics (TokensSigned counter)
  8. Return token + task info to agent
```

Since the signing key is a local Ed25519 private key (not the CA key),
token signing does not require IPC to the signer process. This makes
signing sub-millisecond.

### 8.6 Token Validation Chain

```
  Incoming token: "header.payload.signature"
           |
           v
  1. Split on "." -> 3 parts (or reject)
  2. Base64url decode header -> extract kid
  3. Look up DelegationCert by kid (sync.Map)
       Not found? -> reject "unknown delegation key ID"
  4. Verify delegation cert against pinned root public key:
       a. Reconstruct canonical payload (cert_id, broker_id, pub_key, iat, exp)
       b. ed25519.Verify(root_public_key, payload, cert.Signature)
       c. Check delegation cert not expired
  5. Verify token signature against delegated public key:
       a. ed25519.Verify(delegation_public_key, header+"."+payload, sig)
  6. Base64url decode payload -> parse claims
  7. Check token not expired (exp > now)
  8. Check audience == "ephyr-broker"
  9. Return parsed TaskClaims
```

### 8.7 Capability Envelopes

Envelopes define the upper bound of what a task can do. They are
resolved from the agent's RBAC permissions at task creation time, with
wildcards expanded to literal lists:

```
  Agent RBAC:                      Envelope at issuance:
  ssh:                             targets: [docker-host, hugoblog,
    "*":                                     mandrake-rack]
      roles: [read, operator]      roles: [read, operator]
  services:                        services: [github, grafana,
    "*":                                      uptime-kuma, homepage,
      methods: [GET]                          command-center, gitea,
                                              portainer]
                                   methods: [GET]
                                   remotes: [demo-tools]
```

Wildcard resolution happens once at issuance. This ensures:
- Tokens are self-describing (no wildcard interpretation at validation)
- Adding a new target after token issuance does not expand the token
- Envelope subset checks are straightforward list comparisons

The `IsSubsetOf` method enables future delegation: a child task's
envelope must be a subset of its parent's envelope.

### 8.8 Revocation Model

Ephyr uses epoch-based watermark revocation instead of JTI blocklists:

```
  Traditional JTI Blocklist         Ephyr Epoch Watermarks
  =========================         =======================
  Store: every revoked JTI          Store: one entry per revoked TASK
  Lookup: O(1) per token            Lookup: O(depth) per token
  Memory: grows with token count    Memory: grows with task count
  Cascading: must enumerate         Cascading: automatic via lineage
             all child JTIs                    walk
  GC: complex (need to track        GC: simple (delete watermarks
      expiry per JTI)                    older than max_TTL)
```

When a task is revoked, a watermark is recorded:

```
  revocation_map[task_id] = time.Now()
```

Token validation checks the lineage array:

```
  for each task_id in token.lineage:
      if watermark[task_id] exists AND token.iat <= watermark[task_id]:
          REJECT "task was revoked"
```

This provides cascading revocation: revoking a parent task automatically
invalidates all children because the parent's ID appears in every
child's lineage array.

Watermark GC runs every 60 seconds and removes entries older than
`max_task_TTL`. Once a watermark is older than the maximum possible
task TTL, all tokens that could have been affected have already expired
naturally.

### 8.9 Graceful Degradation

The task identity system is designed for graceful degradation:

```
  Broker starts
       |
       v
  Request root_public_key from signer
       |
   SUCCESS                    FAILURE
       |                         |
  Request delegation cert        |
       |                         v
   SUCCESS        Task identity disabled.
       |          Log warning. Continue with
  Task identity   legacy auth (API key only).
  fully enabled.
  Both auth modes
  work simultaneously.
```

When task identity is disabled:
- All 4 task tools return errors explaining the feature is unavailable
- Existing tools (exec, http_request, etc.) continue to work with API
  key auth
- The `LegacyRequests` counter tracks requests without CTT tokens

---

## 9. Dashboard

### 9.1 Architecture

The dashboard is served on TCP port 8553, separate from the MCP
endpoint. It provides a real-time view of broker state through a
combination of REST APIs and WebSocket event streaming.

```
  Browser                    Dashboard Server (:8553)
    |                              |
    |  GET /                       |
    |  (static HTML/JS/CSS)        |
    |----------------------------->|
    |  <-- Single-page app         |
    |<-----------------------------|
    |                              |
    |  GET /v1/events?token=xxx    |
    |  Upgrade: websocket          |
    |----------------------------->|
    |  <-- WebSocket established   |
    |<-----------------------------|
    |                              |
    |  <-- Event: mcp_exec         |
    |  <-- Event: http_proxy       |
    |  <-- Event: grant_issued     |
    |  <-- Event: mcp_session_*    |
    |  <-- Event: host_toggle      |
    |  <-- Event: remote_toggle    |
    |  ...continuous stream...     |
    |<-----------------------------|
    |                              |
    |  REST API calls:             |
    |  GET /v1/dashboard/status    |
    |  GET /v1/dashboard/agents    |
    |  GET /v1/dashboard/activity  |
    |  POST /v1/dashboard/hosts/   |
    |        {name}/toggle         |
    |  POST /v1/dashboard/services/|
    |        {name}/toggle         |
    |  POST /v1/dashboard/remotes/ |
    |        {name}/toggle         |
    |----------------------------->|
    |<-----------------------------|
```

### 9.2 WebSocket Event Hub

The EventHub manages WebSocket connections with backpressure handling:

- Each client has a 64-slot buffered send channel
- Events dropped for slow clients (non-blocking send)
- Ping/pong keepalive: ping every 30s, pong timeout 60s
- Write timeout: 10s per message
- Read limit: 512 bytes (only pong frames expected)
- Client registration and unregistration are mutex-protected
- Events are JSON-serialized once and broadcast to all clients

Event format:
```json
{
  "type": "mcp_exec",
  "timestamp": "2026-03-13T10:30:00Z",
  "data": {
    "agent": "claude",
    "target": "docker-host",
    "role": "operator",
    "exit_code": "0"
  }
}
```

### 9.3 Dashboard Views

The dashboard provides 10 views across 4 groups:

| Group            | View           | Description                           |
|------------------|----------------|---------------------------------------|
| OVERVIEW         | Overview       | Stat cards, host/service/MCP panels,  |
|                  |                | active sessions, live event feed      |
| INFRASTRUCTURE   | Hosts          | SSH targets with enable/disable toggle|
|                  | Services       | HTTP proxy services with toggle       |
|                  | MCP Servers    | Federated remotes with toggle         |
| MONITOR          | Agents         | Per-agent stats and permissions       |
|                  | Activity       | Searchable activity log               |
|                  | Sessions       | Active SSH sessions                   |
|                  | Audit Log      | Structured audit events               |
| TOOLS            | Terminal       | (Reserved for future terminal access) |
|                  | Settings       | Configuration management              |

### 9.4 Toggle Operations

Hosts, services, and remote MCP servers can be enabled/disabled via the
dashboard (or API). Toggles take effect immediately:

- **Host disabled:** New certificate requests and exec calls to the host
  are denied. Active sessions are not terminated.
- **Service disabled:** HTTP proxy requests matching the service are
  denied with a clear error message.
- **Remote disabled:** Federated tool calls to the remote are denied.
  The federation refresh loop skips disabled remotes.

---

## 10. Metrics and Observability

### 10.1 Prometheus Exposition

Metrics are exposed in Prometheus text format at
`GET /v1/dashboard/metrics` on the dashboard port (8553).

### 10.2 Latency Histograms (8 total)

All histograms use 7 fixed buckets with lock-free atomic operations:

```
  Bucket Bounds:  <100us  <500us  <1ms  <5ms  <10ms  <50ms  >=50ms
  Prometheus le:  0.0001  0.0005  0.001 0.005 0.01   0.05   +Inf
```

| Histogram                  | Measures                              |
|---------------------------|---------------------------------------|
| `ephyr_token_sign`       | CTT-E token signing (local Ed25519)   |
| `ephyr_token_validate`   | CTT-E token validation chain          |
| `ephyr_watermark_check`  | Revocation watermark lineage walk     |
| `ephyr_envelope_check`   | Capability envelope subset check      |
| `ephyr_policy_eval`      | Policy evaluation pipeline            |
| `ephyr_ssh_cert`         | SSH cert signing via signer IPC       |
| `ephyr_delegation_ipc`   | Delegation cert request via IPC       |
| `ephyr_exec_e2e`         | End-to-end exec latency               |

Each histogram provides:
- Per-bucket cumulative counts
- Sum (nanoseconds, exposed as seconds)
- Count (total observations)
- Computed percentiles: p50, p95, p99 (via linear interpolation)

### 10.3 Counters and Gauges

| Metric                            | Type    | Description                       |
|-----------------------------------|---------|-----------------------------------|
| `ephyr_tasks_created_total`      | counter | Total tasks created               |
| `ephyr_tasks_active`             | gauge   | Currently active tasks            |
| `ephyr_tokens_signed_total`      | counter | Total CTT-E tokens signed         |
| `ephyr_tokens_validated_total`   | counter | Total tokens validated            |
| `ephyr_tokens_rejected_total`    | counter | Total tokens rejected             |
| `ephyr_watermark_revocations`    | counter | Total watermark revocations       |
| `ephyr_delegation_rotations`     | counter | Total delegation cert rotations   |
| `ephyr_legacy_requests_total`    | counter | Requests without CTT (legacy)     |
| `ephyr_auth_cache_hits_total`    | counter | Auth cache hits (bcrypt bypassed) |
| `ephyr_auth_cache_misses_total`  | counter | Auth cache misses (bcrypt needed) |
| `ephyr_active_watermarks`        | gauge   | Active revocation watermarks      |
| `ephyr_delegation_cert_age`      | gauge   | Seconds since delegation cert issued |
| `ephyr_delegation_certs_held`    | gauge   | Delegation certs in memory        |

### 10.4 Lock-Free Histogram Implementation

The `LatencyHistogram` struct uses `sync/atomic.Int64` for all state,
ensuring zero lock contention on the hot path:

```go
type LatencyHistogram struct {
    buckets [7]atomic.Int64  // fixed bucket array
    sum     atomic.Int64     // total nanoseconds
    count   atomic.Int64     // total observations
}

func (h *LatencyHistogram) Observe(d time.Duration) {
    ns := d.Nanoseconds()
    h.sum.Add(ns)
    h.count.Add(1)
    for i := 0; i < 6; i++ {
        if ns < latencyBucketBounds[i] {
            h.buckets[i].Add(1)
            return
        }
    }
    h.buckets[6].Add(1)  // >=50ms catch-all
}
```

This design ensures that timing an operation never becomes the
bottleneck. Multiple goroutines can record observations concurrently
without any synchronization beyond atomic memory operations.

### 10.5 Per-Request Timing

Individual request timing is captured in `RequestTiming` structs and
included in audit log entries:

```json
{
  "token_validate_ms": 0.042,
  "watermark_check_ms": 0.003,
  "envelope_check_ms": 0.001,
  "policy_eval_ms": 0.018,
  "ssh_cert_ms": 12.4,
  "ssh_exec_ms": 834.2,
  "total_ms": 847.1
}
```

---

## 11. Audit System

### 11.1 Structured JSON Logging

The audit system writes structured JSON lines to
`/var/log/ephyr/audit.json`. Each event is a single JSON object on
one line, enabling efficient parsing with standard tools (`jq`, log
aggregators).

```json
{
  "timestamp": "2026-03-13T10:30:00.123456Z",
  "severity": "INFO",
  "event_type": "mcp_exec",
  "agent": "claude",
  "target": "docker-host",
  "role": "operator",
  "serial": "001a2b3c4d5e6f70",
  "duration": "847ms",
  "details": {
    "command": "docker ps --format '{{.Names}}'",
    "exit_code": "0",
    "duration_ms": "847"
  }
}
```

### 11.2 Event Types

| Event Type          | Severity | Description                          |
|---------------------|----------|--------------------------------------|
| `startup`           | INFO     | Broker process started               |
| `shutdown`          | INFO     | Broker process stopping              |
| `policy_reload`     | INFO     | Policy reloaded via SIGHUP           |
| `cert_issued`       | INFO     | SSH certificate signed and issued    |
| `cert_denied`       | WARN     | Certificate request denied by policy |
| `cert_pending`      | INFO     | Certificate awaiting manual approval |
| `cert_revoked`      | INFO     | Certificate manually revoked         |
| `cert_expired`      | INFO     | Certificate expired naturally        |
| `rate_limited`      | WARN     | Request throttled by rate limiter    |
| `mcp_request`       | INFO     | MCP method call received             |
| `mcp_tool_call`     | INFO     | MCP tool invocation                  |
| `mcp_exec`          | INFO     | Command executed via SSH             |
| `mcp_exec_error`    | WARN     | Command execution failed             |
| `mcp_session_create`| INFO     | Persistent SSH session opened        |
| `mcp_session_close` | INFO     | Persistent SSH session closed        |
| `mcp_started`       | INFO     | MCP listener started                 |
| `mcp_federation`    | INFO     | Federated tool call forwarded        |
| `http_proxy`        | INFO     | HTTP request proxied                 |
| `http_proxy_denied` | WARN     | HTTP request blocked by policy       |
| `anomaly_detected`  | ALERT    | Behavioral anomaly detected          |
| `session_start`     | INFO     | Agent session started                |
| `session_reset`     | INFO     | Agent session reset                  |
| `request_pending`   | INFO     | Request awaiting approval            |
| `request_approved`  | INFO     | Pending request approved             |
| `request_denied`    | WARN     | Pending request denied               |

### 11.3 Multi-Writer

The AuditLogger supports multiple output writers simultaneously:

```
  AuditEvent
       |
       v
  +------------------+
  | JSON marshal     |
  | + newline        |
  +------------------+
       |
       +---> /var/log/ephyr/audit.json  (file, append mode)
       |
       +---> stdout  (if enabled, for journalctl)
```

The mutex ensures atomic writes across all writers, preventing
interleaved JSON lines.

### 11.4 Audit Fields

Every audit event carries:

| Field          | Always | Description                            |
|----------------|--------|----------------------------------------|
| `timestamp`    | Yes    | UTC RFC3339 with nanoseconds           |
| `severity`     | Yes    | INFO, WARN, ERROR, or ALERT            |
| `event_type`   | Yes    | Machine-readable event classifier      |
| `agent`        | When applicable | Agent name from auth        |
| `target`       | When applicable | SSH target name             |
| `role`         | When applicable | SSH role name               |
| `serial`       | When applicable | Certificate serial (hex)    |
| `duration`     | When applicable | Human-readable duration     |
| `reason`       | When applicable | Policy decision reason      |
| `details`      | When applicable | Free-form key-value pairs   |

---

## 12. Performance Characteristics

### 12.1 Auth Cache: Cold vs. Warm

| Scenario       | Latency         | Operations                          |
|----------------|-----------------|-------------------------------------|
| Cache miss     | ~216ms          | SHA-256 + N * bcrypt.Compare        |
| Cache hit      | <1us            | SHA-256 + map lookup + time compare |
| Cache disabled | ~216ms always   | SHA-256 + N * bcrypt.Compare        |

The bcrypt cost is fixed at 10 (Go default). With a single registered
agent, cold auth takes ~216ms. With multiple agents, worst case is
N * 216ms (each agent's hash is compared sequentially until a match
is found).

The cache TTL (default 60s) means the first request in each 60-second
window pays the bcrypt cost, and subsequent requests from the same
API key are sub-microsecond.

### 12.2 Session Reuse: 60x Speedup

| Mode           | Typical Latency | Operations                          |
|----------------|-----------------|-------------------------------------|
| One-shot exec  | ~850ms          | Keygen + IPC sign + SSH dial + exec |
| Session exec   | ~14ms           | SSH session open + exec on existing |

The one-shot path generates an ephemeral Ed25519 keypair, sends it to
the signer for certificate signing (IPC round-trip), establishes a new
SSH connection with certificate authentication, runs the command, and
tears down the connection.

The session path reuses an existing SSH connection, opening only a new
SSH session (multiplexed on the existing TCP connection) and running
the command. This avoids the keypair generation, signer IPC, TCP
handshake, and SSH handshake.

Sessions auto-close after 5 minutes idle and are limited to 5 per
agent.

### 12.3 Token Signing: Sub-Millisecond

| Operation        | Typical Latency | Notes                             |
|------------------|-----------------|-----------------------------------|
| Token signing    | <100us          | Local Ed25519.Sign (no IPC)       |
| Token validation | <200us          | Delegation cert verify + sig verify |
| Watermark check  | <10us           | O(depth) map lookups, depth < 5   |
| Envelope check   | <5us            | List subset comparisons           |

Token operations are local to the broker and never require IPC to the
signer. The delegation model "pushes" the expensive signer interaction
to key rotation time (once per hour), leaving per-request operations
lightweight.

### 12.4 Memory Model

| Subsystem      | Memory Profile                                   |
|----------------|--------------------------------------------------|
| ActivityStore  | Fixed: 10,000 entries * ~500 bytes = ~5MB max    |
| CertState      | Proportional to active certs (typically <100)     |
| TaskManager    | Proportional to active tasks (cleanup every 30s)  |
| RevocationMap  | Proportional to revoked tasks (GC every 60s)      |
| GrantStore     | Proportional to active grants (cleanup every 30s)  |
| Auth cache     | Proportional to unique API keys (typically <10)    |
| EventHub       | 64 * message_size per WebSocket client             |
| Metrics        | Fixed: ~1KB (atomic integers and histogram arrays) |

---

## 13. Deployment Topology

### 13.1 Single-Host Deployment (Current)

All three processes run on a single LXC container:

```
+---------------------------------------------------+
|  LXC Container (Debian 12, 1 vCPU, 512MB RAM)    |
|                                                   |
|  systemd                                          |
|  +-----+  +--------+  +--------+                 |
|  |signer|  |broker  |  |agent   |                 |
|  |uid999|  |uid999  |  |uid1000 |                 |
|  +-----+  +--------+  +--------+                 |
|      |          |           |                     |
|  /run/ephyr/signer.sock   |                     |
|      |          |           |                     |
|  /run/ephyr/broker.sock---+                     |
|                                                   |
|  nftables: input filter, agent UID output filter  |
|                                                   |
|  Ports: :8553 (dashboard), :8554 (MCP)            |
+---------------------------------------------------+
        |
        | SSH certs
        v
+-------------------+  +-------------------+
| Target Host A     |  | Target Host B     |
| TrustedUserCAKeys |  | TrustedUserCAKeys |
| = ephyr CA pub   |  | = ephyr CA pub   |
+-------------------+  +-------------------+
```

### 13.2 Multi-Host Deployment (Future)

For larger deployments, the signer can run on a dedicated hardened host:

```
+------------------+         +------------------+
| Signer Host      |   IPC   | Broker Host      |
| (hardened, no    |<------->| (network-facing, |
|  network access  |  over   |  MCP + dashboard)|
|  except Unix IPC)|  Unix   |                  |
|                  | socket  |                  |
|  CA key in       |  (or    |  policy.yaml     |
|  /etc/ephyr/    |  TCP    |  services.json   |
|  ca_key          |  with   |  remotes.json    |
|                  |  mTLS)  |                  |
+------------------+         +------------------+
```

In a multi-host scenario, the signer's Unix socket IPC would be
replaced with a TCP transport secured by mutual TLS. The signer's
`SO_PEERCRED` validation would be replaced with client certificate
validation.

### 13.3 Systemd Units

**ephyr-signer.service:**

```
[Service]
Type=simple
User=ephyr-broker
ExecStart=/usr/local/bin/ephyr-signer \
  --ca-key /etc/ephyr/ca_key \
  --socket /run/ephyr/signer.sock
Environment=EPHYR_BROKER_UID=999

# Security hardening
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
NoNewPrivileges=yes
RestrictAddressFamilies=AF_UNIX     <-- No network access
MemoryDenyWriteExecute=yes
CapabilityBoundingSet=              <-- No capabilities
SystemCallFilter=@system-service
ReadOnlyPaths=/etc/ephyr
ReadWritePaths=/run/ephyr
```

**ephyr-broker.service:**

```
[Service]
Type=simple
User=ephyr-broker
ExecStart=/usr/local/bin/ephyr-broker \
  --policy /etc/ephyr/policy.yaml \
  --signer-socket /run/ephyr/signer.sock \
  --listen /run/ephyr/broker.sock \
  --audit-log /var/log/ephyr/audit.json
ExecReload=/bin/kill -HUP $MAINPID
Environment=EPHYR_ADMIN_UIDS=0,1000

Requires=ephyr-signer.service
After=ephyr-signer.service

# Security hardening
ProtectSystem=strict
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6  <-- Network allowed
CapabilityBoundingSet=
ReadOnlyPaths=/etc/ephyr
ReadWritePaths=/run/ephyr /var/log/ephyr /var/lib/ephyr
```

Key differences between signer and broker service units:
- Signer is restricted to `AF_UNIX` only (no TCP)
- Broker allows `AF_INET`/`AF_INET6` (needs TCP for dashboard/MCP)
- Broker depends on signer (`Requires`, `After`)
- Broker supports `ExecReload` (SIGHUP for policy reload)
- Both run as the same user (UID 999) with identical hardening

### 13.4 nftables Isolation

The LXC firewall provides two layers of protection:

```
Input chain (default DROP):
  - Established/related connections: ACCEPT
  - Loopback: ACCEPT
  - ICMP: ACCEPT
  - SSH (port 22): ACCEPT
  - Dashboard (port 8553, from 192.168.0.0/16): ACCEPT
  - MCP (port 8554, from 192.168.0.0/16): ACCEPT

Output chain (default ACCEPT):
  - Agent UID 1000 -> 192.168.100.100 (DockerHost): DROP
  - Agent UID 1000 -> 192.168.100.54 (Gitea): DROP
  - Agent UID 1000 -> 192.168.100.63 (HugoBlog): DROP
  - Agent UID 1000 -> 192.168.100.74 (CommandCenter): DROP
  - Agent UID 1000 -> 192.168.30.55 (MandrakeRack): DROP
```

The output rules ensure that the agent process (UID 1000) cannot
directly reach any backend service. All access must go through the
broker's Unix socket (localhost), which the broker then proxies to
the backend with credential injection. This prevents agents from
bypassing the broker's RBAC and audit controls.

### 13.5 File System Layout

```
/etc/ephyr/
  ca_key                    Ed25519 CA private key (chmod 0600)
  policy.yaml               Policy configuration (chmod 0640)

/run/ephyr/
  signer.sock               Signer IPC socket (chmod 0660)
  broker.sock               Broker IPC socket (chmod 0660)

/var/lib/ephyr/
  services.json             HTTP proxy service configs
  remotes.json              Federated MCP server configs
  network_policy.json       CIDR allow/deny rules
  hosts.json                Persisted host toggle states

/var/log/ephyr/
  audit.json                Structured audit log (JSON lines)

/opt/ephyr/
  cmd/broker/main.go        Broker entry point
  cmd/signer/main.go        Signer entry point
  cmd/ephyr/main.go        CLI entry point
  internal/broker/          Broker subsystems (~15,000 lines)
  internal/policy/          Policy engine and RBAC (~1,500 lines)
  internal/audit/           Audit logger (~200 lines)
  internal/auth/            Session management and peer cred (~200 lines)
  internal/signer/          Signer logic and IPC client (~800 lines)
  internal/token/           Token types, signing, validation, ULID (~800 lines)
  dashboard/                Static HTML/CSS/JS for dashboard
  docs/                     Documentation
```

---

## 14. Extension Points

### 14.1 Adding a New HTTP Proxy Service

Services can be added via the dashboard REST API or by editing
`/var/lib/ephyr/services.json`:

```json
{
  "new-service": {
    "name": "new-service",
    "url_prefix": "http://192.168.100.50:8080",
    "auth_type": "bearer",
    "credential": "secret-token-here",
    "description": "New internal service",
    "timeout": 30,
    "max_response_kb": 2048,
    "enabled": true,
    "allowed_methods": ["GET", "POST"],
    "allowed_paths": ["/api/*"]
  }
}
```

The proxy engine watches for file changes and supports live reload.
Agents will see the new service immediately via `list_services`.

To restrict agent access, add the service to the agent's RBAC policy:

```yaml
agents:
  claude:
    services:
      new-service:
        methods: [GET]
```

### 14.2 Adding a New MCP Tool

New tools require three changes in the broker code:

**1. Define the tool schema** in `mcp_tools.go` `toolDefinitions()`:

```go
{
    Name:        "new_tool",
    Description: "Description of the new tool",
    InputSchema: map[string]interface{}{
        "type": "object",
        "properties": map[string]interface{}{
            "param1": map[string]interface{}{
                "type":        "string",
                "description": "Parameter description",
            },
        },
        "required": []string{"param1"},
    },
},
```

**2. Add the dispatch case** in `handleToolCall()`:

```go
case "new_tool":
    return s.toolNewTool(ctx, agent, args)
```

**3. Implement the handler:**

```go
func (s *MCPServer) toolNewTool(ctx context.Context, agent *MCPAgent,
    args map[string]interface{}) (*MCPToolsCallResult, error) {
    param1, ok := getStringArg(args, "param1")
    if !ok {
        return errorResult("missing required argument: param1"), nil
    }
    // Implementation...
    return jsonResult(result)
}
```

### 14.3 Adding a New Federation Remote

Remotes can be added via the dashboard API:

```
POST /v1/dashboard/remotes
Content-Type: application/json

{
  "name": "my-tools",
  "url": "http://192.168.100.80:8560/mcp",
  "auth_type": "bearer",
  "credential": "remote-api-key",
  "enabled": true,
  "timeout": 30,
  "refresh_seconds": 60,
  "description": "My custom MCP server"
}
```

The federator will:
1. Validate the configuration
2. Persist to `/var/lib/ephyr/remotes.json`
3. Trigger asynchronous discovery (initialize + tools/list + resources/list)
4. On success: federated tools appear as `my-tools.<tool_name>`

Agent access is controlled via RBAC:

```yaml
agents:
  claude:
    remotes:
      my-tools:
        tools: [specific_tool]  # or empty for all tools
```

### 14.4 Adding a New Auth Provider

The current auth model uses bcrypt-hashed API keys. To add a new
authentication method (e.g., mTLS, OIDC), modify `mcp_auth.go`:

**1. Extend the `Authenticate` method** to check the new auth source
before falling through to bcrypt:

```go
func (a *MCPAuthenticator) Authenticate(apiKey string) (*MCPAgent, error) {
    // Check mTLS cert first (from request context)
    // Check OIDC token (Bearer with JWT validation)
    // Fall through to bcrypt API key comparison
}
```

**2. Add new agent config fields** in `policy/types.go`:

```go
type AgentPolicy struct {
    // ...existing fields...
    ClientCertFingerprint string `yaml:"client_cert_fingerprint"`
    OIDCSubject           string `yaml:"oidc_subject"`
}
```

**3. Update the MCP listener** in `server.go` to pass TLS client
certificate info to the authenticator.

The auth cache architecture generalizes naturally: any new auth method
can use the same SHA-256-keyed cache with configurable TTL, avoiding
expensive validation on every request.

### 14.5 Adding New SSH Targets

Targets are added in `policy.yaml` and take effect on SIGHUP:

```yaml
targets:
  new-host:
    host: "192.168.100.200"
    port: 22
    vlan: 100
    allowed_roles: [read, operator]
    max_ttl: "10m"
    auto_approve: true
    description: "New host"
```

The target host must trust the Ephyr CA:

```bash
# On the target host:
echo "<CA_PUBLIC_KEY>" >> /etc/ssh/ca_key.pub
echo "TrustedUserCAKeys /etc/ssh/ca_key.pub" >> /etc/ssh/sshd_config

# Create role accounts:
useradd -m -s /bin/rbash agent-read
useradd -m -s /bin/bash agent-op
useradd -m -s /bin/bash agent-admin

systemctl reload sshd
```

After reloading the broker policy (`systemctl reload ephyr-broker`),
agents with appropriate RBAC permissions will see the new target via
`list_targets` and can execute commands on it.

---

## Appendix A: Glossary

| Term              | Definition                                          |
|-------------------|-----------------------------------------------------|
| CA                | Certificate Authority -- the Ed25519 key that signs  |
|                   | SSH certificates and delegation certs                |
| CTT-E             | Ephyr Task Token - Execution: a JWT authorizing     |
|                   | a specific task's operations                         |
| CTT-D             | Ephyr Task Token - Delegation: (Phase 2b) a JWT     |
|                   | allowing a task to create sub-tasks                  |
| Delegation Cert   | A certificate from the signer authorizing the broker  |
|                   | to sign CTT tokens with an ephemeral key             |
| Envelope          | Capability bounds for a task: targets, roles,         |
|                   | services, remotes, and methods                       |
| IPC               | Inter-Process Communication via Unix domain socket    |
| Lineage           | Array of task IDs from root to current task           |
| MCP               | Model Context Protocol -- the transport protocol      |
|                   | for AI agent tool access                             |
| RBAC              | Role-Based Access Control with template inheritance   |
| SO_PEERCRED       | Linux socket option to retrieve the UID/GID/PID       |
|                   | of the connected process                             |
| ULID              | Universally Unique Lexicographically Sortable ID      |
| Watermark         | Epoch-based revocation: a timestamp recording when    |
|                   | a task was revoked, invalidating all earlier tokens   |

## Appendix B: Configuration Reference

### Environment Variables

| Variable                | Default              | Description                   |
|------------------------|----------------------|-------------------------------|
| `EPHYR_POLICY`        | `/etc/ephyr/policy.yaml` | Policy file path         |
| `EPHYR_SIGNER_SOCKET` | `/run/ephyr/signer.sock` | Signer IPC socket        |
| `EPHYR_LISTEN`        | `/run/ephyr/broker.sock` | Broker Unix socket       |
| `EPHYR_AUDIT_LOG`     | `/var/log/ephyr/audit.json` | Audit log path        |
| `EPHYR_DASHBOARD_LISTEN` | `:8553`           | Dashboard TCP address         |
| `EPHYR_DASHBOARD_TOKEN`  | (auto-generated)  | Dashboard auth token          |
| `EPHYR_DASHBOARD_DIR`    | `/opt/ephyr/dashboard` | Static files directory  |
| `EPHYR_MCP_LISTEN`       | `:8554`           | MCP server TCP address        |
| `EPHYR_AUTH_CACHE_TTL`   | `60s`             | Auth cache TTL (0=disabled)   |
| `EPHYR_SOCKET_GROUP`     | `ephyr-agents`   | Unix socket group ownership   |
| `EPHYR_ADMIN_UIDS`       | `0`               | Comma-separated admin UIDs    |
| `EPHYR_BROKER_UID`       | `-1` (any)        | Allowed caller UID for signer |
| `EPHYR_CA_KEY`            | `/etc/ephyr/ca_key` | CA private key path       |

### Operational Commands

```bash
# Start/stop
systemctl start ephyr-signer ephyr-broker
systemctl stop ephyr-broker ephyr-signer

# Restart (signer must start before broker)
systemctl restart ephyr-signer ephyr-broker

# Hot-reload policy (no downtime)
systemctl reload ephyr-broker

# View logs
journalctl -u ephyr-broker -f
journalctl -u ephyr-signer -f

# Parse audit log
jq '.event_type' /var/log/ephyr/audit.json | sort | uniq -c | sort -rn

# Check health
curl -s http://localhost:8554/mcp -X POST \
  -H "Authorization: Bearer <key>" \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26"}}'
```

---

*This document describes the architecture of Ephyr v0.2. It is derived
from the source code at `/opt/ephyr/` and reflects the implementation
as of 2026-03-13.*
