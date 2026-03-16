# Changelog

All notable changes to Ephyr are documented in this file.

Format based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [0.2b] -- 2026-03-14

Macaroon-based task tokens (**Ephyr Delegation**). Replaces JWT-based CTT-E/CTT-D tokens with HMAC-chained macaroons and introduces the effective envelope reducer.

### Added

- **`internal/macaroon/` package** -- pure stdlib macaroon implementation (HMAC-SHA256, no external dependency). Types, HMAC chain construction, serialization. 17 unit tests.
- **Effective envelope reducer** -- set intersection, minimum, and boolean AND rules derive the most-restrictive authority from accumulated caveats. 22 unit tests + 2 fuzz targets (220k executions).
- **RootKeyStore, Minter, and Verifier** -- macaroon lifecycle management with benchmark (~34us mint, ~32us verify). 23 unit tests.
- **`ephyr inspect` CLI command** -- inspects macaroon caveats in human-readable or JSON format. Accepts token via argument, stdin, or file. 3 input modes.
- **Macaroon Prometheus counters** -- `ephyr_macaroon_minted_total`, `ephyr_macaroon_verified_total`, plus 2 latency histograms.
- **12 integration tests** -- end-to-end macaroon delegation, attenuation enforcement, cross-agent delegation, and performance benchmarks.
- **Signature index in TaskManager** -- maps macaroon signatures to task IDs for O(1) lookup. 5 new tests.

### Changed

- **Task tokens are now macaroon-based** -- `task_create` and `task_delegate` mint macaroons instead of JWTs. Tokens carry a `mac_` prefix for identification.
- **Dual-mode authentication** -- broker accepts `mac_` (macaroon), JWT (`eyJ`), and API key authentication. Existing JWT tokens and API keys continue to work.
- **MCPAgent struct** -- unified agent identity populated from macaroon envelope or legacy JWT claims.
- **Envelope checking** -- extracted to `envelope_check.go`, shared between macaroon and JWT auth paths.

### Security

- Task tokens are bearer tokens by default. A leaked macaroon can be used by anyone until TTL expiry or epoch watermark revocation. This is mitigated by short TTLs (default 30 minutes, max 1 hour) and watermark revocation. Holder binding is available via Ephyr Bind (v0.3) for tasks that opt in.
- The HMAC chain proves caveat accumulation (caveats cannot be removed). The reducer derives semantic narrowing (set intersection, minimum, boolean AND). These are distinct guarantees -- do not conflate them.

## [0.3.0] -- 2026-03-13

> **Note:** This release and all earlier releases were developed under the name "Clauth" (now renamed to Ephyr).

Delegation with attenuation: parent tasks can spawn scoped child tasks with monotonically reduced capabilities.

### Added

- **Delegation with attenuation**: Parent tasks can delegate child tasks via `task_delegate` with capability envelopes that are equal to or a strict subset of the parent's
- **`task_delegate` MCP tool**: Creates a child task under an existing parent, returns a CTT-D (delegation) token
- **`task_bind` MCP tool**: Binds a task token to a holder key for proof-of-possession, with two-phase delegation and auto-revocation on bind deadline -- bringing the total to 15 local tools
- **Proof-of-possession enforcement in auth hot path**: Bound tokens (`HolderBound=true`) require a valid `_pop` field (Ed25519 signature, body_hash, mac_digest, nonce, timestamp) on every `tools/call`. Unbound tokens with a bind deadline return 423 Locked for all tools except `task_bind`. API key and JWT auth bypass PoP. Clock skew configurable via `EPHYR_POP_CLOCK_SKEW` (default 30s). `_pop` field is stripped before tool handlers see it.
- **CTT-D token type**: New delegation token signed by the broker, validated alongside CTT-E tokens via the shared trust chain
- **`SignCTTD()` issuer method**: Signs CTT-D tokens with `"ctd_"` JTI prefix and `"CTT-D"` type header
- **`Validate()` validator method**: Accepts both CTT-E and CTT-D token types; `ValidateCTTE()` remains backward compatible (rejects CTT-D)
- **`CreateChildTask()` task manager method**: Enforces agent match, `CanDelegate` permission, depth limit (max 5), TTL constraint, and envelope attenuation
- **`TaskEnvelope.IsSubsetOf()`**: Delegates to `token.Envelope.IsSubsetOf()` for broker-layer attenuation checks
- **`can_delegate` parameter on `task_create`**: Opt-in flag to allow a root task to spawn children (default false)
- **`TokensDelegated` Prometheus counter**: `ephyr_tokens_delegated_total` tracks CTT-D token issuance
- **7 delegation integration tests**: Create, attenuation enforcement, cascading revocation, depth limit, TTL constraint, `can_delegate` requirement, envelope inheritance
- **13 delegation unit tests**: Covering child creation, lineage chains, depth limits, TTL, envelope attenuation/violation/inheritance, agent mismatch, concurrent creation, lineage copy safety

### Changed

- `authenticateWithCTTE()` now calls `Validate()` instead of `ValidateCTTE()`, accepting both CTT-E and CTT-D tokens for MCP authentication
- MCP tool count increased from 14 to 16 (9 core + 6 task + federated)

## [0.2.0] -- 2026-03-13

> **Note:** Released under the name "Clauth" (now renamed to Ephyr).

Task-scoped portable identity, auth caching, Prometheus metrics, and integration test suite.

### Added

- **Task-scoped identity**: Agents create tasks via `task_create` and receive a signed CTT-E (Ephyr Task Token - Envelope) JWT that correlates all subsequent actions to a task ID with a capability envelope
- **4 new MCP tools**: `task_create`, `task_info`, `task_list`, `task_revoke` -- bringing the total to 14 local tools
- **Tiered trust model**: Signer issues delegation certificates to the broker; broker signs task tokens locally without IPC round-trip per request
- **Capability envelopes**: Task tokens carry an upper-bound permission set (targets, roles, services, remotes, methods) resolved from RBAC policy at creation time
- **Epoch watermark revocation**: `task_revoke` invalidates all tokens for a task via timestamp watermarking with O(depth) validation and no per-token blocklists; cascading revocation propagates to child tasks
- **ULID task IDs**: Lexicographically sortable, collision-resistant identifiers that encode creation time
- **Identity URN scheme**: `ephyr:local:uid:*` and `ephyr:apikey:*` bootstrap identity formats
- **Delegation key rotation**: Broker auto-rotates its signing key before delegation certificate expiry (configurable TTL/refresh)
- **Prometheus metrics endpoint**: `GET /v1/metrics` with Prometheus exposition format -- 8 latency histograms, 10 counters/gauges covering tasks, tokens, delegation, auth cache, and legacy requests
- **Auth cache**: SHA-256 keyed bcrypt result cache with configurable TTL (`EPHYR_AUTH_CACHE_TTL` env var, default 60s)
- **Integration test suite**: 8 end-to-end tests in `test/integration/smoke_test.go` covering MCP handshake, tool listing, legacy compatibility, task lifecycle, task validation, metrics, and performance benchmarks
- **Legacy mode**: Full backward compatibility -- agents without task tokens continue to work unchanged

### Changed

- Signer now supports 4 IPC actions: `ping`, `sign`, `sign_delegation`, `root_public_key`
- BrokerServer initializes task identity subsystem at startup with graceful degradation if signer does not support delegation
- Audit entries include task correlation fields (`task_id`, `task_root_id`, `task_lineage`) when a task token is present
- MCP tool count increased from 10 to 14 (9 core + 4 task + federated)
- Codebase grew from ~16,000 to ~23,000 lines of Go across 64 files
- Test count increased from 165 to 253 across 13 test files

### Fixed

- Removed unused stub function flagged by linter
- Simplified ULID validation per gosimple S1002
- Fixed CI test path resolution and lint errors
- Fixed test fixtures to use testdata directory convention

### Performance

- **Auth cache**: 187x speedup on repeated MCP requests -- cold auth ~216ms (bcrypt), warm auth <1ms (cache hit). Configurable TTL via `EPHYR_AUTH_CACHE_TTL` (default 60s). Disable with `EPHYR_AUTH_CACHE_TTL=0`.
- **Token signing**: <1ms via local Ed25519 signing with delegated key (no IPC per token)
- **Token validation**: <1ms for signature + envelope + watermark check

## [0.1.0] -- 2026-03-13

> **Note:** Released under the name "Clauth" (now renamed to Ephyr).

Initial release. Three-process architecture with SSH certificate authority, HTTP proxy, MCP federation, RBAC, and admin dashboard.

### Added

- **Three-process architecture**: ephyr-signer (CA key custody), ephyr-broker (policy + proxy), ephyr CLI
- **SSH certificate authority**: Ed25519 CA issuing ephemeral per-request certificates with 5-minute default TTL
- **Persistent SSH sessions**: Reduce per-command latency from ~850ms to ~14ms for sequential operations
- **HTTP proxy with credential injection**: Bearer, basic auth, custom header, and query parameter injection for 7+ service types
- **MCP server**: 10 tools over JSON-RPC 2.0 / Streamable HTTP (MCP 2025-03-26)
- **MCP resources**: 7 self-discovery resources (`ephyr://overview`, `ephyr://targets`, etc.)
- **MCP federation**: Aggregate tools from remote MCP servers with namespace prefixing and automatic discovery
- **Policy engine**: Declarative YAML with 8-step evaluation pipeline and hot-reload via SIGHUP
- **RBAC**: Per-agent permissions across SSH, HTTP proxy, MCP federation, and dashboard with template inheritance and wildcard support
- **TTL-based access grants**: Time-limited grants for SSH certificates, services, and MCP remotes with automatic cleanup
- **Admin dashboard**: Single-page UI with 10 views -- overview, hosts, services, MCP servers, agents, activity, sessions, audit log, terminal, settings
- **WebSocket event streaming**: Real-time state changes pushed to dashboard clients
- **Activity monitoring**: 10,000-entry ring buffer tracking 7 activity types with per-agent statistics
- **Structured audit logging**: Append-only JSON-line format with logrotate integration
- **Network isolation**: nftables rules blocking agent UID from direct backend access
- **Security hardening**: SO_PEERCRED authentication, constant-time token comparison, systemd sandboxing, CA key isolation
- **Rate limiting**: Per-agent sliding window rate limiter
- **Target provisioning**: Automated script for deploying role accounts, principals, and sudoers to target hosts
- **MCP client integration**: Configuration guides for Claude Code, Claude Desktop, Cursor, and Cline
- **165 unit tests** across policy engine, grants, rate limiter, and broker internals
- **GitHub Actions CI**: Build, test, and lint pipeline
- **Threat model**: 12 enumerated threats with mitigations and residual risk assessment
- **Documentation**: Architecture, security, configuration, deployment, API reference, and MCP integration guides
