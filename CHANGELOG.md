# Changelog

## [Unreleased] — v0.2.0-alpha (Task Identity)

### Added
- **Task-scoped identity (Phase 2a)**: Agents can create tasks with `task_create`, receiving a signed CTT-E token that correlates all actions to a task ID
- **Tiered trust model**: Signer issues delegation certificates to the broker; broker signs task tokens locally without IPC per-request
- **Epoch watermark revocation**: `task_revoke` invalidates all tokens for a task via timestamp-based watermarking (O(depth) validation, no per-token blocklists)
- **4 new MCP tools**: `task_create`, `task_info`, `task_revoke`, `task_list`
- **Performance metrics**: Lock-free latency histograms, Prometheus `/v1/metrics` endpoint, per-request timing breakdown in audit entries
- **ULID task IDs**: Lexicographically sortable, collision-resistant, encode creation time
- **Capability envelopes**: Task tokens carry an upper-bound envelope (targets, roles, services, remotes, methods) resolved from RBAC policy at creation time
- **Identity URN scheme**: `clauth:local:uid:*` and `clauth:apikey:*` bootstrap identity formats
- **Delegation key rotation**: Broker auto-rotates its signing key before delegation cert expiry (configurable TTL/refresh)
- **Legacy mode**: Full backward compatibility — agents without task tokens continue to work unchanged

### Changed
- Signer now supports 4 IPC actions: `ping`, `sign`, `sign_delegation`, `root_public_key`
- BrokerServer initializes task identity subsystem at startup (graceful degradation if signer doesn't support delegation)
- Audit entries can include task correlation fields (`task_id`, `task_root_id`, `task_lineage`)

## [0.1.0] — 2026-03-13

### Added
- Three-process architecture: signer (CA key custody), broker (policy + proxy), CLI
- SSH exec via ephemeral Ed25519 certificates
- HTTP proxy with automatic credential injection (7 services)
- MCP federation with remote tool aggregation
- Per-agent RBAC with template inheritance, wildcards, role intersection
- Real-time dashboard with 10 views (overview, hosts, services, MCP servers, agents, activity, sessions, audit, terminal, settings)
- Policy hot-reload via SIGHUP
- Rate limiting (per-UID sliding window)
- WebSocket event streaming for dashboard
- 165 tests, GitHub Actions CI (build + test + lint)
- Threat model document (12 enumerated threats)
