# Ephyr Implementation Progress

## Phase 1: Rename Clauth → Ephyr

| Step | Description | Status | Agent | Notes |
|------|-------------|--------|-------|-------|
| 1.0 | Pre-flight: tag v0.3.0-pre-rename, backup | DONE | manual | Tagged + LXC backup |
| 1.1 | Atomic source rename (62 files, ~1350 lines) | IN PROGRESS | rename-agent | go.mod, imports, env vars, paths, metrics, URIs |
| 1.2 | Deploy files + dashboard + docs rename | | | systemd, provision, dashboard branding |
| 1.3 | Build verification + all tests pass | | | go build ./... && go test -race ./... |
| 1.4 | Commit, push to Gitea + GitHub | | | Single atomic commit |
| 1.5 | LXC migration (paths, systemd, users, binaries) | | | ~3 min downtime |
| 1.6 | Target host migration (CA key, sudoers, sshd) | | | 3 hosts |
| 1.7 | Update external refs (CLAUDE.md, memory, MCP config) | | | |

## Phase 2: Macaroon Engine v0.2b

| Milestone | Description | Status | Agent | Notes |
|-----------|-------------|--------|-------|-------|
| 2b.1 | `internal/macaroon/` types + HMAC chain (no ext deps) | | | Pure stdlib crypto/hmac |
| 2b.2 | Reducer (safety-critical) + fuzz tests | | | Set intersection, minimum, AND |
| 2b.3 | RootKeyStore + Minter + Verifier + tests | | | 8-step verification pipeline |
| 2b.3b | TaskManager signature index | | | SHA-256 sig→task lookup |
| 2b.3c | Metrics preparation | | | Prometheus counters/histograms |
| 2b.4 | Auth rewrite: mcp_token_auth.go (JWT→macaroon) | | | Dual-mode during migration |
| 2b.4b | MCPAgent struct + envelope_check.go | | | EffectiveEnvelope type |
| 2b.5 | Tool handlers: mcp_task.go (mint/delegate) | | | task_create, task_delegate |
| 2b.6 | `ephyr inspect` CLI command | | | Caveat display, effective envelope |
| 2b.7 | Integration tests + performance benchmarks | | | Full pipeline verification |

## Phase 3: Documentation Review

| Step | Description | Status | Agent | Notes |
|------|-------------|--------|-------|-------|
| 3.1 | STYLE-GUIDE compliance audit (all .md files) | | | Voice, naming, formatting |
| 3.2 | README.md rewrite (Ephyr product framing) | | | Match /home/claude/EPHYR/README.md |
| 3.3 | Architecture + security docs alignment | | | Tier model, invariants |
| 3.4 | CHANGELOG update for rename + v0.2b | | | Keep a Changelog format |
