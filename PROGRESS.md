# Ephyr Implementation Progress

## Phase 1: Rename Clauth → Ephyr

| Step | Description | Status | Agent | Notes |
|------|-------------|--------|-------|-------|
| 1.0 | Pre-flight: tag v0.3.0-pre-rename, backup | DONE | manual | Tagged + LXC backup |
| 1.1 | Atomic source rename (62 files, ~1350 lines) | DONE | rename-agent | 56 files changed, commit b57f7e0 |
| 1.2 | Deploy files + dashboard + docs rename | DONE | rename-agent | Included in 1.1 atomic commit |
| 1.3 | Build verification + all tests pass | DONE | rename-agent | 4 test suites pass |
| 1.4 | Commit, push to Gitea + GitHub | DONE | manual | Pushed to both remotes |
| 1.5 | LXC migration (paths, systemd, users, binaries) | DONE | lxc-agent | Services active, hostname Ephyr |
| 1.6 | Target host migration (CA key, sudoers, sshd) | DEFERRED | | Non-blocking, old paths still work |
| 1.7 | Update external refs (CLAUDE.md, memory, MCP config) | DEFERRED | | After macaroon implementation |

## Phase 2: Macaroon Engine v0.2b

| Milestone | Description | Status | Agent | Notes |
|-----------|-------------|--------|-------|-------|
| 2b.1 | `internal/macaroon/` types + HMAC chain (no ext deps) | DONE | macaroon-agent | 17 tests, pure stdlib |
| 2b.2 | Reducer (safety-critical) + fuzz tests | DONE | macaroon-agent | 22 tests + 2 fuzz (220k executions) |
| 2b.3 | RootKeyStore + Minter + Verifier + tests | DONE | verifier-agent | 23 tests + benchmark (~51μs/verify) |
| 2b.3b | TaskManager signature index | DONE | sig-agent | 5 new tests, race-safe |
| 2b.3c | Metrics preparation | DONE | metrics-agent | 5 counters + 2 histograms, 2 new tests |
| 2b.4 | Auth rewrite: mcp_token_auth.go (JWT→macaroon) | DONE | integration-agent | Dual-mode mac_+JWT+API key |
| 2b.4b | MCPAgent struct + envelope_check.go | DONE | integration-agent | TaskClaims populated from envelope |
| 2b.5 | Tool handlers: mcp_task.go (mint/delegate) | DONE | integration-agent | Mints macaroons, root key deletion on revoke |
| 2b.6 | `ephyr inspect` CLI command | DONE | cli-agent | Human + JSON output, 3 input modes |
| 2b.7 | Integration tests + performance benchmarks | DONE | bench-agent | 12 e2e tests + 10 benchmarks (~34μs mint, ~32μs verify) |

## Phase 3: Documentation Review

| Step | Description | Status | Agent | Notes |
|------|-------------|--------|-------|-------|
| 3.1 | STYLE-GUIDE compliance audit (all .md files) | | | Voice, naming, formatting |
| 3.2 | README.md rewrite (Ephyr product framing) | | | Match /home/claude/EPHYR/README.md |
| 3.3 | Architecture + security docs alignment | | | Tier model, invariants |
| 3.4 | CHANGELOG update for rename + v0.2b | | | Keep a Changelog format |
