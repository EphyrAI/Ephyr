# Contributing to Ephyr

Thanks for your interest in contributing to Ephyr! This document covers the basics.

## Development Setup

```bash
# Clone the repo
git clone https://github.com/ben-spanswick/Ephyr.git
cd ephyr

# Build all binaries
go build -o bin/ephyr-broker ./cmd/broker
go build -o bin/ephyr-signer ./cmd/signer
go build -o bin/ephyr ./cmd/ephyr

# Run tests
go test ./...
```

**Requirements:** Go 1.24+, Linux (SO_PEERCRED is Linux-only)

## Project Structure

```
cmd/           Entry points for the three binaries
internal/      Core packages (not importable externally)
  audit/       Structured JSON audit logging
  auth/        Session management, Unix peer credentials
  broker/      Broker server, dashboard, MCP, proxy, activity
  macaroon/    Macaroon minting, verification, reducer (Delegation)
  policy/      Policy engine, YAML config, evaluation pipeline
  signer/      Certificate signing, CA key management
configs/       Default policy.yaml
dashboard/     React 18 SPA (single HTML file, CDN dependencies)
deploy/        Systemd unit files
docs/          Documentation
```

## Guidelines

### Code Style

- Follow standard Go conventions (`gofmt`, `go vet`)
- Keep packages focused -- each file should do one thing well
- Error messages should be lowercase, no trailing punctuation
- Use `fmt.Errorf("context: %w", err)` for error wrapping

### Security

This project handles SSH certificate signing -- security is paramount.

- Never log credentials, keys, or tokens in plaintext
- Use `crypto/subtle.ConstantTimeCompare` for secret comparison
- Validate all inputs at API boundaries
- New features touching auth/crypto should include threat analysis in the PR description

### Commits

- Use conventional commit style: `feat:`, `fix:`, `docs:`, `refactor:`, `test:`
- Keep commits atomic -- one logical change per commit
- Write clear commit messages that explain *why*, not just *what*

### Pull Requests

1. Fork and create a feature branch
2. Write/update tests for your changes
3. Update documentation if adding features
4. Ensure `go test ./...` passes
5. Open a PR with a clear description

### Testing

- Unit tests live next to the code they test (`*_test.go`)
- Integration tests that need Unix sockets should use `t.TempDir()`
- Test both happy paths and error cases
- Mock the signer for broker tests (no real CA key needed)

## Architecture Decisions

Major architectural changes should be discussed in an issue first. The three-tier design (signer/broker/CLI) is intentional -- proposals that merge these components need strong justification.

Key invariants:
- The CA key **must** stay isolated in the signer process
- The broker **must not** have direct access to the CA private key
- All cert operations **must** be audit-logged
- Policy evaluation **must** be deterministic given the same inputs

## Reporting Security Issues

If you find a security vulnerability, please **do not** open a public issue. Instead, email the maintainers directly. We take security reports seriously and will respond promptly.

## License

By contributing, you agree that your contributions will be licensed under the Apache License 2.0.
