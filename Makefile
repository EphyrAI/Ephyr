.PHONY: build test lint cover clean install install-user install-systemd setup uninstall

BINDIR := bin
GOFLAGS := -trimpath

# Detect nologin path (varies by distro)
NOLOGIN := $(shell command -v nologin 2>/dev/null || echo /usr/bin/false)

# Configurable defaults (override with: make setup DASHBOARD_TOKEN=mysecret)
DASHBOARD_TOKEN ?= changeme
MCP_PORT ?= 8554
DASHBOARD_PORT ?= 8553

# ── Build ───────────────────────────────────────────────────────────

build:
	@mkdir -p $(BINDIR)
	go build $(GOFLAGS) -o $(BINDIR)/ephyr-broker ./cmd/broker
	go build $(GOFLAGS) -o $(BINDIR)/ephyr-signer ./cmd/signer
	go build $(GOFLAGS) -o $(BINDIR)/ephyr ./cmd/ephyr
	@echo "Built: $(BINDIR)/ephyr-broker  $(BINDIR)/ephyr-signer  $(BINDIR)/ephyr"

test:
	go test -race -coverprofile=coverage.out ./...

lint:
	golangci-lint run ./...

cover: test
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report: coverage.html"

clean:
	rm -rf $(BINDIR) coverage.out coverage.html

# ── Install ─────────────────────────────────────────────────────────

install: build
	install -m 0755 $(BINDIR)/ephyr-broker /usr/local/bin/
	install -m 0755 $(BINDIR)/ephyr-signer /usr/local/bin/
	install -m 0755 $(BINDIR)/ephyr /usr/local/bin/

install-user:
	@echo "Creating ephyr system user and directories..."
	@groupadd -f ephyr-agents 2>/dev/null || true
	@id -u ephyr-broker >/dev/null 2>&1 || useradd -r -s $(NOLOGIN) -g ephyr-agents -M ephyr-broker
	@mkdir -p /etc/ephyr /run/ephyr /var/log/ephyr /var/lib/ephyr
	@chown root:ephyr-agents /etc/ephyr
	@chmod 0750 /etc/ephyr
	@chown ephyr-broker:ephyr-agents /run/ephyr /var/log/ephyr /var/lib/ephyr
	@chmod 0750 /run/ephyr /var/log/ephyr /var/lib/ephyr
	@echo "Created user ephyr-broker (shell: $(NOLOGIN))"

install-systemd:
	@deploy/install-services.sh "$(DASHBOARD_TOKEN)" "$(MCP_PORT)" "$(DASHBOARD_PORT)"

# ── Setup (one-command install) ─────────────────────────────────────
# Usage: sudo make setup
#        sudo make setup DASHBOARD_TOKEN=mysecret MCP_PORT=9000

setup: build install install-user
	@echo ""
	@echo "=== Ephyr Setup ==="
	@# Generate CA key if missing
	@if [ ! -f /etc/ephyr/ca_key ]; then \
		echo "Generating CA key..."; \
		ssh-keygen -t ed25519 -f /etc/ephyr/ca_key -N "" -C "ephyr-ca" -q; \
		chown ephyr-broker:ephyr-agents /etc/ephyr/ca_key; \
		chmod 0600 /etc/ephyr/ca_key; \
		echo "  CA key: /etc/ephyr/ca_key"; \
	else \
		echo "  CA key exists (skipping)"; \
	fi
	@# Write minimal policy if missing
	@if [ ! -f /etc/ephyr/policy.yaml ]; then \
		echo "Writing example policy..."; \
		cp examples/policy.yaml /etc/ephyr/policy.yaml; \
		chown ephyr-broker:ephyr-agents /etc/ephyr/policy.yaml; \
		chmod 0640 /etc/ephyr/policy.yaml; \
		echo "  Policy: /etc/ephyr/policy.yaml"; \
	else \
		echo "  Policy exists (skipping)"; \
	fi
	@# Install systemd units and start
	@$(MAKE) -s install-systemd DASHBOARD_TOKEN=$(DASHBOARD_TOKEN) MCP_PORT=$(MCP_PORT) DASHBOARD_PORT=$(DASHBOARD_PORT)
	@systemctl enable ephyr-signer ephyr-broker --quiet 2>/dev/null || true
	@systemctl start ephyr-signer
	@sleep 1
	@systemctl start ephyr-broker
	@sleep 1
	@echo ""
	@echo "=== Ephyr is running ==="
	@echo ""
	@echo "  Dashboard:  http://localhost:$(DASHBOARD_PORT)  (token: $(DASHBOARD_TOKEN))"
	@echo "  MCP:        http://localhost:$(MCP_PORT)/mcp"
	@echo "  Demo key:   ephyr-demo-key  (from examples/policy.yaml)"
	@echo ""
	@echo "  Status:     systemctl status ephyr-signer ephyr-broker"
	@echo "  Logs:       journalctl -u ephyr-broker -f"
	@echo "  Reload:     systemctl reload ephyr-broker"
	@echo ""
	@echo "  Next: edit /etc/ephyr/policy.yaml to add your targets."
	@echo ""

# ── Uninstall ───────────────────────────────────────────────────────

uninstall:
	@systemctl stop ephyr-broker ephyr-signer 2>/dev/null || true
	@systemctl disable ephyr-broker ephyr-signer 2>/dev/null || true
	@rm -f /etc/systemd/system/ephyr-broker.service /etc/systemd/system/ephyr-signer.service
	@rm -f /etc/tmpfiles.d/ephyr.conf
	@rm -f /usr/local/bin/ephyr-broker /usr/local/bin/ephyr-signer /usr/local/bin/ephyr
	@systemctl daemon-reload
	@echo "Ephyr uninstalled. Config preserved in /etc/ephyr/."
