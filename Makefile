.PHONY: build test lint cover clean install install-user install-systemd uninstall

BINDIR := bin
GOFLAGS := -trimpath

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

cover:
	go test -race -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report: coverage.html"

clean:
	rm -rf $(BINDIR) coverage.out coverage.html

install: build
	install -m 0755 $(BINDIR)/ephyr-broker /usr/local/bin/
	install -m 0755 $(BINDIR)/ephyr-signer /usr/local/bin/
	install -m 0755 $(BINDIR)/ephyr /usr/local/bin/

install-user:
	@echo "Creating ephyr-broker system user and directories..."
	groupadd -f ephyr-agents
	id -u ephyr-broker &>/dev/null || useradd -r -s /usr/sbin/nologin -g ephyr-agents ephyr-broker
	mkdir -p /etc/ephyr /run/ephyr /var/log/ephyr /var/lib/ephyr
	chown ephyr-broker:ephyr-agents /run/ephyr /var/log/ephyr /var/lib/ephyr
	chmod 0750 /run/ephyr /var/log/ephyr /var/lib/ephyr
	chmod 0700 /etc/ephyr
	@echo "Done. Add agent users to the 'ephyr-agents' group."

install-systemd:
	install -m 0644 deploy/systemd/ephyr-signer.service /etc/systemd/system/
	install -m 0644 deploy/systemd/ephyr-broker.service /etc/systemd/system/
	systemctl daemon-reload
	@echo "Units installed. Enable with: systemctl enable --now ephyr-signer ephyr-broker"

uninstall:
	systemctl stop ephyr-broker ephyr-signer 2>/dev/null || true
	systemctl disable ephyr-broker ephyr-signer 2>/dev/null || true
	rm -f /etc/systemd/system/ephyr-broker.service /etc/systemd/system/ephyr-signer.service
	rm -f /usr/local/bin/ephyr-broker /usr/local/bin/ephyr-signer /usr/local/bin/ephyr
	systemctl daemon-reload
