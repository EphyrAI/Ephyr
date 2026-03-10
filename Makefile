.PHONY: build test clean install install-user install-systemd

BINDIR := bin
GOFLAGS := -trimpath

build:
	@mkdir -p $(BINDIR)
	go build $(GOFLAGS) -o $(BINDIR)/clauth-broker ./cmd/broker
	go build $(GOFLAGS) -o $(BINDIR)/clauth-signer ./cmd/signer
	go build $(GOFLAGS) -o $(BINDIR)/clauth ./cmd/clauth
	@echo "Built: $(BINDIR)/clauth-broker  $(BINDIR)/clauth-signer  $(BINDIR)/clauth"

test:
	go test ./...

clean:
	rm -rf $(BINDIR)

install: build
	install -m 0755 $(BINDIR)/clauth-broker /usr/local/bin/
	install -m 0755 $(BINDIR)/clauth-signer /usr/local/bin/
	install -m 0755 $(BINDIR)/clauth /usr/local/bin/

install-user:
	@echo "Creating clauth-broker system user and directories..."
	groupadd -f clauth-agents
	id -u clauth-broker &>/dev/null || useradd -r -s /usr/sbin/nologin -g clauth-agents clauth-broker
	mkdir -p /etc/clauth /run/clauth /var/log/clauth /var/lib/clauth
	chown clauth-broker:clauth-agents /run/clauth /var/log/clauth /var/lib/clauth
	chmod 0750 /run/clauth /var/log/clauth /var/lib/clauth
	chmod 0700 /etc/clauth
	@echo "Done. Add agent users to the 'clauth-agents' group."

install-systemd:
	install -m 0644 deploy/systemd/clauth-signer.service /etc/systemd/system/
	install -m 0644 deploy/systemd/clauth-broker.service /etc/systemd/system/
	systemctl daemon-reload
	@echo "Units installed. Enable with: systemctl enable --now clauth-signer clauth-broker"

uninstall:
	systemctl stop clauth-broker clauth-signer 2>/dev/null || true
	systemctl disable clauth-broker clauth-signer 2>/dev/null || true
	rm -f /etc/systemd/system/clauth-broker.service /etc/systemd/system/clauth-signer.service
	rm -f /usr/local/bin/clauth-broker /usr/local/bin/clauth-signer /usr/local/bin/clauth
	systemctl daemon-reload
