.PHONY: build clean install test fmt vet lint

GOBIN ?= /usr/local/bin
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -ldflags "-X main.version=$(VERSION)"

build:
	@mkdir -p bin
	go build $(LDFLAGS) -o bin/clauth-broker ./cmd/broker
	go build $(LDFLAGS) -o bin/clauth-signer ./cmd/signer
	go build $(LDFLAGS) -o bin/clauth ./cmd/clauth
	@echo "Build complete: bin/clauth-broker bin/clauth-signer bin/clauth"

clean:
	rm -rf bin/

install: build
	install -m 755 bin/clauth-broker $(GOBIN)/
	install -m 755 bin/clauth-signer $(GOBIN)/
	install -m 755 bin/clauth $(GOBIN)/
	@echo "Installed to $(GOBIN)/"

test:
	go test -v -race ./...

fmt:
	gofmt -s -w .

vet:
	go vet ./...

lint: vet
	@which golangci-lint >/dev/null 2>&1 && golangci-lint run ./... || echo "golangci-lint not installed, skipping"

# Install systemd units (run as root).
install-systemd:
	install -m 644 deploy/systemd/clauth-broker.service /etc/systemd/system/
	install -m 644 deploy/systemd/clauth-signer.service /etc/systemd/system/
	systemctl daemon-reload
	@echo "Systemd units installed. Enable with: systemctl enable --now clauth-signer clauth-broker"

# Create the clauth-broker system user (run as root).
install-user:
	@id clauth-broker >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin clauth-broker
	mkdir -p /etc/clauth /var/log/clauth /var/lib/clauth
	chown clauth-broker:clauth-broker /var/log/clauth /var/lib/clauth
	@echo "System user and directories created."
