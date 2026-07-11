.PHONY: build test lint fmt clean install module build-embedded

# Build the binary
build:
	go build -o bin/nvolt ./cmd/nvolt

# Compile the self-contained wolfPKCS11 module to the //go:embed path.
# Set TPM_INTERFACE=swtpm to build without TPM hardware (CI/testing).
module:
	build/pkcs11/build-module.sh

# Build nvolt with the wolfPKCS11 module embedded (requires `make module` first).
build-embedded:
	go build -tags wolfpkcs11_embed -o bin/nvolt ./cmd/nvolt

# Run tests
test:
	go test -v -race -coverprofile=coverage.out ./...

# Run linter
lint:
	golangci-lint run ./...

# Format code
fmt:
	gofmt -s -w .
	goimports -w .

# Clean build artifacts
clean:
	rm -rf bin/
	rm -f coverage.out
	rm -rf ~/.nvolt
	rm -rf ~/.nvolt-ilya

# Install dependencies
deps:
	go mod download
	go mod tidy

# Install the binary locally
install:
	go install ./cmd/nvolt

# Run all checks (format, lint, test)
check: fmt lint test

# Development build with race detector
dev:
	go build -race -o bin/nvolt-dev ./cmd/nvolt
