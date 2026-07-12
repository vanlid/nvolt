.PHONY: build test lint fmt clean install module build-embedded build-pkcs11 build-tpm

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

# Build nvolt with dynamic PKCS#11 support (-tags pkcs11): purego dlopen/
# LoadLibrary, cgo-free. Reaches external tokens (OpenSC/YubiKey) on Linux,
# Windows and macOS. Add wolfpkcs11_embed (after `make module`) to also bundle
# the bundled TPM module: go build -tags "pkcs11 wolfpkcs11_embed" ...
build-pkcs11:
	go build -tags pkcs11 -o bin/nvolt ./cmd/nvolt

# Build the fully-static nvolt-tpm binary (cgo, musl libc, TPM only, Linux
# only). Requires prebuilt wolfPKCS11 static archives first:
#   STATIC_ARCHIVES=internal/pkcs11/dist/static TPM_INTERFACE=devtpm build/pkcs11/build-module.sh /dev/null
# then a musl C compiler as CC (e.g. CC=musl-gcc make build-tpm).
build-tpm:
	CGO_ENABLED=1 go build -tags "wolfpkcs11_static netgo osusergo" \
		-ldflags '-linkmode external -extldflags "-static"' \
		-o bin/nvolt-tpm ./cmd/nvolt

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
