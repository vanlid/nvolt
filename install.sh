#!/bin/sh
set -e

# nvolt-pkcs11 installer — downloads the PKCS#11 build from GitHub Releases.
# Usage: curl -fsSL https://raw.githubusercontent.com/vanlid/nvolt-pkcs11/dist/install.sh | sh
#   NVOLT_TAG=dev  ->  install the rolling development build instead of the
#                      latest stable (-p11) release.

REPO="vanlid/nvolt-pkcs11"
NVOLT_TAG="${NVOLT_TAG:-latest}"
if [ "$NVOLT_TAG" = "latest" ]; then
    # GitHub's /releases/latest/ resolves to the newest NON-prerelease release
    # (the -p11 stable builds; the rolling `dev` build is a prerelease).
    BASE_URL="https://github.com/${REPO}/releases/latest/download"
else
    BASE_URL="https://github.com/${REPO}/releases/download/${NVOLT_TAG}"
fi
INSTALL_DIR="/usr/local/bin"
BINARY_NAME="nvolt"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

info() {
    printf "${GREEN}[INFO]${NC} %s\n" "$1" >&2
}

warn() {
    printf "${YELLOW}[WARN]${NC} %s\n" "$1" >&2
}

error() {
    printf "${RED}[ERROR]${NC} %s\n" "$1" >&2
    exit 1
}

# Detect OS
detect_os() {
    OS="$(uname -s)"
    case "$OS" in
        Linux*)     OS="linux" ;;
        Darwin*)    OS="darwin" ;;
        MINGW*|MSYS*|CYGWIN*) OS="windows" ;;
        *)          error "Unsupported operating system: $OS" ;;
    esac
    echo "$OS"
}

# Detect architecture
detect_arch() {
    ARCH="$(uname -m)"
    case "$ARCH" in
        x86_64|amd64)   ARCH="amd64" ;;
        aarch64|arm64)  ARCH="arm64" ;;
        *)              error "Unsupported architecture: $ARCH" ;;
    esac
    echo "$ARCH"
}

# Download binary
download_binary() {
    local os="$1"
    local arch="$2"
    local binary_file="nvolt-${os}-${arch}"

    if [ "$os" = "windows" ]; then
        binary_file="${binary_file}.exe"
    fi

    local url="${BASE_URL}/${binary_file}"
    local tmp_file="/tmp/${binary_file}"

    info "Downloading nvolt from ${url}..."

    if command -v curl > /dev/null 2>&1; then
        curl -fsSL "$url" -o "$tmp_file" || error "Failed to download binary"
    elif command -v wget > /dev/null 2>&1; then
        wget -q "$url" -O "$tmp_file" || error "Failed to download binary"
    else
        error "Neither curl nor wget found. Please install one of them and try again."
    fi

    echo "$tmp_file"
}

# Verify checksum (optional, if SHA256SUMS is available)
verify_checksum() {
    local binary_file="$1"
    local os="$2"
    local arch="$3"

    local expected_file="nvolt-${os}-${arch}"
    if [ "$os" = "windows" ]; then
        expected_file="${expected_file}.exe"
    fi

    # Download checksums file
    local checksums_url="${BASE_URL}/SHA256SUMS"
    local checksums_file="/tmp/SHA256SUMS"

    if command -v curl > /dev/null 2>&1; then
        curl -fsSL "$checksums_url" -o "$checksums_file" 2>/dev/null || {
            warn "Could not download checksums file, skipping verification"
            return 0
        }
    else
        warn "Could not download checksums file, skipping verification"
        return 0
    fi

    # Verify checksum
    if command -v sha256sum > /dev/null 2>&1; then
        info "Verifying checksum..."
        cd /tmp
        grep "$expected_file" "$checksums_file" | sha256sum -c - || error "Checksum verification failed"
        cd - > /dev/null
    elif command -v shasum > /dev/null 2>&1; then
        info "Verifying checksum..."
        cd /tmp
        grep "$expected_file" "$checksums_file" | shasum -a 256 -c - || error "Checksum verification failed"
        cd - > /dev/null
    else
        warn "sha256sum/shasum not found, skipping checksum verification"
    fi
}

# Install binary
install_binary() {
    local tmp_file="$1"
    local install_path="${INSTALL_DIR}/${BINARY_NAME}"

    # Check if we need sudo
    if [ ! -w "$INSTALL_DIR" ]; then
        if command -v sudo > /dev/null 2>&1; then
            info "Installing to ${install_path} (requires sudo)..."
            sudo mv "$tmp_file" "$install_path" || error "Failed to install binary"
            sudo chmod +x "$install_path" || error "Failed to make binary executable"
        else
            error "Cannot write to ${INSTALL_DIR} and sudo is not available"
        fi
    else
        info "Installing to ${install_path}..."
        mv "$tmp_file" "$install_path" || error "Failed to install binary"
        chmod +x "$install_path" || error "Failed to make binary executable"
    fi
}

# Main installation
main() {
    info "Installing nvolt..."

    # Detect system
    OS=$(detect_os)
    ARCH=$(detect_arch)

    info "Detected OS: ${OS}, Architecture: ${ARCH}"

    # Download binary
    TMP_FILE=$(download_binary "$OS" "$ARCH")

    # Verify checksum
    verify_checksum "$TMP_FILE" "$OS" "$ARCH"

    # Install
    install_binary "$TMP_FILE"

    # Verify installation
    if command -v nvolt > /dev/null 2>&1; then
        info "nvolt installed successfully!"
        info "Version: $(nvolt --version 2>&1 || echo 'unknown')"
        info ""
        info "Get started by running: nvolt --help"
    else
        warn "nvolt installed but not found in PATH. You may need to add ${INSTALL_DIR} to your PATH"
    fi
}

main