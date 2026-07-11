# nvolt

<div align="center">

```
   ███╗   ██╗██╗   ██╗ ██████╗ ██╗  ████████╗
   ████╗  ██║██║   ██║██╔═══██╗██║  ╚══██╔══╝
██╔██╗ ██║██║   ██║██║   ██║██║     ██║
██║╚██╗██║╚██╗ ██╔╝██║   ██║██║     ██║
██║ ╚████║ ╚████╔╝ ╚██████╔╝███████╗██║
╚═╝  ╚═══╝  ╚═══╝   ╚═════╝ ╚══════╝╚═╝
```

**GitHub-native, Zero-Trust CLI for managing encrypted environment variables**

[![Go Version](https://img.shields.io/github/go-mod/go-version/iluxav/nvolt)](https://golang.org/doc/devel/release.html)
[![Release](https://img.shields.io/github/v/release/iluxav/nvolt)](https://github.com/iluxav/nvolt/releases)
[![License](https://img.shields.io/github/license/iluxav/nvolt)](LICENSE)
[![Go Report Card](https://goreportcard.com/badge/github.com/iluxav/nvolt)](https://goreportcard.com/report/github.com/iluxav/nvolt)

[Website](https://nvolt.io) • [Documentation](https://nvolt.io/docs.html) • [Quick Start](#quick-start)

</div>

**`nvolt`** is a cryptographically enforced secret manager built entirely around Git and local files. No server, no login, no organization model - just Git, encryption, and per-machine keypairs.

## Features

- **Zero-Trust Architecture**: All encryption/decryption happens locally
- **No Backend**: All data lives in Git repositories
- **No Authentication**: Uses Git for access control
- **Cryptographically Enforced**: Access control through wrapped keys
- **Git-Native**: `.nvolt/` directories act as encrypted, committed `.env` replacements
- **Hardware-Key Support**: Back a machine identity with a YubiKey or other PKCS#11 token - the private key never leaves the device
- **$0/month**: Free forever, no usage limits

## Why nvolt?

| Feature                | nvolt    | HashiCorp Vault     | Doppler | git-crypt   | SOPS        |
| ---------------------- | -------- | ------------------- | ------- | ----------- | ----------- |
| **Monthly Cost**       | **free** | $$$                 | $$      | free        | free        |
| **Zero-Knowledge**     | ✅       | ⚠️ Self-hosted only | ❌      | ✅          | ✅          |
| **No Backend**         | ✅       | ❌                  | ❌      | ✅          | ✅          |
| **No Login/Auth**      | ✅       | ❌                  | ❌      | ✅          | ✅          |
| **Per-Machine Access** | ✅       | ✅                  | ✅      | ⚠️ GPG only | ⚠️ GPG only |
| **Environment-Based**  | ✅       | ✅                  | ✅      | ❌          | ❌          |
| **Multi-Project**      | ✅       | ✅                  | ✅      | ⚠️ Limited  | ⚠️ Limited  |

## Installation

### Quick Install (Recommended)

```bash
# macOS and Linux (also works in Git Bash on Windows)
curl -fsSL https://install.nvolt.io/latest/install.sh | bash
```

### Using Go

```bash
go install github.com/iluxav/nvolt/cmd/nvolt@latest
```

### From Source

```bash
git clone https://github.com/iluxav/nvolt.git
cd nvolt
make build
```

## Quick Start

### Local Mode (Current Directory)

```bash
# Initialize vault in current directory
$ nvolt init
✓ Machine keypair generated
✓ Vault initialized at .nvolt/

# Push secrets from .env file
$ nvolt push -f .env
✓ Encrypted 12 secrets
✓ Secrets pushed to vault

# Pull and view secrets
$ nvolt pull
API_KEY=abc123
DB_PASSWORD=secret

# Run a command with secrets loaded
$ nvolt run npm start
✓ Loaded 12 secrets
🚀 Server running on port 3000
```

### Global Mode (Dedicated GitHub Repo)

```bash
# Initialize with a GitHub repository
nvolt init --repo org/secrets-repo

# Push secrets to production environment
nvolt push -f .env.production -e production

# Pull secrets from production
nvolt pull -e production
```

## Use Cases

- 🚀 **Startups & Solo Developers**: No monthly costs, enterprise-grade security without the enterprise price tag
- 👥 **Small Teams**: Securely share secrets across laptops and CI/CD using tools you already know
- 🔒 **Security-Conscious Organizations**: Zero-Trust architecture with no single point of failure
- 🤖 **CI/CD Pipelines**: Grant servers access to specific environments, secrets loaded at runtime

## Commands

### `nvolt init`

Initialize a new vault and generate machine keypair.

```bash
# Local mode (current directory)
nvolt init

# Global mode (dedicated GitHub repo)
nvolt init --repo org/secrets-repo
```

**Flags:**

- `--repo` - GitHub repository URL for global vault
- `--pkcs11` - Back this machine's identity with a PKCS#11 hardware token instead of a software keypair (see [Using a hardware key](#using-a-hardware-key-pkcs11))

---

### `nvolt join`

Join an existing vault and register this machine.

```bash
# Local mode (vault in current directory)
nvolt join

# Global mode (vault in GitHub repo)
nvolt join org/secrets-repo
# or
nvolt join --repo org/secrets-repo
```

**Flags:**

- `--repo` - GitHub repository URL for global vault
- `--pkcs11` - Back this machine's identity with a PKCS#11 hardware token instead of a software keypair (see [Using a hardware key](#using-a-hardware-key-pkcs11))

**Note:** After joining, you'll need someone with push access to grant your machine access to specific environments using `nvolt machine grant <your-machine-id>`.

---

### `nvolt push`

Encrypt and push secrets to the vault.

```bash
# From .env file
nvolt push -f .env.production -e production

# Set individual secrets with -k flag
nvolt push -k API_KEY=abc123 -k DB_PASSWORD=secret

# Multiple secrets with custom project name
nvolt push -k API_KEY=abc123 -k DB_SECRET=xyz789 -p my-backend -e staging
```

**Flags:**

- `-f, --file` - Path to .env file
- `-k, --key` - Key=value pairs (can be specified multiple times)
- `-e, --env` - Environment name (default: "default")
- `-p, --project` - Project name (auto-detected if not specified)

---

### `nvolt pull`

Decrypt and retrieve secrets from the vault.

```bash
# View secrets for default environment
nvolt pull

# View secrets for specific environment
nvolt pull -e production

# Write to .env file
nvolt pull -e production > .env.local
```

**Flags:**

- `-e, --env` - Environment name (default: "default")
- `-p, --project` - Project name (auto-detected if not specified)

---

### `nvolt run`

Run a command with decrypted secrets loaded as environment variables.

```bash
# Run development server
nvolt run npm start

# Run with specific environment
nvolt run -e production npm start

# Run arbitrary commands
nvolt run python app.py
```

**Flags:**

- `-e, --env` - Environment name (default: "default")
- `-c, --command` - Command to run

---

### `nvolt machine add`

Generate a new keypair for CI or another device.

```bash
nvolt machine add ci-server
nvolt machine add alice-laptop
```

---

### `nvolt machine grant`

Grant a machine access to decrypt secrets in an environment.

```bash
# Grant access to default environment
nvolt machine grant ci-server

# Grant access to specific environment
nvolt machine grant ci-server -e production

# Grant access with project and environment
nvolt machine grant alice-laptop -p myproject -e staging
```

**Flags:**

- `-e, --env` - Environment name (default: "default")
- `-p, --project` - Project name (auto-detected if not specified)

---

### `nvolt machine rm`

Revoke machine access and re-wrap master keys.

```bash
nvolt machine rm old-laptop
```

---

### `nvolt vault show`

Display vault information and machine access.

```bash
nvolt vault show
```

---

### `nvolt vault verify`

Verify integrity of encrypted files and keys.

```bash
nvolt vault verify
```

---

### `nvolt sync`

Re-wrap or rotate master keys.

```bash
# Re-wrap keys for all machines
nvolt sync

# Rotate master key
nvolt sync --rotate
```

**Flags:**

- `--rotate` - Rotate the master encryption key

---

### `nvolt pkcs11`

Discover and use RSA keys stored on a PKCS#11 hardware token (YubiKey, SoftHSM, etc.).

```bash
# List RSA keys visible on the token
nvolt pkcs11 list

# Enroll an on-card key as a *new* machine's identity (fresh init/join):
# with no flags, this walks you through picking a token and key;
# or name the key directly with --pkcs11-uri:
nvolt init --pkcs11 --pkcs11-uri 'pkcs11:token=my-yubikey;id=%01;type=private'

# Already have a machine? Swap its existing identity onto the same
# key's hardware/software backing with `nvolt rebind` instead:
nvolt rebind --pkcs11 --pkcs11-uri 'pkcs11:token=my-yubikey;id=%01;type=private'

# Generate a new RSA keypair on the token
nvolt pkcs11 generate --token my-yubikey --label my-key --id 01 --bits 2048
```

**Flags:**

- `--pkcs11-module` - Path to the PKCS#11 module (`.so` on Linux/macOS, `.dll` on Windows). Optional: nvolt autodetects common OpenSC/YubiKey locations, so you only need this (or `NVOLT_PKCS11_MODULE`) to override
- `--pkcs11-uri` - PKCS#11 URI of the RSA key to enroll (required for `init/join --pkcs11` and `rebind --pkcs11` when not picked interactively)
- `--pkcs11-pin-mode` - How to obtain the PIN: `prompt`, `env`, or `none` (default: `prompt`)

## Using a hardware key (PKCS#11)

nvolt can keep this machine's private key on a hardware token (like a YubiKey) instead of in a file. The key is created on the device and never leaves it — nvolt only sees the public key, and the token itself does the decryption.

A typical setup looks like this:

```bash
nvolt pkcs11 list      # show the tokens and keys nvolt can find
nvolt init --pkcs11    # pick one and make it this machine's identity
nvolt push             # push/pull/run then work as usual — the token unwraps your secrets
```

**Finding the module.** nvolt talks to the token through a PKCS#11 module — a `.so` file on Linux/macOS or a `.dll` on Windows, installed by OpenSC or your YubiKey software. nvolt checks the common install locations automatically, so you usually don't pass anything. If it can't find yours, point it at the file:

- Linux/macOS: `--pkcs11-module /path/to/opensc-pkcs11.so`
- Windows: `--pkcs11-module "C:\Program Files\OpenSC Project\OpenSC\pkcs11\opensc-pkcs11.dll"`

Or set `NVOLT_PKCS11_MODULE` once in your shell profile so you never type it again.

**Nothing shows up?** You need OpenSC (or your YubiKey vendor's tools) installed so a module exists on the machine:

- Linux (Debian/Ubuntu): `sudo apt install opensc pcscd` — `pcscd` is the service that lets the system see the card
- macOS: `brew install opensc`
- Windows: install OpenSC from its [releases page](https://github.com/OpenSC/OpenSC/releases), or run `winget install OpenSC.OpenSC`

Then plug in the token and run `nvolt pkcs11 list` again. (`pkcs11-tool --list-slots`, which comes with OpenSC, is a quick way to confirm the card is detected at all.)

**Entering your PIN.** By default nvolt asks for the token PIN and hides it as you type. For automation, use `--pkcs11-pin-mode env` to read it from `NVOLT_PKCS11_PIN`, or `--pkcs11-pin-mode none` for tokens that don't require a PIN.

## Security

nvolt uses industry-standard cryptography to protect your secrets:

- **Encryption**: AES-256-GCM for secret encryption
- **Key Wrapping**: RSA-4096 for wrapping master keys
- **Local-Only**: All cryptographic operations happen on your machine
- **Audit Trail**: Every change is tracked in Git history
- **Zero-Knowledge**: nvolt never sees your plaintext secrets

### Reporting Vulnerabilities

If you discover a security vulnerability, please email [security@nvolt.io](mailto:security@nvolt.io). We take security seriously and will respond promptly.

## Development

```bash
# Install dependencies
make deps

# Format code
make fmt

# Run linter
make lint

# Run tests
make test

# Build binary
make build

# Run all checks
make check
```

## Project Structure

```
nvolt/
├── cmd/nvolt/          # Main entry point
├── internal/
│   ├── cli/            # CLI commands
│   ├── crypto/         # Cryptographic operations
│   ├── vault/          # Vault management
│   ├── git/            # Git operations
│   └── config/         # Configuration management
└── pkg/
    └── types/          # Shared types
```

## Documentation

- 📖 [Full Documentation](https://nvolt.io/docs.html) - Complete guide with examples
- 📋 [TASKS.md](TASKS.md) - Development progress tracking

## Contributing

Contributions are welcome! Here's how you can help:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Run `make check` to ensure tests pass
5. Commit your changes (`git commit -m 'Add amazing feature'`)
6. Push to the branch (`git push origin feature/amazing-feature`)
7. Open a Pull Request

Please ensure your code follows the existing style and includes tests for new functionality.

## Links

- 🌐 [Website](https://nvolt.io)
- 📖 [Documentation](https://nvolt.io/docs.html)
- 💬 [Discussions](https://github.com/iluxav/nvolt/discussions)
- 🐛 [Issue Tracker](https://github.com/iluxav/nvolt/issues)
- 📦 [Releases](https://github.com/iluxav/nvolt/releases)

## Status

nvolt is in **active development**. Current stable version: [v1.0.21](https://github.com/iluxav/nvolt/releases)

## License

MIT - see [LICENSE](LICENSE) file for details.

---

<div align="center">

**Built with ❤️ for developers who value security and simplicity**

Star ⭐ this repo if you find nvolt useful!

</div>
