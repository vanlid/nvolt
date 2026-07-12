package vault

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const (
	// NvoltDir is the name of the vault directory
	NvoltDir = ".nvolt"

	// HomeNvoltDir is the nvolt directory in user's home
	HomeNvoltDir = ".nvolt"

	// SubDirs
	SecretsDir     = "secrets"
	WrappedKeysDir = "wrapped_keys"
	MachinesDir    = "machines"
	OrgsDir        = "orgs"

	// Files
	PrivateKeyFile  = "private_key.pem"
	MachineInfoFile = "machine-info.json"
	KeyInfoFile     = "keyinfo.json"
	ConfigFile      = "config.json"
)

// Paths holds all vault-related paths
type Paths struct {
	// Root is the root directory of the vault (.nvolt or ~/.nvolt/orgs/org/repo)
	Root string

	// Secrets directory
	Secrets string

	// Wrapped keys directory
	WrappedKeys string

	// Machines directory
	Machines string

	// KeyInfo file
	KeyInfo string

	// Config file
	Config string
}

// HomePaths holds paths in the home directory
type HomePaths struct {
	// Root is ~/.nvolt
	Root string

	// PrivateKey is the machine's private key
	PrivateKey string

	// MachineInfo is the machine metadata
	MachineInfo string

	// Machines directory for storing machine public keys
	Machines string

	// Orgs directory for organization repos
	Orgs string
}

// GetHomePaths returns the home directory paths
func GetHomePaths() (*HomePaths, error) {
	var root string

	// Check for NVOLT_CONFIG override
	if configDir := os.Getenv("NVOLT_CONFIG"); configDir != "" {
		// Expand tilde if present
		if strings.HasPrefix(configDir, "~/") {
			homeDir, err := os.UserHomeDir()
			if err != nil {
				return nil, fmt.Errorf("failed to get home directory: %w", err)
			}
			configDir = filepath.Join(homeDir, configDir[2:])
		}
		root = configDir
	} else {
		// Use default ~/.nvolt
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("failed to get home directory: %w", err)
		}
		root = filepath.Join(homeDir, HomeNvoltDir)
	}

	return &HomePaths{
		Root:        root,
		PrivateKey:  filepath.Join(root, PrivateKeyFile),
		MachineInfo: filepath.Join(root, MachinesDir, MachineInfoFile),
		Machines:    filepath.Join(root, MachinesDir),
		Orgs:        filepath.Join(root, OrgsDir),
	}, nil
}

// GetVaultPaths returns the vault directory paths using unified prefix logic
// For local mode: vaultRoot = ./.nvolt, projectName is ignored
//   - machine_prefix = ".nvolt"
//   - secret_prefix = ".nvolt"
//   - keys_prefix = ".nvolt"
//
// For global mode: vaultRoot = ~/.nvolt/orgs/org/repo, projectName is required
//   - machine_prefix = "" (machines at root)
//   - secret_prefix = projectName
//   - keys_prefix = projectName
//
// The code remains identical regardless of mode, only prefixes change.
func GetVaultPaths(vaultRoot, projectName string) *Paths {
	mode := GetVaultMode(vaultRoot)

	var machinePrefix, secretPrefix, keysPrefix string

	if mode == ModeLocal {
		// Local mode: everything under .nvolt/
		machinePrefix = NvoltDir
		secretPrefix = NvoltDir
		keysPrefix = NvoltDir
	} else {
		// Global mode: machines at root, secrets/keys under project
		machinePrefix = ""
		secretPrefix = projectName
		keysPrefix = projectName
	}

	return &Paths{
		Root:        vaultRoot,
		Machines:    filepath.Join(vaultRoot, machinePrefix, MachinesDir),
		Secrets:     filepath.Join(vaultRoot, secretPrefix, SecretsDir),
		WrappedKeys: filepath.Join(vaultRoot, keysPrefix, WrappedKeysDir),
		KeyInfo:     filepath.Join(vaultRoot, secretPrefix, KeyInfoFile),
		Config:      filepath.Join(vaultRoot, secretPrefix, ConfigFile),
	}
}

// GetLocalVaultPath returns the vault path in the current directory
func GetLocalVaultPath() (string, error) {
	cwd, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("failed to get current directory: %w", err)
	}
	return filepath.Join(cwd, NvoltDir), nil
}

// GetGlobalVaultPath returns the vault path for a global repo
// Returns the repo root path, not a .nvolt subdirectory
func GetGlobalVaultPath(org, repo string) (string, error) {
	homePaths, err := GetHomePaths()
	if err != nil {
		return "", err
	}

	repoRoot := filepath.Join(homePaths.Orgs, org, repo)
	return repoRoot, nil
}

// GetSecretsPath returns the path for an environment's secrets
func (p *Paths) GetSecretsPath(environment string) string {
	return filepath.Join(p.Secrets, environment)
}

// GetSecretFilePath returns the full path for a secret file
func (p *Paths) GetSecretFilePath(environment, key string) string {
	return filepath.Join(p.Secrets, environment, fmt.Sprintf("%s.enc.json", key))
}

// GetWrappedKeyPath returns the path for a machine's wrapped key in a specific environment
func (p *Paths) GetWrappedKeyPath(environment, machineID string) string {
	return filepath.Join(p.WrappedKeys, environment, fmt.Sprintf("%s.json", machineID))
}

// GetWrappedKeysEnvPath returns the wrapped keys directory for a specific environment
func (p *Paths) GetWrappedKeysEnvPath(environment string) string {
	return filepath.Join(p.WrappedKeys, environment)
}

// GetMachineInfoPath returns the path for a machine's info file
func (p *Paths) GetMachineInfoPath(machineID string) string {
	return filepath.Join(p.Machines, fmt.Sprintf("%s.json", machineID))
}

// IsVaultInitialized checks if a vault exists at the given path
func IsVaultInitialized(vaultPath string) bool {
	info, err := os.Stat(vaultPath)
	if os.IsNotExist(err) {
		return false
	}
	return info.IsDir()
}

// IsMachineInitialized checks if this machine has an established identity.
//
// machine-info.json is required in all cases. A software machine additionally
// requires its private_key.pem on disk. A PKCS#11-backed machine deliberately
// keeps NO software private key locally (the identity lives on the token), so
// it is recognized as initialized from machine-info's key_source instead —
// otherwise every runtime command (push/pull/run, via EnsureMachineInitialized)
// would wrongly treat a hardware-backed machine as uninitialized and try to
// generate a software keypair.
func IsMachineInitialized() (bool, error) {
	homePaths, err := GetHomePaths()
	if err != nil {
		return false, err
	}

	// Check if machine info exists (required for both software and pkcs11).
	if _, err := os.Stat(homePaths.MachineInfo); err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, fmt.Errorf("failed to check machine info: %w", err)
	}

	// A PKCS#11-backed identity has no local private key; treat it as
	// initialized based on its recorded key_source.
	mi, err := LoadMachineInfoFromFile(homePaths.MachineInfo)
	if err != nil {
		return false, fmt.Errorf("failed to load machine info: %w", err)
	}
	if mi.KeySource != nil && mi.KeySource.Source == "pkcs11" {
		return true, nil
	}

	// Software machine: require the private key on disk.
	if _, err := os.Stat(homePaths.PrivateKey); err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, fmt.Errorf("failed to check private key: %w", err)
	}

	return true, nil
}

// GetRepoRootFromVault extracts the repo root path from a vault path
// For local mode: returns the directory containing .nvolt
// For global mode: returns the repo root (e.g., ~/.nvolt/orgs/org/repo)
func GetRepoRootFromVault(vaultPath string) string {
	vaultPath = filepath.Clean(vaultPath)

	// If this is a local vault (.nvolt), return parent directory
	if filepath.Base(vaultPath) == NvoltDir {
		return filepath.Dir(vaultPath)
	}

	// For global mode, the vaultPath IS the repo root
	return vaultPath
}
