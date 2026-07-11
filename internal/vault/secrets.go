package vault

import (
	"bufio"
	stdcrypto "crypto"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/iluxav/nvolt/internal/crypto"
	"github.com/iluxav/nvolt/pkg/types"
)

// ParseEnvFile parses a .env file into a map of key-value pairs
func ParseEnvFile(path string) (map[string]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	envVars := make(map[string]string)
	scanner := bufio.NewScanner(file)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Parse KEY=VALUE
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid format at line %d: %s", lineNum, line)
		}

		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		// Remove quotes if present
		value = strings.Trim(value, "\"'")

		if key == "" {
			return nil, fmt.Errorf("empty key at line %d", lineNum)
		}

		envVars[key] = value
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading file: %w", err)
	}

	return envVars, nil
}

// ParseKeyValuePairs parses command-line KEY=VALUE pairs
func ParseKeyValuePairs(pairs []string) (map[string]string, error) {
	envVars := make(map[string]string)

	for _, pair := range pairs {
		parts := strings.SplitN(pair, "=", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid key=value format: %s", pair)
		}

		key := strings.TrimSpace(parts[0])
		value := parts[1] // Don't trim value to preserve spaces

		if key == "" {
			return nil, fmt.Errorf("empty key in: %s", pair)
		}

		envVars[key] = value
	}

	return envVars, nil
}

// EncryptSecret encrypts a secret value using the master key
func EncryptSecret(masterKey []byte, value string) (*types.EncryptedSecret, error) {
	plaintext := []byte(value)

	ciphertext, nonce, err := crypto.EncryptAESGCM(masterKey, plaintext)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt: %w", err)
	}

	return &types.EncryptedSecret{
		Version: 2,
		Data:    base64.StdEncoding.EncodeToString(ciphertext),
		Nonce:   base64.StdEncoding.EncodeToString(nonce),
		Tag:     "", // Tag is included in ciphertext with GCM
	}, nil
}

// DecryptSecret decrypts a secret value using the master key
func DecryptSecret(masterKey []byte, encrypted *types.EncryptedSecret) (string, error) {
	if encrypted.Version != 2 {
		return "", fmt.Errorf("unsupported secret version: %d", encrypted.Version)
	}

	ciphertext, err := base64.StdEncoding.DecodeString(encrypted.Data)
	if err != nil {
		return "", fmt.Errorf("failed to decode ciphertext: %w", err)
	}

	nonce, err := base64.StdEncoding.DecodeString(encrypted.Nonce)
	if err != nil {
		return "", fmt.Errorf("failed to decode nonce: %w", err)
	}

	plaintext, err := crypto.DecryptAESGCM(masterKey, ciphertext, nonce)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt: %w", err)
	}

	return string(plaintext), nil
}

// SaveEncryptedSecret saves an encrypted secret to a file
func SaveEncryptedSecret(paths *Paths, environment, key string, encrypted *types.EncryptedSecret) error {
	// Ensure secrets directory exists
	if err := EnsureSecretsDir(paths, environment); err != nil {
		return err
	}

	secretPath := paths.GetSecretFilePath(environment, key)

	data, err := json.MarshalIndent(encrypted, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal secret: %w", err)
	}

	if err := WriteFileAtomic(secretPath, data, FilePerm); err != nil {
		return fmt.Errorf("failed to write secret: %w", err)
	}

	return nil
}

// LoadEncryptedSecret loads an encrypted secret from a file
func LoadEncryptedSecret(paths *Paths, environment, key string) (*types.EncryptedSecret, error) {
	secretPath := paths.GetSecretFilePath(environment, key)

	data, err := ReadFile(secretPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read secret: %w", err)
	}

	var encrypted types.EncryptedSecret
	if err := json.Unmarshal(data, &encrypted); err != nil {
		return nil, fmt.Errorf("failed to parse secret: %w", err)
	}

	return &encrypted, nil
}

// WrapMasterKeyForMachines wraps the master key for machines with permission prompts
// Uses unified paths - works identically in both local and global modes
// If autoGrant is true, automatically grants access to all machines without prompting
func WrapMasterKeyForMachines(paths *Paths, environment string, masterKey []byte, grantedBy string, autoGrant bool) error {
	// Get all machines
	machines, err := ListMachines(paths)
	if err != nil {
		return fmt.Errorf("failed to list machines: %w", err)
	}

	if len(machines) == 0 {
		return fmt.Errorf("no machines found in vault")
	}

	// Ensure wrapped keys environment directory exists
	envDir := paths.GetWrappedKeysEnvPath(environment)
	if err := ensureDir(envDir, DirPerm); err != nil {
		return fmt.Errorf("failed to create wrapped keys directory: %w", err)
	}

	// Wrap key for each machine
	for _, machine := range machines {
		wrappedKeyPath := paths.GetWrappedKeyPath(environment, machine.ID)

		// Check if wrapped key already exists
		keyExists := FileExists(wrappedKeyPath)

		// If key doesn't exist and not auto-granting, prompt for permission
		// Skip prompt for the current machine (self)
		if !keyExists && !autoGrant && machine.ID != grantedBy {
			// Prompt for permission
			fmt.Printf("\nMachine '%s' (%s) does not have access to '%s' environment.\n",
				machine.ID, machine.Hostname, environment)
			fmt.Printf("Grant access? (y/n): ")

			var response string
			fmt.Scanln(&response)

			if response != "y" && response != "yes" {
				fmt.Printf("⊘ Skipping machine '%s'\n", machine.ID)
				continue
			}
			fmt.Printf("✓ Granting access to '%s'\n", machine.ID)
		}

		// Parse public key
		publicKey, err := crypto.DecodePublicKeyPEM([]byte(machine.PublicKey))
		if err != nil {
			return fmt.Errorf("failed to decode public key for %s: %w", machine.ID, err)
		}

		// Wrap master key
		wrappedKey, err := crypto.WrapKey(publicKey, masterKey)
		if err != nil {
			return fmt.Errorf("failed to wrap key for %s: %w", machine.ID, err)
		}

		// Create wrapped key metadata
		wrappedKeyData := &types.WrappedKey{
			MachineID:            machine.ID,
			PublicKeyFingerprint: machine.Fingerprint,
			WrappedKey:           base64.StdEncoding.EncodeToString(wrappedKey),
			GrantedBy:            grantedBy,
			GrantedAt:            machine.CreatedAt,
		}

		// Save wrapped key
		data, err := json.MarshalIndent(wrappedKeyData, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal wrapped key: %w", err)
		}

		if err := WriteFileAtomic(wrappedKeyPath, data, FilePerm); err != nil {
			return fmt.Errorf("failed to save wrapped key for %s: %w", machine.ID, err)
		}
	}

	return nil
}

// WrapMasterKeyForExistingMachines wraps the master key ONLY for machines that already have access
// This is used during push to update existing keys without granting new access
func WrapMasterKeyForExistingMachines(paths *Paths, environment string, masterKey []byte, grantedBy string) error {
	// Get all machines
	machines, err := ListMachines(paths)
	if err != nil {
		return fmt.Errorf("failed to list machines: %w", err)
	}

	if len(machines) == 0 {
		return fmt.Errorf("no machines found in vault")
	}

	// Ensure wrapped keys environment directory exists
	envDir := paths.GetWrappedKeysEnvPath(environment)
	if err := ensureDir(envDir, DirPerm); err != nil {
		return fmt.Errorf("failed to create wrapped keys directory: %w", err)
	}

	// Wrap key ONLY for machines that already have access
	for _, machine := range machines {
		wrappedKeyPath := paths.GetWrappedKeyPath(environment, machine.ID)

		// Only wrap if key already exists or if it's the current machine
		if !FileExists(wrappedKeyPath) && machine.ID != grantedBy {
			continue // Skip machines without existing access
		}

		// Parse public key
		publicKey, err := crypto.DecodePublicKeyPEM([]byte(machine.PublicKey))
		if err != nil {
			return fmt.Errorf("failed to decode public key for %s: %w", machine.ID, err)
		}

		// Wrap master key
		wrappedKey, err := crypto.WrapKey(publicKey, masterKey)
		if err != nil {
			return fmt.Errorf("failed to wrap key for %s: %w", machine.ID, err)
		}

		// Create wrapped key metadata
		wrappedKeyData := &types.WrappedKey{
			MachineID:            machine.ID,
			PublicKeyFingerprint: machine.Fingerprint,
			WrappedKey:           base64.StdEncoding.EncodeToString(wrappedKey),
			GrantedBy:            grantedBy,
			GrantedAt:            machine.CreatedAt,
		}

		// Save wrapped key
		data, err := json.MarshalIndent(wrappedKeyData, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal wrapped key: %w", err)
		}

		if err := WriteFileAtomic(wrappedKeyPath, data, FilePerm); err != nil {
			return fmt.Errorf("failed to save wrapped key for %s: %w", machine.ID, err)
		}
	}

	return nil
}

// GrantMachineAccess grants a specific machine access to an environment
// Returns (wasGranted, error) where wasGranted indicates if access was newly granted
// Returns (false, nil) if machine already has access (not an error)
func GrantMachineAccess(paths *Paths, environment, machineID string, masterKey []byte, grantedBy string) (bool, error) {
	// Get all machines
	machines, err := ListMachines(paths)
	if err != nil {
		return false, fmt.Errorf("failed to list machines: %w", err)
	}

	// Find the machine
	var targetMachine *types.MachineInfo
	for _, m := range machines {
		if m.ID == machineID {
			targetMachine = m
			break
		}
	}

	if targetMachine == nil {
		return false, fmt.Errorf("machine '%s' not found in vault", machineID)
	}

	// Check if machine already has access
	wrappedKeyPath := paths.GetWrappedKeyPath(environment, machineID)
	if FileExists(wrappedKeyPath) {
		return false, nil // Already has access - not an error
	}

	// Ensure wrapped keys environment directory exists
	envDir := paths.GetWrappedKeysEnvPath(environment)
	if err := ensureDir(envDir, DirPerm); err != nil {
		return false, fmt.Errorf("failed to create wrapped keys directory: %w", err)
	}

	// Parse public key
	publicKey, err := crypto.DecodePublicKeyPEM([]byte(targetMachine.PublicKey))
	if err != nil {
		return false, fmt.Errorf("failed to decode public key for %s: %w", machineID, err)
	}

	// Wrap master key
	wrappedKey, err := crypto.WrapKey(publicKey, masterKey)
	if err != nil {
		return false, fmt.Errorf("failed to wrap key for %s: %w", machineID, err)
	}

	// Create wrapped key metadata
	wrappedKeyData := &types.WrappedKey{
		MachineID:            targetMachine.ID,
		PublicKeyFingerprint: targetMachine.Fingerprint,
		WrappedKey:           base64.StdEncoding.EncodeToString(wrappedKey),
		GrantedBy:            grantedBy,
		GrantedAt:            targetMachine.CreatedAt,
	}

	// Save wrapped key
	data, err := json.MarshalIndent(wrappedKeyData, "", "  ")
	if err != nil {
		return false, fmt.Errorf("failed to marshal wrapped key: %w", err)
	}

	if err := WriteFileAtomic(wrappedKeyPath, data, FilePerm); err != nil {
		return false, fmt.Errorf("failed to save wrapped key for %s: %w", machineID, err)
	}

	return true, nil
}

// UnwrapMasterKey unwraps the master key for the current machine in a specific environment
// Uses unified paths - works identically in both local and global modes.
//
// The decrypter is supplied by the caller rather than loaded here: this package
// (vault) must NOT import internal/keyprovider, because keyprovider already
// imports vault (LoadPrivateKey, machine info) and doing so would create an
// import cycle. The cli layer owns keyprovider.LoadDecrypter() and passes the
// resulting crypto.Decrypter (software *rsa.PrivateKey or a PKCS#11-backed
// decrypter) down here, so pull/push transparently support hardware tokens.
func UnwrapMasterKey(paths *Paths, environment string, dec stdcrypto.Decrypter) ([]byte, error) {

	// Get current machine ID
	machineID, err := GetCurrentMachineID()
	if err != nil {
		return nil, fmt.Errorf("failed to get current machine ID: %w", err)
	}

	// Load wrapped key
	wrappedKeyPath := paths.GetWrappedKeyPath(environment, machineID)
	data, err := ReadFile(wrappedKeyPath)
	if err != nil {
		return nil, fmt.Errorf("access denied to '%s' environment: %w\nYou may need to request access from someone with push permissions", environment, err)
	}

	var wrappedKeyData types.WrappedKey
	if err := json.Unmarshal(data, &wrappedKeyData); err != nil {
		return nil, fmt.Errorf("failed to parse wrapped key: %w", err)
	}

	// Decode wrapped key
	wrappedKey, err := base64.StdEncoding.DecodeString(wrappedKeyData.WrappedKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode wrapped key: %w", err)
	}

	// Unwrap master key using the caller-supplied decrypter
	masterKey, err := crypto.UnwrapKey(dec, wrappedKey)
	if err != nil {
		return nil, fmt.Errorf("failed to unwrap master key: %w", err)
	}

	return masterKey, nil
}

// FormatEnvOutput formats secrets as .env format
func FormatEnvOutput(secrets map[string]string) string {
	var builder strings.Builder

	for key, value := range secrets {
		// Quote values that contain spaces or special characters
		if strings.ContainsAny(value, " \t\n\"'\\") {
			value = fmt.Sprintf("\"%s\"", strings.ReplaceAll(value, "\"", "\\\""))
		}
		builder.WriteString(fmt.Sprintf("%s=%s\n", key, value))
	}

	return builder.String()
}
