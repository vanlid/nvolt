package types

import "time"

// EncryptedSecret represents an encrypted secret value
type EncryptedSecret struct {
	Version int    `json:"version"`
	Data    string `json:"data"`  // base64 encoded ciphertext
	Nonce   string `json:"nonce"` // base64 encoded IV
	Tag     string `json:"tag"`   // base64 encoded auth tag
}

// WrappedKey represents a master key wrapped for a specific machine
type WrappedKey struct {
	MachineID            string    `json:"machine_id"`
	PublicKeyFingerprint string    `json:"public_key_fingerprint"`
	WrappedKey           string    `json:"wrapped_key"` // base64 encoded
	GrantedBy            string    `json:"granted_by"`
	GrantedAt            time.Time `json:"granted_at"`
}

// MachineInfo represents a machine's public key and metadata
type MachineInfo struct {
	ID          string     `json:"id"`
	PublicKey   string     `json:"public_key"`  // PEM format
	Fingerprint string     `json:"fingerprint"` // SHA256 hash
	Hostname    string     `json:"hostname"`
	Description string     `json:"description"`
	CreatedAt   time.Time  `json:"created_at"`
	KeySource   *KeySource `json:"key_source,omitempty"`
}

// KeySource describes where a machine's private key material lives: either
// a local software (PEM) key, or a PKCS#11-backed hardware token (e.g. a
// YubiKey). Absent/nil is treated as software for backward compatibility.
type KeySource struct {
	Source   string `json:"source,omitempty"` // "software" | "pkcs11"
	Module   string `json:"module,omitempty"`
	URI      string `json:"uri,omitempty"`
	PinMode  string `json:"pin_mode,omitempty"`  // "prompt" | "env" | "none"
	OAEPMode string `json:"oaep_mode,omitempty"` // "native" | "raw"
}

// KeyInfo represents metadata about the project master key
type KeyInfo struct {
	Version         int       `json:"version"`
	KeyID           string    `json:"key_id"`
	CreatedAt       time.Time `json:"created_at"`
	LastRotated     time.Time `json:"last_rotated,omitempty"`
	RotationHistory []string  `json:"rotation_history,omitempty"`
}

// VaultConfig represents the vault configuration
type VaultConfig struct {
	Mode       string `json:"mode"`       // "local" or "global"
	Repository string `json:"repository"` // GitHub repo (org/repo) for global mode
	Project    string `json:"project"`    // Project name
}
