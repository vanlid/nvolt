package crypto

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
)

const (
	// RSAKeySize is the size of RSA keys in bits
	RSAKeySize = 4096
)

// Type alias for cleaner code
type RSAPrivateKey = rsa.PrivateKey

// GenerateRSAKeypair generates a new RSA keypair
func GenerateRSAKeypair() (*rsa.PrivateKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, RSAKeySize)
	if err != nil {
		return nil, fmt.Errorf("failed to generate RSA key: %w", err)
	}

	// Validate key strength
	if err := ValidateRSAKey(privateKey); err != nil {
		return nil, fmt.Errorf("generated key failed validation: %w", err)
	}

	return privateKey, nil
}

// ValidateRSAKey validates that an RSA key meets security requirements
func ValidateRSAKey(key *rsa.PrivateKey) error {
	if key == nil {
		return fmt.Errorf("key is nil")
	}

	// Check key size
	keySize := key.N.BitLen()
	if keySize < 2048 {
		return fmt.Errorf("key size %d bits is too small (minimum 2048 bits required)", keySize)
	}

	// Verify public exponent is reasonable
	if key.E < 3 || key.E > (1<<31-1) {
		return fmt.Errorf("invalid public exponent: %d", key.E)
	}

	// Check that primes exist
	if len(key.Primes) < 2 {
		return fmt.Errorf("invalid number of primes: %d", len(key.Primes))
	}

	return nil
}

// EncodePrivateKeyPEM encodes a private key to PEM format
func EncodePrivateKeyPEM(privateKey *rsa.PrivateKey) ([]byte, error) {
	privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	})
	if privateKeyPEM == nil {
		return nil, fmt.Errorf("failed to encode private key to PEM")
	}
	return privateKeyPEM, nil
}

// DecodePrivateKeyPEM decodes an RSA private key from PEM, accepting the two
// common encodings so users aren't forced into one tool's default:
//   - PKCS#1  ("RSA PRIVATE KEY") — `openssl genrsa -traditional`, `ssh-keygen -m PEM`
//   - PKCS#8  ("PRIVATE KEY")     — openssl's modern default (`openssl genpkey`, genrsa 3.x)
//
// A PKCS#8 key that isn't RSA is rejected. An OpenSSH-format key
// ("OPENSSH PRIVATE KEY") is not parsed directly (would add a dependency);
// the error tells the caller how to convert it in place.
func DecodePrivateKeyPEM(pemData []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}
	switch block.Type {
	case "RSA PRIVATE KEY": // PKCS#1
		key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse PKCS#1 private key: %w", err)
		}
		return key, nil
	case "PRIVATE KEY": // PKCS#8
		parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse PKCS#8 private key: %w", err)
		}
		key, ok := parsed.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("private key is %T, want RSA", parsed)
		}
		return key, nil
	default:
		return nil, fmt.Errorf("unsupported private key PEM type %q; want \"RSA PRIVATE KEY\" (PKCS#1) or \"PRIVATE KEY\" (PKCS#8). "+
			"For an OpenSSH key convert it in place: ssh-keygen -p -m PEM -f <keyfile>", block.Type)
	}
}

// EncodePublicKeyPEM encodes a public key to PEM format
func EncodePublicKeyPEM(publicKey *rsa.PublicKey) ([]byte, error) {
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key: %w", err)
	}

	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	})
	if publicKeyPEM == nil {
		return nil, fmt.Errorf("failed to encode public key to PEM")
	}
	return publicKeyPEM, nil
}

// DecodePublicKeyPEM decodes a public key from PEM format
func DecodePublicKeyPEM(pemData []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}
	if block.Type != "PUBLIC KEY" {
		return nil, fmt.Errorf("unexpected PEM block type: %s", block.Type)
	}

	publicKeyInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	publicKey, ok := publicKeyInterface.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("not an RSA public key")
	}

	return publicKey, nil
}

// GenerateFingerprint generates a SHA256 fingerprint of a public key
func GenerateFingerprint(publicKey *rsa.PublicKey) (string, error) {
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return "", fmt.Errorf("failed to marshal public key: %w", err)
	}

	hash := sha256.Sum256(publicKeyBytes)
	fingerprint := base64.StdEncoding.EncodeToString(hash[:])
	return fmt.Sprintf("SHA256:%s", fingerprint), nil
}
