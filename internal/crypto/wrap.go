package crypto

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
)

// WrapKey wraps a symmetric key using RSA-OAEP with a public key
func WrapKey(publicKey *rsa.PublicKey, key []byte) ([]byte, error) {
	if publicKey == nil {
		return nil, fmt.Errorf("public key is nil")
	}

	wrappedKey, err := rsa.EncryptOAEP(
		sha256.New(),
		rand.Reader,
		publicKey,
		key,
		nil,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to wrap key: %w", err)
	}

	return wrappedKey, nil
}

// UnwrapKey unwraps a symmetric key using RSA-OAEP-SHA256 via any crypto.Decrypter.
// *rsa.PrivateKey satisfies crypto.Decrypter, so the software backend is
// behavior-preserving; PKCS#11-backed decrypters can be substituted transparently.
func UnwrapKey(dec crypto.Decrypter, wrappedKey []byte) ([]byte, error) {
	if dec == nil {
		return nil, fmt.Errorf("decrypter is nil")
	}

	key, err := dec.Decrypt(rand.Reader, wrappedKey, &rsa.OAEPOptions{Hash: crypto.SHA256})
	if err != nil {
		return nil, fmt.Errorf("failed to unwrap key: %w", err)
	}

	return key, nil
}
