package keyprovider

import (
	"crypto"

	"github.com/iluxav/nvolt/internal/vault"
)

// loadSoftwareDecrypter loads the machine's software (PEM) private key and
// wraps it as a crypto.Decrypter. *rsa.PrivateKey satisfies crypto.Decrypter
// natively, so no adaptation is needed.
func loadSoftwareDecrypter() (crypto.Decrypter, func() error, error) {
	key, err := vault.LoadPrivateKey()
	if err != nil {
		return nil, nil, err
	}
	return key, func() error { return nil }, nil
}
