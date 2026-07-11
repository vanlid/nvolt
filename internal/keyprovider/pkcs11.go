package keyprovider

import (
	"crypto"
	"fmt"
)

// loadPKCS11Decrypter loads a crypto.Decrypter backed by a PKCS#11 token.
//
// TASK-6 PLACEHOLDER: not yet implemented. Task 6 replaces this with a real
// PKCS#11 session + decrypter implementation.
func loadPKCS11Decrypter(src keySource) (crypto.Decrypter, func() error, error) {
	return nil, nil, fmt.Errorf("pkcs11 key source not yet implemented")
}
