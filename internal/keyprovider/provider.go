// Package keyprovider abstracts loading the machine's private-key decrypter,
// so callers don't need to know whether the key lives in a software PEM file
// or on a PKCS#11-backed hardware token (e.g. a YubiKey).
package keyprovider

import "crypto"

// sourcePKCS11 identifies a hardware-token-backed key source in machine.json's
// key_source.source field (vs. the default software-file-backed source).
const sourcePKCS11 = "pkcs11"

// LoadDecrypter returns the decrypter for THIS machine plus a close func.
// It reads the machine key-source from machine.json; absent source ⇒ software.
func LoadDecrypter() (crypto.Decrypter, func() error, error) {
	src, err := loadKeySource()
	if err != nil {
		return nil, nil, err
	}
	switch src.Source {
	case sourcePKCS11:
		return loadPKCS11Decrypter(&src) // Task 6
	default:
		return loadSoftwareDecrypter()
	}
}
