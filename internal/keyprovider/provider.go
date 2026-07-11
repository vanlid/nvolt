// Package keyprovider abstracts loading the machine's private-key decrypter,
// so callers don't need to know whether the key lives in a software PEM file
// or on a PKCS#11-backed hardware token (e.g. a YubiKey).
package keyprovider

import "crypto"

// keySource is a minimal placeholder for the machine key-source descriptor.
//
// TASK-5 PLACEHOLDER: Task 5 will replace this type (and loadKeySource) with
// real machine.json reading logic. Keep this struct small so Task 5 can swap
// it out cleanly.
type keySource struct {
	Source string
}

// loadKeySource returns the key source configured for this machine.
//
// TASK-5 PLACEHOLDER: always reports "software" until Task 5 implements
// reading the actual machine.json key-source configuration.
func loadKeySource() (keySource, error) {
	return keySource{Source: "software"}, nil
}

// LoadDecrypter returns the decrypter for THIS machine plus a close func.
// It reads the machine key-source (Task 5); absent source ⇒ software.
func LoadDecrypter() (crypto.Decrypter, func() error, error) {
	src, err := loadKeySource() // Task 5
	if err != nil {
		return nil, nil, err
	}
	switch src.Source {
	case "pkcs11":
		return loadPKCS11Decrypter(src) // Task 6
	default:
		return loadSoftwareDecrypter()
	}
}
