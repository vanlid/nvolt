//go:build !pkcs11

package cli

import (
	"crypto/rsa"
	"errors"
)

// errNoPKCS11 is returned by every PKCS#11 entry point in a build compiled
// without a PKCS#11 loader (the default fully-static binary). Use the dynamic
// `-tags pkcs11` build (or the static `nvolt-tpm` build) for hardware keys.
var errNoPKCS11 = errors.New("this nvolt was not built with PKCS#11 support; use the pkcs11-enabled build for hardware/TPM keys")

// resolveEnrollTarget is the default build's stub for the real pkcs11.go
// helper of the same name: init/join/rebind/machine all call it to resolve
// the module/URI to enroll or rebind against, but with no PKCS#11 loader
// compiled in there is nothing to resolve.
func resolveEnrollTarget(_, _ string) (module, uri string, err error) {
	return "", "", errNoPKCS11
}

// enrollPKCS11Machine is the default build's stub for the real pkcs11.go
// function: machine_setup.go's ensurePKCS11MachineInitialized calls it to
// enroll an on-card key as this machine's identity.
func enrollPKCS11Machine(_, _, _ string) error {
	return errNoPKCS11
}

// ReadTokenPublicKey is the default build's stub for the real pkcs11.go
// function: machine.go's machineAddPublicKey calls it for `machine add
// --pkcs11`.
func ReadTokenPublicKey(_, _ string) (*rsa.PublicKey, error) {
	return nil, errNoPKCS11
}
