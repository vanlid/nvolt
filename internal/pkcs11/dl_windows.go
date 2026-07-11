//go:build windows

package pkcs11

import "errors"

// errNotSupported is returned by every dl* primitive on Windows. nvolt only
// speaks PKCS#11 on the remote Linux host (the YubiKey is forwarded there via
// p11-kit/usbip), so a Windows binary never dlopens a real module — it just
// needs to compile and fail clearly if a pkcs11 command is invoked directly.
var errNotSupported = errors.New("pkcs11: not supported on windows (run nvolt on the linux host where the token is forwarded)")

func dlopen(path string) (uintptr, error) {
	return 0, errNotSupported
}

func dlsym(handle uintptr, name string) (uintptr, error) {
	return 0, errNotSupported
}

func dlclose(handle uintptr) error {
	return errNotSupported
}
