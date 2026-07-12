//go:build !pkcs11 && !wolfpkcs11_static

package keyprovider

import (
	"crypto"
	"crypto/rsa"
	"errors"

	"github.com/iluxav/nvolt/pkg/types"
)

// errNoPKCS11 is returned by every PKCS#11 entry point in a build compiled
// without a PKCS#11 loader (the default fully-static binary). Use the
// `-tags pkcs11` (dynamic) or `-tags wolfpkcs11_static` (static) build for
// hardware-backed keys.
var errNoPKCS11 = errors.New("this nvolt was not built with PKCS#11 support; use rebind to switch config to using a software key or use a build with PKCS#11 support")

// loadPKCS11Decrypter is the default build's stub for the real pkcs11.go
// function of the same name: provider.go's LoadDecrypter (always compiled)
// dispatches here when a machine's key_source is "pkcs11". With no PKCS#11
// loader compiled in there is nothing to load, so this returns a clear error
// instead of panicking or silently doing nothing.
func loadPKCS11Decrypter(_ *types.KeySource) (crypto.Decrypter, func() error, error) {
	return nil, nil, errNoPKCS11
}

// Enroll is the default build's stub for the real pkcs11.go function.
// internal/cli/rebind.go (always compiled, since rebind handles both
// --pkcs11 and --software) calls keyprovider.Enroll directly, so the symbol
// must exist here even though it is unreachable in practice: rebind resolves
// its module/URI via cli's own resolveEnrollTarget stub first, which already
// fails with the equivalent "not built with PKCS#11" error before Enroll
// would ever run.
func Enroll(_, _, _ string, _ func() (string, error)) (types.KeySource, *rsa.PublicKey, error) {
	return types.KeySource{}, nil, errNoPKCS11
}
