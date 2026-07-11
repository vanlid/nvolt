//go:build !wolfpkcs11_embed

package pkcs11

// embeddedModuleBytes is empty in the default build: nvolt carries no PKCS#11
// module and relies on an external one (autodetected or via --pkcs11-module).
// Build with -tags wolfpkcs11_embed to compile the module in (see embed_on.go).
var embeddedModuleBytes []byte

// embeddedModuleAvailable reports whether a module was compiled in. False here.
const embeddedModuleAvailable = false
