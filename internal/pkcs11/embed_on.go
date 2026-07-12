//go:build tpm_embed

package pkcs11

import _ "embed"

// embeddedModuleBytes is the self-contained wolfPKCS11 module (wolfSSL + wolfTPM
// linked in) produced by build/pkcs11/build-module.sh. The blob at dist/module.bin
// is git-ignored and must exist at build time — run `make module` first, then
// build with `-tags tpm_embed` (or `make build-embedded`).
//
//go:embed dist/module.bin
var embeddedModuleBytes []byte

// embeddedModuleAvailable reports whether a module was compiled in. True here.
const embeddedModuleAvailable = true
