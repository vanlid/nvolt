//go:build pkcs11 && tpm_static

package pkcs11

// Selecting both loaders is unsupported: they provide conflicting Open/DetectModules
// implementations (purego dlopen vs cgo static link). This line fails to compile so
// the mistake is caught at build time rather than producing a broken binary.
const _ = "build error: tags 'pkcs11' and 'tpm_static' are mutually exclusive" - 0
