//go:build wolfpkcs11_static && !pkcs11

package pkcs11

// DetectModules returns just the statically-linked wolfPKCS11 module. There is
// no filesystem probing and no "embedded" sentinel in this build — the module
// is the binary, so the single "builtin" entry is always both the default and
// the only option.
func DetectModules() []DiscoveredModule {
	return []DiscoveredModule{{
		Path:   "builtin",
		Label:  "wolfPKCS11 (static, TPM)",
		Source: "builtin",
	}}
}
