//go:build pkcs11 || tpm_static

package pkcs11

import (
	"fmt"
	"os"
)

// DefaultModulePath returns the path of the first PKCS#11 module discovered by
// DetectModules (a p11-kit proxy on Unix, a registry/common-path provider, or
// the built-in wolfPKCS11 module), falling back to an error that lists every
// common location probed when nothing is found, so callers know to pass
// --pkcs11-module explicitly.
//
// It lives behind the loader tags because DetectModules only exists when a
// loader is compiled in; the tag-free build carries no PKCS#11 loader at all.
func DefaultModulePath() (string, error) {
	if mods := DetectModules(); len(mods) > 0 {
		return mods[0].Path, nil
	}
	// Nothing discovered: reuse the per-OS candidate list to produce a
	// deterministic "not found" error naming where we looked.
	return defaultModulePathFrom(candidatesForOS())
}

// ResolveModulePath resolves the PKCS#11 module path to use, in order of
// precedence: an explicit --module flag value, then the NVOLT_PKCS11_MODULE
// environment variable, then autodetection of common install locations. The
// value may be the "embedded" sentinel (a real path here, materialized to a
// file by Open on load); it is passed through unchanged like any other path.
func ResolveModulePath(flagValue string) (string, error) {
	if flagValue != "" {
		return flagValue, nil
	}
	if env := os.Getenv("NVOLT_PKCS11_MODULE"); env != "" {
		return env, nil
	}
	path, err := DefaultModulePath()
	if err != nil {
		return "", fmt.Errorf("failed to resolve PKCS#11 module: %w", err)
	}
	return path, nil
}
