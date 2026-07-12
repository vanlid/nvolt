package pkcs11

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// cleanModuleKey returns a canonical key for a module path used to dedupe
// DetectModules results: the resolved (symlink-followed) absolute path, so a
// symlink (e.g. /usr/lib/x86_64-linux-gnu/opensc-pkcs11.so) and its target
// (e.g. /usr/lib/x86_64-linux-gnu/pkcs11/opensc-pkcs11.so) collapse to the
// same key instead of listing the same physical module twice. Falls back to
// the cleaned absolute path (or cleaned original path) when the path doesn't
// exist or can't be resolved, so a not-yet-verified candidate still gets a
// stable key.
func cleanModuleKey(path string) string {
	if resolved, err := filepath.EvalSymlinks(path); err == nil {
		return filepath.Clean(resolved)
	}
	if abs, err := filepath.Abs(path); err == nil {
		return filepath.Clean(abs)
	}
	return filepath.Clean(path)
}

// linuxModuleCandidates lists the common install paths for PKCS#11 provider
// libraries on Linux, covering p11-kit, OpenSC and YubiKey's ykcs11.
var linuxModuleCandidates = []string{
	"/usr/lib/x86_64-linux-gnu/pkcs11/p11-kit-client.so",
	"/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so",
	"/usr/lib/x86_64-linux-gnu/pkcs11/opensc-pkcs11.so",
	"/usr/lib/pkcs11/opensc-pkcs11.so",
	"/usr/local/lib/opensc-pkcs11.so",
	"/usr/lib/x86_64-linux-gnu/pkcs11/ykcs11.so",
	"/usr/local/lib/libykcs11.so",
}

// darwinModuleCandidates lists the common install paths for PKCS#11 provider
// libraries on macOS, covering Homebrew (both Apple Silicon and Intel
// prefixes), the OpenSC.org installer and YubiKey's ykcs11.
var darwinModuleCandidates = []string{
	"/opt/homebrew/lib/opensc-pkcs11.so",
	"/usr/local/lib/opensc-pkcs11.so",
	"/Library/OpenSC/lib/opensc-pkcs11.so",
	"/usr/local/lib/libykcs11.dylib",
	"/opt/homebrew/lib/libykcs11.dylib",
}

// windowsModuleCandidates lists the common install paths for PKCS#11 provider
// libraries on Windows, covering the OpenSC installer and Yubico's PIV tools.
var windowsModuleCandidates = []string{
	`C:\Program Files\OpenSC Project\OpenSC\pkcs11\opensc-pkcs11.dll`,
	`C:\Program Files\Yubico\Yubico PIV Tool\bin\libykcs11.dll`,
	`C:\Program Files\Yubico\YubiKey PIV Manager\ykcs11.dll`,
}

// candidatesForOS returns the module search list for the current GOOS.
func candidatesForOS() []string {
	switch runtime.GOOS {
	case "darwin":
		return darwinModuleCandidates
	case "windows":
		return windowsModuleCandidates
	default:
		return linuxModuleCandidates
	}
}

// defaultModulePathFrom returns the first candidate that exists on disk, or
// an error listing all of them. Split out from DefaultModulePath so tests can
// probe a synthetic candidate list instead of the real per-OS paths.
func defaultModulePathFrom(candidates []string) (string, error) {
	for _, path := range candidates {
		if _, err := os.Stat(path); err == nil {
			return path, nil
		}
	}
	return "", fmt.Errorf("no PKCS#11 module found; looked in: %s (pass --pkcs11-module or set NVOLT_PKCS11_MODULE)", strings.Join(candidates, ", "))
}
