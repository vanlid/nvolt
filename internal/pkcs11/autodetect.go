package pkcs11

import (
	"fmt"
	"os"
	"runtime"
	"strings"
)

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

// DefaultModulePath probes a per-OS list of common PKCS#11 module install
// locations (p11-kit, OpenSC, YubiKey ykcs11) and returns the first one that
// exists on disk. It returns an error listing every path it looked at when
// none are found, so callers know to pass --module explicitly.
func DefaultModulePath() (string, error) {
	return defaultModulePathFrom(candidatesForOS())
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
	return "", fmt.Errorf("no PKCS#11 module found; looked in: %s (pass --module or set NVOLT_PKCS11_MODULE)", strings.Join(candidates, ", "))
}

// ResolveModulePath resolves the PKCS#11 module path to use, in order of
// precedence: an explicit --module flag value, then the NVOLT_PKCS11_MODULE
// environment variable, then autodetection of common install locations.
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
