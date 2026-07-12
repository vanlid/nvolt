//go:build pkcs11 && windows

package pkcs11

import (
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows/registry"
)

// DetectModules discovers PKCS#11 provider libraries on Windows. There is no
// universal standard location, so this is best-effort: it first reads known
// vendor registry keys (OpenSC, Yubico) to derive install directories, then
// falls back to well-known paths under %ProgramFiles% / %ProgramFiles(x86)%.
// Results are deduped by cleaned absolute path; only paths that exist on disk
// are returned.
func DetectModules() []DiscoveredModule {
	var mods []DiscoveredModule
	seen := make(map[string]bool)

	add := func(path, source string) {
		if path == "" {
			return
		}
		if _, err := os.Stat(path); err != nil {
			return
		}
		key := cleanModuleKey(path)
		if seen[key] {
			return
		}
		seen[key] = true
		mods = append(mods, DiscoveredModule{
			Path:   path,
			Label:  filepath.Base(path),
			Source: source,
		})
	}

	for _, path := range registryModuleCandidates() {
		add(path, "registry")
	}
	for _, path := range envModuleCandidates() {
		add(path, "path")
	}

	return appendEmbeddedOption(mods, embeddedModuleAvailable)
}

// registryModuleCandidates reads known vendor registry keys and derives the
// PKCS#11 DLL path from each install directory it finds. Every read is
// best-effort and defensive: missing keys and unknown value names are
// tolerated (never panics). The exact value names below are guesses at the
// common installers' layout; when they are absent, readRegistryInstallDir
// enumerates the key's string values and picks one that looks like a path.
func registryModuleCandidates() []string {
	var out []string

	// OpenSC installer records its install directory; the module lives under
	// <dir>\pkcs11\opensc-pkcs11.dll.
	if dir, ok := readRegistryInstallDir(`SOFTWARE\OpenSC Project\OpenSC`); ok {
		out = append(out, filepath.Join(dir, "pkcs11", "opensc-pkcs11.dll"))
	}

	// Yubico tools: probe a couple of known key locations. The precise DLL
	// name/layout varies by product, so we try the common ones under the
	// discovered directory.
	for _, key := range []string{
		`SOFTWARE\Yubico\YubiKey PIV Manager`,
		`SOFTWARE\Yubico\Yubico PIV Tool`,
		`SOFTWARE\Yubico`,
	} {
		dir, ok := readRegistryInstallDir(key)
		if !ok {
			continue
		}
		out = append(out,
			filepath.Join(dir, "ykcs11.dll"),
			filepath.Join(dir, "bin", "libykcs11.dll"),
			filepath.Join(dir, "libykcs11.dll"),
		)
	}

	return out
}

// readRegistryInstallDir opens an HKLM subkey (64-bit view) and returns a
// directory path from it, best-effort. It first tries common install-dir value
// names, then falls back to enumerating all string values and returning the
// first that looks like a filesystem path. A missing key returns ok=false
// rather than erroring.
func readRegistryInstallDir(path string) (string, bool) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.READ|registry.WOW64_64KEY)
	if err != nil {
		return "", false
	}
	defer k.Close()

	// Common install-dir value names used by installers. The empty name reads
	// the key's default value.
	for _, name := range []string{"Install_Dir", "InstallDir", "InstallLocation", "Path", ""} {
		if v, _, err := k.GetStringValue(name); err == nil && looksLikePath(v) {
			return v, true
		}
	}

	// Fall back: enumerate every string value and pick one that looks like a
	// path. This avoids hard-coding value names we cannot verify.
	names, err := k.ReadValueNames(0)
	if err != nil {
		return "", false
	}
	for _, name := range names {
		if v, _, err := k.GetStringValue(name); err == nil && looksLikePath(v) {
			return v, true
		}
	}

	return "", false
}

// looksLikePath reports whether v resembles a Windows filesystem path (a
// drive-letter path like C:\... or a UNC path like \\host\share).
func looksLikePath(v string) bool {
	if len(v) >= 3 && v[1] == ':' && (v[2] == '\\' || v[2] == '/') {
		return true
	}
	return strings.HasPrefix(v, `\\`)
}

// envModuleCandidates builds well-known PKCS#11 DLL paths from the Program
// Files environment variables, falling back to the default install roots when
// the variables are empty.
func envModuleCandidates() []string {
	programFiles := os.Getenv("ProgramFiles")
	if programFiles == "" {
		programFiles = `C:\Program Files`
	}
	programFilesX86 := os.Getenv("ProgramFiles(x86)")
	if programFilesX86 == "" {
		programFilesX86 = `C:\Program Files (x86)`
	}

	var out []string
	for _, base := range []string{programFiles, programFilesX86} {
		out = append(out,
			filepath.Join(base, "OpenSC Project", "OpenSC", "pkcs11", "opensc-pkcs11.dll"),
			filepath.Join(base, "Yubico", "Yubico PIV Tool", "bin", "libykcs11.dll"),
			filepath.Join(base, "Yubico", "YubiKey PIV Manager", "ykcs11.dll"),
		)
	}
	return out
}
