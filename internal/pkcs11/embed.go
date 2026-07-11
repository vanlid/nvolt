package pkcs11

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

// embeddedModuleSentinel is the reserved --pkcs11-module / NVOLT_PKCS11_MODULE
// value (and key_source.module value) that selects nvolt's built-in wolfPKCS11
// module instead of a filesystem path. Chosen as a fixed word so a machine's
// recorded key source carries no absolute path — "embedded" simply means "use
// the module compiled into this nvolt binary".
const embeddedModuleSentinel = "embedded"

// moduleExt returns the file extension used for the extracted module. dlopen
// ignores the extension, but Windows' loader conventionally expects .dll.
func moduleExt() string {
	if runtime.GOOS == "windows" {
		return ".dll"
	}
	return ".so"
}

// materializeModule writes module bytes into dir under a content-addressed
// filename and returns the path, so the embedded wolfPKCS11 module can be handed
// to dlopen (which needs a real file). It is idempotent and safe under
// concurrency: the name is derived from the content hash, an existing file with
// matching content is reused without rewriting, and new files are written to a
// temp file in the same directory and atomically renamed into place. Distinct
// module bytes (e.g. after a version bump) get distinct names, so a stale cache
// file is never mistaken for a new one.
func materializeModule(dir string, data []byte) (string, error) {
	if len(data) == 0 {
		return "", errors.New("empty PKCS#11 module data")
	}
	sum := sha256.Sum256(data)
	path := filepath.Join(dir, fmt.Sprintf("wolfpkcs11-%x%s", sum[:8], moduleExt()))

	// Reuse an existing, correct extraction.
	if existing, err := os.ReadFile(path); err == nil && bytes.Equal(existing, data) {
		return path, nil
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", fmt.Errorf("create module cache dir: %w", err)
	}

	tmp, err := os.CreateTemp(dir, "wolfpkcs11-*.tmp")
	if err != nil {
		return "", fmt.Errorf("create temp module: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op after a successful rename

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return "", fmt.Errorf("write temp module: %w", err)
	}
	if err := tmp.Chmod(0o755); err != nil {
		tmp.Close()
		return "", fmt.Errorf("chmod temp module: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return "", fmt.Errorf("close temp module: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return "", fmt.Errorf("install module: %w", err)
	}
	return path, nil
}

// appendEmbeddedOption adds nvolt's built-in wolfPKCS11 module to a discovered-
// module list when it is compiled in, so it appears in `pkcs11 list` and
// selection like any external module. It is appended last: a real external
// token or p11-kit proxy stays the default, while the built-in TPM module is
// always available as an option and becomes the sole default on a machine with
// nothing else installed. Its Path is the "embedded" sentinel, which Open
// materializes to a real file on load.
func appendEmbeddedOption(mods []DiscoveredModule, available bool) []DiscoveredModule {
	if !available {
		return mods
	}
	return append(mods, DiscoveredModule{
		Path:   embeddedModuleSentinel,
		Label:  "wolfPKCS11 (built-in, TPM)",
		Source: "embedded",
	})
}

// extractEmbeddedModule materializes the wolfPKCS11 module compiled into this
// binary and returns its on-disk path, extracting lazily on first use into the
// per-user cache dir. Returns an actionable error when nvolt was built without
// the module (the default, tag-free build).
func extractEmbeddedModule() (string, error) {
	if len(embeddedModuleBytes) == 0 {
		return "", errors.New("this nvolt was built without an embedded PKCS#11 module; " +
			"rebuild with -tags wolfpkcs11_embed (see build/pkcs11/README.md) " +
			"or pass --pkcs11-module with a real module path")
	}
	dir, err := os.UserCacheDir()
	if err != nil || dir == "" {
		dir = os.TempDir()
	}
	return materializeModule(filepath.Join(dir, "nvolt"), embeddedModuleBytes)
}
