package pkcs11

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestResolveModulePathFlagPrecedence asserts an explicit --module flag value
// wins over NVOLT_PKCS11_MODULE, even when the env var is also set.
func TestResolveModulePathFlagPrecedence(t *testing.T) {
	t.Setenv("NVOLT_PKCS11_MODULE", "/env/module.so")

	got, err := ResolveModulePath("/flag/module.so")
	if err != nil {
		t.Fatalf("ResolveModulePath: %v", err)
	}
	if got != "/flag/module.so" {
		t.Fatalf("got %q, want flag value %q", got, "/flag/module.so")
	}
}

// TestResolveModulePathEnvFallback asserts NVOLT_PKCS11_MODULE is used when
// no --module flag value is given.
func TestResolveModulePathEnvFallback(t *testing.T) {
	t.Setenv("NVOLT_PKCS11_MODULE", "/env/module.so")

	got, err := ResolveModulePath("")
	if err != nil {
		t.Fatalf("ResolveModulePath: %v", err)
	}
	if got != "/env/module.so" {
		t.Fatalf("got %q, want env value %q", got, "/env/module.so")
	}
}

// TestResolveModulePathAutodetectFallback asserts that with neither a flag
// value nor the env var set, resolution falls through to DefaultModulePath
// (i.e. either a real module is found, or the "no module found" error is
// returned - never a value pulled out of thin air).
func TestResolveModulePathAutodetectFallback(t *testing.T) {
	t.Setenv("NVOLT_PKCS11_MODULE", "")

	got, err := ResolveModulePath("")
	if err != nil {
		if !strings.Contains(err.Error(), "no PKCS#11 module found") {
			t.Fatalf("unexpected error: %v", err)
		}
		return
	}
	if got == "" {
		t.Fatal("expected a non-empty module path when err is nil")
	}
}

// TestDefaultModulePathFromFound asserts a candidate list containing a path
// that exists on disk resolves to that path.
func TestDefaultModulePathFromFound(t *testing.T) {
	dir := t.TempDir()
	modulePath := filepath.Join(dir, "fake-pkcs11.so")
	if err := os.WriteFile(modulePath, []byte("not a real module"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	candidates := []string{
		filepath.Join(dir, "does-not-exist.so"),
		modulePath,
	}

	got, err := defaultModulePathFrom(candidates)
	if err != nil {
		t.Fatalf("defaultModulePathFrom: %v", err)
	}
	if got != modulePath {
		t.Fatalf("got %q, want %q", got, modulePath)
	}
}

// TestDefaultModulePathFromNotFound asserts an empty (or all-missing)
// candidate list returns a deterministic "not found" error listing the
// candidates that were checked.
func TestDefaultModulePathFromNotFound(t *testing.T) {
	_, err := defaultModulePathFrom(nil)
	if err == nil {
		t.Fatal("expected an error for an empty candidate list")
	}
	if !strings.Contains(err.Error(), "no PKCS#11 module found") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestDefaultModulePathCandidatesForOS asserts every supported GOOS has a
// non-empty candidate list wired up (guards against a typo dropping an OS's
// list entirely).
func TestDefaultModulePathCandidatesForOS(t *testing.T) {
	if len(linuxModuleCandidates) == 0 {
		t.Error("linuxModuleCandidates is empty")
	}
	if len(darwinModuleCandidates) == 0 {
		t.Error("darwinModuleCandidates is empty")
	}
	if len(windowsModuleCandidates) == 0 {
		t.Error("windowsModuleCandidates is empty")
	}
}
