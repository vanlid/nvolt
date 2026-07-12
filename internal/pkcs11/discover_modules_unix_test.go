//go:build pkcs11 && !windows

package pkcs11

import (
	"os"
	"path/filepath"
	"testing"
)

// writeTempModule creates an empty file to stand in for a PKCS#11 module and
// returns its path.
func writeTempModule(t *testing.T, dir, name string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte("not a real module"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	return path
}

// TestDetectModulesUnixProxyFirst asserts an existing proxy is surfaced first
// with Source "p11-kit", followed by common-path providers as Source "path".
func TestDetectModulesUnixProxyFirst(t *testing.T) {
	dir := t.TempDir()
	proxy := writeTempModule(t, dir, "p11-kit-proxy.so")
	opensc := writeTempModule(t, dir, "opensc-pkcs11.so")

	mods := detectModulesUnix(
		[]string{filepath.Join(dir, "missing-proxy.so"), proxy},
		[]string{filepath.Join(dir, "missing.so"), opensc},
	)

	if len(mods) != 2 {
		t.Fatalf("got %d modules, want 2: %+v", len(mods), mods)
	}
	if mods[0].Path != proxy || mods[0].Source != "p11-kit" {
		t.Fatalf("first module = %+v, want proxy with source p11-kit", mods[0])
	}
	if mods[1].Path != opensc || mods[1].Source != "path" || mods[1].Label != "opensc-pkcs11.so" {
		t.Fatalf("second module = %+v, want opensc common-path entry", mods[1])
	}
}

// TestDetectModulesUnixDedup asserts a common-path candidate that resolves to
// the same file as the proxy is not listed twice.
func TestDetectModulesUnixDedup(t *testing.T) {
	dir := t.TempDir()
	proxy := writeTempModule(t, dir, "p11-kit-proxy.so")

	// Same file reached via a non-cleaned path must be deduped.
	dupe := filepath.Join(dir, ".", "p11-kit-proxy.so")

	mods := detectModulesUnix([]string{proxy}, []string{dupe})
	if len(mods) != 1 {
		t.Fatalf("got %d modules, want 1 (dedup): %+v", len(mods), mods)
	}
	if mods[0].Source != "p11-kit" {
		t.Fatalf("kept module = %+v, want the proxy entry", mods[0])
	}
}

// TestDetectModulesUnixDedupSymlink asserts a common-path candidate reached
// via a symlink is deduped against another candidate pointing straight at the
// same physical file (e.g. /usr/lib/x86_64-linux-gnu/opensc-pkcs11.so
// symlinked to /usr/lib/x86_64-linux-gnu/pkcs11/opensc-pkcs11.so): the two
// paths are textually distinct, so only resolving symlinks (not just
// filepath.Clean) collapses them to one listed module.
func TestDetectModulesUnixDedupSymlink(t *testing.T) {
	dir := t.TempDir()
	target := writeTempModule(t, dir, "opensc-pkcs11.so")
	link := filepath.Join(dir, "opensc-pkcs11-symlink.so")
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("Symlink: %v", err)
	}

	mods := detectModulesUnix(
		[]string{filepath.Join(dir, "missing-proxy.so")},
		[]string{link, target},
	)
	if len(mods) != 1 {
		t.Fatalf("got %d modules, want 1 (symlink+target dedup): %+v", len(mods), mods)
	}
	if mods[0].Path != link {
		t.Fatalf("expected first-seen path %q kept, got %+v", link, mods[0])
	}
}

// TestDetectModulesUnixNoProxy asserts common-path providers are still listed
// when no proxy exists.
func TestDetectModulesUnixNoProxy(t *testing.T) {
	dir := t.TempDir()
	ykcs11 := writeTempModule(t, dir, "libykcs11.so")

	mods := detectModulesUnix(
		[]string{filepath.Join(dir, "missing-proxy.so")},
		[]string{ykcs11},
	)
	if len(mods) != 1 {
		t.Fatalf("got %d modules, want 1: %+v", len(mods), mods)
	}
	if mods[0].Source != "path" || mods[0].Label != "libykcs11.so" {
		t.Fatalf("module = %+v, want ykcs11 common-path entry", mods[0])
	}
}

// TestDetectModulesUnixEmpty asserts nothing is returned when no candidate
// exists on disk.
func TestDetectModulesUnixEmpty(t *testing.T) {
	dir := t.TempDir()
	mods := detectModulesUnix(
		[]string{filepath.Join(dir, "nope-proxy.so")},
		[]string{filepath.Join(dir, "nope.so")},
	)
	if len(mods) != 0 {
		t.Fatalf("got %d modules, want 0: %+v", len(mods), mods)
	}
}
