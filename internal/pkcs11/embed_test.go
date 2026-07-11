package pkcs11

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestMaterializeModuleWritesContent asserts materializeModule writes the given
// bytes into dir and returns a path whose contents match exactly, so the
// embedded module round-trips to a file dlopen can load.
func TestMaterializeModuleWritesContent(t *testing.T) {
	dir := t.TempDir()
	data := []byte("fake wolfpkcs11 module bytes")

	path, err := materializeModule(dir, data)
	if err != nil {
		t.Fatalf("materializeModule: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read back %q: %v", path, err)
	}
	if !bytes.Equal(got, data) {
		t.Fatalf("content mismatch: wrote %d bytes, read %d", len(data), len(got))
	}
	if filepath.Dir(path) != dir {
		t.Fatalf("path %q not in dir %q", path, dir)
	}
}

// TestMaterializeModuleIdempotent asserts a second call with the same bytes
// returns the same path without error and leaves the content intact, so
// repeated PKCS#11 calls reuse one extracted file instead of rewriting it.
func TestMaterializeModuleIdempotent(t *testing.T) {
	dir := t.TempDir()
	data := []byte("stable module bytes")

	first, err := materializeModule(dir, data)
	if err != nil {
		t.Fatalf("first materializeModule: %v", err)
	}
	second, err := materializeModule(dir, data)
	if err != nil {
		t.Fatalf("second materializeModule: %v", err)
	}
	if first != second {
		t.Fatalf("non-idempotent path: %q != %q", first, second)
	}
	got, err := os.ReadFile(second)
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("content not intact after second call (err=%v)", err)
	}
}

// TestMaterializeModuleContentAddressed asserts different bytes materialize to
// different paths (so a version bump self-invalidates) while identical bytes
// share one path (so distinct processes converge on the same cache file).
func TestMaterializeModuleContentAddressed(t *testing.T) {
	dir := t.TempDir()

	a1, err := materializeModule(dir, []byte("module version A"))
	if err != nil {
		t.Fatalf("materializeModule A: %v", err)
	}
	a2, err := materializeModule(dir, []byte("module version A"))
	if err != nil {
		t.Fatalf("materializeModule A again: %v", err)
	}
	b, err := materializeModule(dir, []byte("module version B"))
	if err != nil {
		t.Fatalf("materializeModule B: %v", err)
	}
	if a1 != a2 {
		t.Fatalf("same content gave different paths: %q vs %q", a1, a2)
	}
	if a1 == b {
		t.Fatalf("different content gave same path: %q", a1)
	}
}

// TestMaterializeModuleRejectsEmpty asserts empty data is an error rather than
// producing an empty, unloadable file.
func TestMaterializeModuleRejectsEmpty(t *testing.T) {
	if _, err := materializeModule(t.TempDir(), nil); err == nil {
		t.Fatal("expected an error for empty module data")
	}
}

// TestExtractEmbeddedModuleNotCompiledIn asserts that, in a binary built WITHOUT
// the wolfpkcs11_embed tag (the default test build), extracting the embedded
// module fails with an actionable error naming the build tag rather than
// silently producing nothing. Extraction happens at the load boundary (Open),
// so this is where a "not compiled in" request surfaces.
func TestExtractEmbeddedModuleNotCompiledIn(t *testing.T) {
	if embeddedModuleAvailable {
		t.Skip("binary built with wolfpkcs11_embed; module is present")
	}
	_, err := extractEmbeddedModule()
	if err == nil {
		t.Fatal("expected an error extracting the embedded module without the build tag")
	}
	if !strings.Contains(err.Error(), "wolfpkcs11_embed") {
		t.Fatalf("error should name the build tag, got: %v", err)
	}
}

// TestAppendEmbeddedOptionWhenAvailable asserts the built-in module is surfaced
// as a discovered option (Source "embedded", Path the sentinel) so it appears in
// `pkcs11 list` and selection like any other found module, appended after the
// real modules (a plugged-in token stays the default).
func TestAppendEmbeddedOptionWhenAvailable(t *testing.T) {
	base := []DiscoveredModule{{Path: "/usr/lib/opensc-pkcs11.so", Label: "opensc", Source: "path"}}
	got := appendEmbeddedOption(base, true)
	if len(got) != len(base)+1 {
		t.Fatalf("expected one appended entry, got %d from %d", len(got), len(base))
	}
	if got[0].Path != base[0].Path {
		t.Fatalf("real modules must stay first; got[0]=%+v", got[0])
	}
	last := got[len(got)-1]
	if last.Path != embeddedModuleSentinel || last.Source != "embedded" || last.Label == "" {
		t.Fatalf("appended entry = %+v, want labeled embedded sentinel", last)
	}
}

// TestAppendEmbeddedOptionWhenUnavailable asserts nothing is appended when no
// module is compiled in, so a tag-free build lists only real modules.
func TestAppendEmbeddedOptionWhenUnavailable(t *testing.T) {
	base := []DiscoveredModule{{Path: "/x.so"}}
	if got := appendEmbeddedOption(base, false); len(got) != len(base) {
		t.Fatalf("expected no change, got %d from %d", len(got), len(base))
	}
}
