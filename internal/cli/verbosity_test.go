//go:build pkcs11 || tpm_static

package cli

import (
	"crypto/rand"
	"crypto/rsa"
	"os"
	"path/filepath"
	"strings"
	"testing"

	nvcrypto "github.com/iluxav/nvolt/internal/crypto"
	"github.com/iluxav/nvolt/internal/hsmtest"
	"github.com/iluxav/nvolt/internal/pkcs11"
	"github.com/iluxav/nvolt/internal/ui"
	"github.com/iluxav/nvolt/internal/vault"
)

// TestPkcs11ModuleListingDefaultOmitsPathSource proves printModuleListing's
// concise Info summary shows only the user-facing Name (never the technical
// Label, filesystem Path, or discovery Source), and that the technical Label,
// Path and Source all appear once the level is raised to Verbose. Uses a
// synthetic pkcs11.DiscoveredModule, so no SoftHSM fixture is required.
func TestPkcs11ModuleListingDefaultOmitsPathSource(t *testing.T) {
	ui.SetLevel(ui.LevelInfo)
	defer ui.SetLevel(ui.LevelInfo)

	mod := pkcs11.DiscoveredModule{
		Path:   "/usr/lib/softhsm/libsofthsm2.so",
		Name:   "SoftHSM",
		Label:  "libsofthsm2 (technical)",
		Source: "path",
	}

	out, err := captureStdout(func() error {
		printModuleListing(mod)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, ".so") {
		t.Fatalf("default (Info) module listing leaked the module path:\n%s", out)
	}
	if strings.Contains(out, "technical") {
		t.Fatalf("default (Info) module listing leaked the technical Label:\n%s", out)
	}
	if !strings.Contains(out, "SoftHSM") {
		t.Fatalf("expected the concise module Name in default output:\n%s", out)
	}

	ui.SetLevel(ui.LevelVerbose)
	vout, err := captureStdout(func() error {
		printModuleListing(mod)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(vout, ".so") {
		t.Fatalf("expected the module path at Verbose level:\n%s", vout)
	}
	if !strings.Contains(vout, "technical") {
		t.Fatalf("expected the technical module Label at Verbose level:\n%s", vout)
	}
	if !strings.Contains(vout, "path") {
		t.Fatalf("expected the module source at Verbose level:\n%s", vout)
	}
}

// TestPkcs11ListDefaultOmitsKeyIDAndLabel drives runPKCS11List (the pkcs11
// list command's RunE body) against a real SoftHSM fixture token
// (hsmtest.Provision) and proves the default (Info) output shows only the
// concise "RSA-<bits>" summary per key -- never the key's raw ID or full
// Label -- while Verbose shows both. Skipped unless NVOLT_TEST_PKCS11_MODULE
// is set.
func TestPkcs11ListDefaultOmitsKeyIDAndLabel(t *testing.T) {
	mod := hsmtest.Provision(t)

	ui.SetLevel(ui.LevelInfo)
	defer ui.SetLevel(ui.LevelInfo)
	out, err := captureStdout(func() error { return runPKCS11List(mod) })
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "ID:") {
		t.Fatalf("default (Info) list output leaked the key ID:\n%s", out)
	}
	if strings.Contains(out, "Label: "+hsmtest.KeyLabel) {
		t.Fatalf("default (Info) list output leaked the key label:\n%s", out)
	}
	if !strings.Contains(out, "RSA-2048") {
		t.Fatalf("expected the concise RSA-2048 summary in default output:\n%s", out)
	}

	ui.SetLevel(ui.LevelVerbose)
	vout, err := captureStdout(func() error { return runPKCS11List(mod) })
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(vout, "ID:") {
		t.Fatalf("expected the key ID at Verbose level:\n%s", vout)
	}
	if !strings.Contains(vout, hsmtest.KeyLabel) {
		t.Fatalf("expected the key label at Verbose level:\n%s", vout)
	}
}

// TestEnrollPKCS11MachineVerboseShowsModuleURIFingerprint proves
// enrollPKCS11Machine's default (Info) output is the concise "now backed by
// the on-card key" success line (plus the always-shown software-key notice
// when applicable), while Fingerprint/Module/URI/OAEP-mode detail only
// appears at Verbose. Skipped unless NVOLT_TEST_PKCS11_MODULE is set.
func TestEnrollPKCS11MachineVerboseShowsModuleURIFingerprint(t *testing.T) {
	mod := hsmtest.Provision(t)
	uri := "pkcs11:token=" + hsmtest.TokenLabel + ";id=%01;type=private"

	// First identity: enroll at the default (Info) level and assert the
	// technical detail (module path, URI) is absent.
	t.Setenv("HOME", t.TempDir())
	t.Setenv("NVOLT_PKCS11_PIN", hsmtest.PIN)

	ui.SetLevel(ui.LevelInfo)
	defer ui.SetLevel(ui.LevelInfo)
	out, err := captureStdout(func() error {
		return enrollPKCS11Machine(mod, uri, "env")
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "now backed by the on-card key") {
		t.Fatalf("expected the concise success line at Info level:\n%s", out)
	}
	if strings.Contains(out, mod) {
		t.Fatalf("default (Info) enroll output leaked the module path:\n%s", out)
	}
	if strings.Contains(out, "id=%01") {
		t.Fatalf("default (Info) enroll output leaked the URI:\n%s", out)
	}

	// Second, separate identity (fresh HOME): enroll at Verbose and assert
	// the same detail now appears, with the literal "%01" surviving intact
	// (single-pass ui.Verbose, no corrupted "%!" artifact and no doubled "%%").
	t.Setenv("HOME", t.TempDir())
	ui.SetLevel(ui.LevelVerbose)
	vout, err := captureStdout(func() error {
		return enrollPKCS11Machine(mod, uri, "env")
	})
	if err != nil {
		t.Fatal(err)
	}
	mi := readMachineInfo(t)
	if !strings.Contains(vout, mod) {
		t.Fatalf("expected the module path at Verbose level:\n%s", vout)
	}
	if !strings.Contains(vout, "id=%01") {
		t.Fatalf("expected the literal URI at Verbose level:\n%s", vout)
	}
	if strings.Contains(vout, "%!") {
		t.Fatalf("verbose output shows a corrupted format-verb artifact (%%!):\n%s", vout)
	}
	if !strings.Contains(vout, mi.Fingerprint) {
		t.Fatalf("expected the fingerprint at Verbose level:\n%s", vout)
	}
}

// TestPKCS11GenerateShowsChosenKeyAndNextStep drives runPKCS11Generate against
// a real SoftHSM fixture token and proves the default (Info) output tells the
// user exactly which key was created (label + id) and the copy-paste next step
// to adopt it as the machine identity (the whole point of auto-assigning ids),
// while purely technical detail (Bits) stays behind Verbose. Skipped unless
// NVOLT_TEST_PKCS11_MODULE is set.
func TestPKCS11GenerateShowsChosenKeyAndNextStep(t *testing.T) {
	mod := hsmtest.Provision(t)
	t.Setenv("NVOLT_PKCS11_PIN", hsmtest.PIN)

	ui.SetLevel(ui.LevelInfo)
	defer ui.SetLevel(ui.LevelInfo)
	out, err := captureStdout(func() error {
		return runPKCS11Generate(mod, hsmtest.TokenLabel, "gen-key", "05", 2048, "env")
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, hsmtest.TokenLabel) {
		t.Fatalf("expected the success line to name the token at Info level:\n%s", out)
	}
	// The chosen label and id must be visible at the default level — the user
	// needs to know what was created (especially the auto-assigned id).
	if !strings.Contains(out, "label=gen-key") {
		t.Fatalf("expected the chosen key label at Info level:\n%s", out)
	}
	if !strings.Contains(out, "id=05") {
		t.Fatalf("expected the chosen key id at Info level:\n%s", out)
	}
	// The next-step line must give the exact init command with the PKCS#11
	// %-hex id (id 0x05 -> id=%05) so it can be copy-pasted.
	if !strings.Contains(out, "nvolt init --pkcs11") || !strings.Contains(out, "id=%05") {
		t.Fatalf("expected the copy-paste init next-step with id=%%05 at Info level:\n%s", out)
	}
	// Bits is technical detail: Verbose only.
	if strings.Contains(out, "Bits:") {
		t.Fatalf("default (Info) generate output leaked the Bits detail:\n%s", out)
	}

	ui.SetLevel(ui.LevelVerbose)
	vout, err := captureStdout(func() error {
		return runPKCS11Generate(mod, hsmtest.TokenLabel, "gen-key-2", "06", 2048, "env")
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(vout, "gen-key-2") {
		t.Fatalf("expected the key label at Verbose level:\n%s", vout)
	}
	if !strings.Contains(vout, "Bits: 2048") {
		t.Fatalf("expected the key bits at Verbose level:\n%s", vout)
	}
}

// TestPKCS11GenerateAutoAssignsNextFreeID proves that omitting --id makes
// generate pick the lowest unused single-byte CKA_ID on the token. The SoftHSM
// fixture pre-seeds ids 01 and 02, so the first auto-assignment lands on 03.
// Skipped unless NVOLT_TEST_PKCS11_MODULE is set.
func TestPKCS11GenerateAutoAssignsNextFreeID(t *testing.T) {
	mod := hsmtest.Provision(t)
	t.Setenv("NVOLT_PKCS11_PIN", hsmtest.PIN)

	ui.SetLevel(ui.LevelInfo)
	defer ui.SetLevel(ui.LevelInfo)
	out, err := captureStdout(func() error {
		return runPKCS11Generate(mod, hsmtest.TokenLabel, "", "", 2048, "env")
	})
	if err != nil {
		t.Fatal(err)
	}
	// Pre-seeded ids are 01 and 02, so the next free single-byte id is 03, and
	// the label defaults to "nvolt".
	if !strings.Contains(out, "id=03") {
		t.Fatalf("expected auto-assigned id 03 (01/02 pre-seeded) at Info level:\n%s", out)
	}
	if !strings.Contains(out, "label=nvolt") {
		t.Fatalf("expected the default label 'nvolt' at Info level:\n%s", out)
	}
	if !strings.Contains(out, "id=%03") {
		t.Fatalf("expected the next-step URI to carry id=%%03:\n%s", out)
	}
}

// TestPKCS11GenerateRejectsDuplicateExplicitID proves that an explicit --id
// colliding with an existing key on the token is rejected (the SoftHSM fixture
// pre-seeds id 01). Skipped unless NVOLT_TEST_PKCS11_MODULE is set.
func TestPKCS11GenerateRejectsDuplicateExplicitID(t *testing.T) {
	mod := hsmtest.Provision(t)
	t.Setenv("NVOLT_PKCS11_PIN", hsmtest.PIN)

	err := runPKCS11Generate(mod, hsmtest.TokenLabel, "dup", "01", 2048, "env")
	if err == nil {
		t.Fatal("expected an error generating a key with an already-used explicit id 01")
	}
	if !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("expected an 'already exists' duplicate-id error, got: %v", err)
	}
}

// TestPKCS11ImportVerboseShowsLabelID drives runPKCS11Import against a real
// SoftHSM fixture token and proves the default (Info) output is the one-line
// success naming the token, while Label/ID detail only appears at Verbose.
// It also pins the %-escaping gotcha: a label containing a literal "%" must
// render literally at Verbose (single-pass Printf), not as a corrupted
// "%!"-style artifact or a doubled "%%".
func TestPKCS11ImportVerboseShowsLabelID(t *testing.T) {
	mod := hsmtest.Provision(t)
	t.Setenv("NVOLT_PKCS11_PIN", hsmtest.PIN)
	dir := t.TempDir()

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pemBytes, err := nvcrypto.EncodePrivateKeyPEM(priv)
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(dir, "k.pem")
	if err := os.WriteFile(keyPath, pemBytes, 0o600); err != nil {
		t.Fatal(err)
	}

	const labelWithPercent = "my%key"

	ui.SetLevel(ui.LevelInfo)
	defer ui.SetLevel(ui.LevelInfo)
	out, err := captureStdout(func() error {
		return runPKCS11Import(mod, hsmtest.TokenLabel, labelWithPercent, "07", keyPath, "env")
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, hsmtest.TokenLabel) {
		t.Fatalf("expected the one-line success to name the token at Info level:\n%s", out)
	}
	if strings.Contains(out, labelWithPercent) {
		t.Fatalf("default (Info) import output leaked the key label:\n%s", out)
	}

	ui.SetLevel(ui.LevelVerbose)
	vout, err := captureStdout(func() error {
		return runPKCS11Import(mod, hsmtest.TokenLabel, labelWithPercent, "08", keyPath, "env")
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(vout, labelWithPercent) {
		t.Fatalf("expected the literal label %q at Verbose level (not corrupted or doubled), got:\n%s", labelWithPercent, vout)
	}
	if strings.Contains(vout, "%!") {
		t.Fatalf("verbose output shows a corrupted format-verb artifact (%%!):\n%s", vout)
	}
	if strings.Contains(vout, "my%%key") {
		t.Fatalf("verbose output doubled the literal %%, got:\n%s", vout)
	}
}

// TestRebindToHardwareVerboseShowsModuleFingerprint drives runRebind's
// --pkcs11 path end-to-end: a software identity is created, its exact
// keypair is imported onto a SoftHSM token (so the token's public key matches
// the identity), then rebind --pkcs11 is driven against that token. It proves
// the default (Info) output is just the "now backed by hardware" line, while
// Module/Fingerprint detail only appears at Verbose.
func TestRebindToHardwareVerboseShowsModuleFingerprint(t *testing.T) {
	mod := hsmtest.Provision(t)
	t.Setenv("HOME", t.TempDir())

	if _, err := vault.InitializeMachine(""); err != nil {
		t.Fatalf("InitializeMachine: %v", err)
	}
	homePaths, err := vault.GetHomePaths()
	if err != nil {
		t.Fatal(err)
	}
	privPEM, err := os.ReadFile(homePaths.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(t.TempDir(), "identity.pem")
	if err := os.WriteFile(keyPath, privPEM, 0o600); err != nil {
		t.Fatal(err)
	}

	t.Setenv("NVOLT_PKCS11_PIN", hsmtest.PIN)
	if err := runPKCS11Import(mod, hsmtest.TokenLabel, "rebind-key", "09", keyPath, "env"); err != nil {
		t.Fatalf("import identity key onto token: %v", err)
	}

	origPKCS11, origSoftware := rebindPKCS11, rebindSoftware
	origModule, origURI, origPinMode, origPrivkey := rebindModule, rebindURI, rebindPinMode, rebindPrivkey
	defer func() {
		rebindPKCS11, rebindSoftware = origPKCS11, origSoftware
		rebindModule, rebindURI, rebindPinMode, rebindPrivkey = origModule, origURI, origPinMode, origPrivkey
	}()

	rebindPKCS11 = true
	rebindSoftware = false
	rebindModule = mod
	rebindURI = "pkcs11:token=" + hsmtest.TokenLabel + ";id=%09;type=private"
	rebindPinMode = "env"
	rebindPrivkey = ""

	ui.SetLevel(ui.LevelInfo)
	defer ui.SetLevel(ui.LevelInfo)
	out, err := captureStdout(runRebind)
	if err != nil {
		t.Fatalf("runRebind: %v\noutput:\n%s", err, out)
	}
	if !strings.Contains(out, "now backed by hardware") {
		t.Fatalf("expected the concise success line at Info level:\n%s", out)
	}
	if strings.Contains(out, mod) {
		t.Fatalf("default (Info) rebind output leaked the module path:\n%s", out)
	}

	ui.SetLevel(ui.LevelVerbose)
	vout, err := captureStdout(runRebind)
	if err != nil {
		t.Fatalf("runRebind (verbose): %v\noutput:\n%s", err, vout)
	}
	if !strings.Contains(vout, mod) {
		t.Fatalf("expected the module path at Verbose level:\n%s", vout)
	}
	if !strings.Contains(vout, "Fingerprint:") {
		t.Fatalf("expected the fingerprint at Verbose level:\n%s", vout)
	}
}

// TestMachineAddExternalSourceVerboseShowsFingerprintSource moved to
// machine_test.go: it exercises runMachineAdd's --pubkey path only (no
// PKCS#11 hardware involved), so it stays covered in the default
// (non-pkcs11) build alongside this file's other tag-gated tests.
