//go:build pkcs11 || tpm_static

package cli

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	nvcrypto "github.com/iluxav/nvolt/internal/crypto"
	"github.com/iluxav/nvolt/internal/hsmtest"
	"github.com/iluxav/nvolt/internal/keyprovider"
	"github.com/iluxav/nvolt/internal/pkcs11"
	"github.com/iluxav/nvolt/internal/ui"
	"github.com/iluxav/nvolt/internal/vault"
	"github.com/iluxav/nvolt/pkg/types"
)

// wantURI is the fixture SoftHSM token/id URI shared by every test in this
// file that needs a valid PKCS#11 URI for the "nvolt-test" token.
const wantURI = "pkcs11:token=nvolt-test;id=%01;type=private"

// readMachineInfo loads the current (HOME-scoped) machine's machine-info.json,
// failing the test on any error.
func readMachineInfo(t *testing.T) *types.MachineInfo {
	t.Helper()
	homePaths, err := vault.GetHomePaths()
	if err != nil {
		t.Fatal(err)
	}
	mi, err := vault.LoadMachineInfoFromFile(homePaths.MachineInfo)
	if err != nil {
		t.Fatal(err)
	}
	return mi
}

// TestPKCS11ListShowsKeys drives runPKCS11List (the pkcs11 list command's
// RunE body) against a real SoftHSM fixture token (provisioned in-code by
// internal/hsmtest) and asserts the fixture key label appears in the
// rendered output. Skipped unless NVOLT_TEST_PKCS11_MODULE is set.
func TestPKCS11ListShowsKeys(t *testing.T) {
	mod := hsmtest.Provision(t)

	out, err := captureStdout(func() error {
		return runPKCS11List(mod)
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "nvolt-test") {
		t.Fatalf("expected key in output:\n%s", out)
	}
}

// TestPrintTokenListingShowsEmptyTokenWithGenerateHint proves a token with no
// RSA keys yet (e.g. a freshly-provisioned YubiKey's PIV_II slot) still
// renders its label plus a short, actionable hint naming that exact token,
// instead of vanishing from the output the way it did before this change
// (which made a real card indistinguishable from "no card detected").
func TestPrintTokenListingShowsEmptyTokenWithGenerateHint(t *testing.T) {
	out, err := captureStdout(func() error {
		printTokenListing(pkcs11.TokenListing{Label: "PIV_II"}, "embedded")
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "PIV_II") {
		t.Fatalf("expected the empty token's label in output:\n%s", out)
	}
	if !strings.Contains(out, "No RSA key yet") {
		t.Fatalf("expected a 'no RSA key yet' hint in output:\n%s", out)
	}
	if !strings.Contains(out, "nvolt pkcs11 generate --pkcs11-module embedded --token PIV_II") {
		t.Fatalf("expected the generate command naming the token in output:\n%s", out)
	}
}

// TestPrintTokenListingShowsKeysWhenPresent proves a token with keys renders,
// at the default (Info) level, the concise "RSA-<bits>" summary per key and
// never the empty-token hint; the key's full Label/ID are technical detail
// that only appears once the level is raised to Verbose.
func TestPrintTokenListingShowsKeysWhenPresent(t *testing.T) {
	tok := pkcs11.TokenListing{
		Label: "nvolt-test",
		Keys: []pkcs11.KeyInfo{
			{TokenLabel: "nvolt-test", Label: "my-key", ID: []byte{0x01}, Bits: 2048},
		},
	}

	ui.SetLevel(ui.LevelInfo)
	defer ui.SetLevel(ui.LevelInfo)
	out, err := captureStdout(func() error {
		printTokenListing(tok, "embedded")
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "RSA-2048") {
		t.Fatalf("expected the concise RSA-2048 summary in default output:\n%s", out)
	}
	if strings.Contains(out, "my-key") {
		t.Fatalf("did not expect the key label at the default (Info) level:\n%s", out)
	}
	if strings.Contains(out, "No RSA key yet") {
		t.Fatalf("did not expect the empty-token hint when keys are present:\n%s", out)
	}

	ui.SetLevel(ui.LevelVerbose)
	vout, err := captureStdout(func() error {
		printTokenListing(tok, "embedded")
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(vout, "my-key") {
		t.Fatalf("expected the key label at the Verbose level:\n%s", vout)
	}
}

// Module resolution (flag -> NVOLT_PKCS11_MODULE -> autodetect -> not-found
// error) is covered by pkcs11.ResolveModulePath's unit tests in
// internal/pkcs11/autodetect_test.go, so there is no CLI-level "requires
// module" test here: with autodetection, an empty --pkcs11-module is no
// longer an error when a module can be resolved from the environment or
// common paths.

// TestEnrollPKCS11Machine drives enrollPKCS11Machine (the shared enroll body
// used by the --pkcs11 branch of init/join, formerly also `nvolt pkcs11
// use` before that command was removed) against a real SoftHSM fixture token
// (provisioned in-code by internal/hsmtest) and asserts the resulting
// machine-info.json records the on-card key as this machine's identity.
// Skipped unless NVOLT_TEST_PKCS11_MODULE is set.
func TestEnrollPKCS11Machine(t *testing.T) {
	mod := hsmtest.Provision(t)
	t.Setenv("HOME", t.TempDir())
	t.Setenv("NVOLT_PKCS11_PIN", "1234")

	uri := wantURI
	// The URI is technical detail (see verbosity_test.go), shown only at
	// Verbose: raise the level here so this test can still assert on the
	// literal, uncorrupted URI in the enroll banner (Fix 1).
	ui.SetLevel(ui.LevelVerbose)
	defer ui.SetLevel(ui.LevelInfo)
	out, err := captureStdout(func() error {
		return enrollPKCS11Machine(mod, uri, "env")
	})
	if err != nil {
		t.Fatal(err)
	}

	mi := readMachineInfo(t)
	if mi.KeySource == nil || mi.KeySource.Source != "pkcs11" {
		t.Fatalf("not enrolled: %+v", mi.KeySource)
	}
	if mi.PublicKey == "" || mi.Fingerprint == "" {
		t.Fatal("missing pub/fingerprint")
	}

	// The enroll banner must render the literal URI, including "id=%01", not a
	// corrupted format-verb artifact (Fix 1).
	if !strings.Contains(out, "id=%01") {
		t.Fatalf("expected banner to contain literal URI %q, got:\n%s", uri, out)
	}
	if strings.Contains(out, "%!") {
		t.Fatalf("banner shows a corrupted format-verb artifact (%%!), got:\n%s", out)
	}
}

// TestEnrollPKCS11MachineRefusesToOverwriteExistingIdentity proves
// enrollPKCS11Machine never clobbers an already-initialized machine identity.
// Replacing one is a deliberate manual step (remove machine-info.json), not a
// flag: overwriting would orphan every secret wrapped to the current key,
// since the master key is not re-wrapped.
func TestEnrollPKCS11MachineRefusesToOverwriteExistingIdentity(t *testing.T) {
	mod := hsmtest.Provision(t)
	t.Setenv("HOME", t.TempDir())
	t.Setenv("NVOLT_PKCS11_PIN", "1234")

	uri := wantURI
	if _, err := captureStdout(func() error {
		return enrollPKCS11Machine(mod, uri, "env")
	}); err != nil {
		t.Fatal(err)
	}

	out, err := captureStdout(func() error {
		return enrollPKCS11Machine(mod, uri, "env")
	})
	if err == nil {
		t.Fatalf("expected error re-enrolling over an existing identity, got output:\n%s", out)
	}
}

// TestEnrollPKCS11MachineInformsAboutOrphanedSoftwareKeyInsteadOfDeleting
// covers the partial-init state the orphan-cleanup branch in
// enrollPKCS11Machine handles: a stray private_key.pem left on disk (e.g.
// from a half-finished software init) with no machine-info.json yet. Per the
// non-destructive principle nvolt commands share (also followed by `nvolt
// rebind`), enrollPKCS11Machine must never delete that file on the user's
// behalf -- only inform about it -- so after enrolling, the file must still
// exist.
func TestEnrollPKCS11MachineInformsAboutOrphanedSoftwareKeyInsteadOfDeleting(t *testing.T) {
	mod := hsmtest.Provision(t)
	t.Setenv("HOME", t.TempDir())
	t.Setenv("NVOLT_PKCS11_PIN", "1234")

	homePaths, err := vault.GetHomePaths()
	if err != nil {
		t.Fatal(err)
	}
	if err := vault.InitializeHomeDirectory(); err != nil {
		t.Fatal(err)
	}
	if err := vault.WriteFileAtomic(homePaths.PrivateKey, []byte("stray software key"), vault.FilePerm); err != nil {
		t.Fatal(err)
	}

	uri := wantURI
	out, err := captureStdout(func() error {
		return enrollPKCS11Machine(mod, uri, "env")
	})
	if err != nil {
		t.Fatal(err)
	}

	if !vault.FileExists(homePaths.PrivateKey) {
		t.Fatalf("expected the stray software private key at %s to still exist (inform, not delete)", homePaths.PrivateKey)
	}
	if !strings.Contains(out, homePaths.PrivateKey) {
		t.Fatalf("expected enroll output to mention the remaining software key path %s, got:\n%s", homePaths.PrivateKey, out)
	}
}

// TestPercentEscapeSurvivesUIDoublePass unit-tests, in isolation from the
// PKCS#11 hardware path, that strings.ReplaceAll(uri, "%", "%%") is exactly
// the escaping needed for a URI to render literally through
// ui.PrintKeyValue -> ui.Info's Sprintf-then-Fprintf double pass (Fix 1).
func TestPercentEscapeSurvivesUIDoublePass(t *testing.T) {
	uri := wantURI
	escaped := strings.ReplaceAll(uri, "%", "%%")

	out, err := captureStdout(func() error {
		ui.PrintKeyValue("  URI", escaped)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, uri) {
		t.Fatalf("expected literal URI %q in output, got:\n%s", uri, out)
	}
	if strings.Contains(out, "%!") {
		t.Fatalf("escaping did not survive ui's double pass, got:\n%s", out)
	}
}

// TestPKCS11URIRoundTrip builds a pkcs11: URI from a token label and id via
// the wizard's percent-encoding helpers, then parses it the way Enroll does
// (keyprovider.ParsePKCS11URI), asserting the decoded token/id match the
// originals. Covers a plain label, a label needing escaping (";", "%",
// space), and the RFC7512 example from this repo's own docs/tests:
// id=[]byte{0x01} -> "id=%01".
func TestPKCS11URIRoundTrip(t *testing.T) {
	cases := []struct {
		name  string
		token string
		id    []byte
	}{
		{"simple", "nvolt-test", []byte{0x01}},
		{"id needs two digit hex per byte", "yubikey", []byte{0x00, 0x0a, 0xff}},
		{"token needs escaping", "My Token; v2 (100%)", []byte{0x03}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			uri := fmt.Sprintf("pkcs11:token=%s;id=%s;type=private",
				pctEncodePKCS11Attr(tc.token), pctEncodeID(tc.id))

			gotToken, gotID, err := keyprovider.ParsePKCS11URI(uri)
			if err != nil {
				t.Fatalf("ParsePKCS11URI(%q): %v", uri, err)
			}
			if gotToken != tc.token {
				t.Fatalf("token round-trip mismatch: built %q, parsed back %q (uri=%q)", tc.token, gotToken, uri)
			}
			if !bytes.Equal(gotID, tc.id) {
				t.Fatalf("id round-trip mismatch: built %x, parsed back %x (uri=%q)", tc.id, gotID, uri)
			}
		})
	}
}

// TestPctEncodeIDSingleByte pins down the exact example from the task spec:
// id byte 0x01 must render as "%01" (lowercase hex), matching the URIs used
// throughout this repo's own SoftHSM fixtures and docs.
func TestPctEncodeIDSingleByte(t *testing.T) {
	if got := pctEncodeID([]byte{0x01}); got != "%01" {
		t.Fatalf("pctEncodeID([]byte{0x01}) = %q, want %q", got, "%01")
	}
}

// TestResolveEnrollURINonInteractiveErrorsWithoutHanging proves the wizard's
// URI step refuses to prompt when stdin is not a terminal (the normal case
// under `go test`): it must return a clear, actionable error immediately
// instead of blocking on input or silently guessing a key.
func TestResolveEnrollURINonInteractiveErrorsWithoutHanging(t *testing.T) {
	if isInteractive() {
		t.Skip("stdin is a terminal in this environment; non-interactive gating not exercised")
	}
	_, err := resolveEnrollURI("/nonexistent/pkcs11-module.so", nil)
	if err == nil {
		t.Fatal("expected an error when stdin is not a terminal, got nil")
	}
	if !strings.Contains(err.Error(), "not a terminal") {
		t.Fatalf("expected a 'not a terminal' error naming --pkcs11-uri, got: %v", err)
	}
	if !strings.Contains(err.Error(), "--pkcs11-uri") {
		t.Fatalf("expected the error to name --pkcs11-uri as the fix, got: %v", err)
	}
}

// TestPKCS11ImportCreatesUsableKey drives runPKCS11Import (the pkcs11 import
// command's RunE body) against a real SoftHSM fixture token: it writes a
// freshly generated RSA-2048 key to a PEM file, imports it via
// C_CreateObject, and asserts the specific imported key (id 0x09) is
// findable on the token by that id and reports the expected 2048-bit
// modulus, proving the import round-trips through the real PKCS#11 FFI path
// (not just an in-process mock).
//
// This deliberately does not use pkcs11.ListTokensAndKeys: that function
// opens its discovery session without logging in, and ImportRSAPrivateKey
// creates a CKA_PRIVATE=true object with no matching public-key object, so
// on SoftHSM the imported key is invisible pre-login regardless of whether
// the import worked — asserting via ListTokensAndKeys would either be
// vacuously true (satisfied by the two pre-seeded ids 01/02 from
// hsmtest.Provision) or, if scoped to id 0x09, always false. Logging in and
// calling FindRSAPrivateKey(id) instead targets exactly the key this test
// imports, which the pre-seeded fixture keys (ids 01, 02) cannot satisfy.
func TestPKCS11ImportCreatesUsableKey(t *testing.T) {
	mod := hsmtest.Provision(t)
	t.Setenv("NVOLT_PKCS11_PIN", "1234")
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

	id := []byte{0x09}
	if err := runPKCS11Import(mod, "nvolt-test", "imported", "09", keyPath, "env"); err != nil {
		t.Fatalf("import: %v", err)
	}

	// Assert the specific imported key (id 0x09) is present, not merely that
	// the token has *some* key: hsmtest.Provision pre-seeds "nvolt-test" with
	// two RSA keys (id 01, 02) before this test ever runs runPKCS11Import, so
	// a bare "token has keys" check would pass even if the import were a
	// no-op. FindRSAPrivateKey(id) searches by CKA_ID, so ids 01/02 cannot
	// satisfy it.
	m, err := pkcs11.Open(mod)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = m.Close() }()
	sess, err := m.OpenSession("nvolt-test")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sess.Close() }()
	if err := sess.Login("1234"); err != nil {
		t.Fatal(err)
	}
	obj, err := sess.FindRSAPrivateKey(id)
	if err != nil {
		t.Fatalf("imported key (id 0x09) not found on token: %v", err)
	}
	pub, err := sess.RSAPublicKey(obj)
	if err != nil {
		t.Fatalf("RSAPublicKey on imported key: %v", err)
	}
	if pub.N.Cmp(priv.PublicKey.N) != 0 {
		t.Fatalf("imported key modulus mismatch: token key is not the key that was imported")
	}
}

// TestResolveEnrollTargetExplicitFlagsWin proves the fully-explicit
// `--pkcs11-module X --pkcs11-uri Y` path returns exactly those values with no wizard
// involvement (no autodetection, no key listing) regardless of whether
// stdin happens to be a terminal — the non-interactive contract scripts/CI
// depend on.
func TestResolveEnrollTargetExplicitFlagsWin(t *testing.T) {
	const wantModule = "/some/explicit/module.so"

	gotModule, gotURI, err := resolveEnrollTarget(wantModule, wantURI, nil)
	if err != nil {
		t.Fatalf("resolveEnrollTarget with explicit flags: %v", err)
	}
	if gotModule != wantModule {
		t.Fatalf("module = %q, want %q (flag must win outright)", gotModule, wantModule)
	}
	if gotURI != wantURI {
		t.Fatalf("uri = %q, want %q (flag must win outright, no prompting)", gotURI, wantURI)
	}
}
