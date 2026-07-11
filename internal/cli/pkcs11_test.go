package cli

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/iluxav/nvolt/internal/hsmtest"
	"github.com/iluxav/nvolt/internal/ui"
	"github.com/iluxav/nvolt/internal/vault"
	"github.com/iluxav/nvolt/pkg/types"
)

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

// captureStdout redirects os.Stdout for the duration of f, returning whatever
// was written along with f's error. It also redirects the ui package's
// logger output (which caches os.Stdout at init time rather than reading the
// global var on every call), so ui.Info/ui.Section/etc. are captured too.
func captureStdout(f func() error) (string, error) {
	orig := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		return "", err
	}
	os.Stdout = w
	ui.SetOutput(w)
	defer func() {
		os.Stdout = orig
		ui.SetOutput(orig)
	}()

	fnErr := f()

	w.Close()
	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)
	return buf.String(), fnErr
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

// Module resolution (flag -> NVOLT_PKCS11_MODULE -> autodetect -> not-found
// error) is covered by pkcs11.ResolveModulePath's unit tests in
// internal/pkcs11/autodetect_test.go, so there is no CLI-level "requires
// module" test here: with autodetection, an empty --module is no longer an
// error when a module can be resolved from the environment or common paths.

// TestUseEnrollsPKCS11Machine drives runPKCS11Use (the pkcs11 use command's
// RunE body) against a real SoftHSM fixture token (provisioned in-code by
// internal/hsmtest) and asserts the resulting machine-info.json records the
// on-card key as this machine's identity. Skipped unless
// NVOLT_TEST_PKCS11_MODULE is set.
func TestUseEnrollsPKCS11Machine(t *testing.T) {
	mod := hsmtest.Provision(t)
	t.Setenv("HOME", t.TempDir())
	t.Setenv("NVOLT_PKCS11_PIN", "1234")

	if _, err := captureStdout(func() error {
		return runPKCS11Use(mod, "pkcs11:token=nvolt-test;id=%01;type=private", "env", false)
	}); err != nil {
		t.Fatal(err)
	}

	mi := readMachineInfo(t)
	if mi.KeySource == nil || mi.KeySource.Source != "pkcs11" {
		t.Fatalf("not enrolled: %+v", mi.KeySource)
	}
	if mi.PublicKey == "" || mi.Fingerprint == "" {
		t.Fatal("missing pub/fingerprint")
	}
}

// TestUseRefusesToOverwriteWithoutForce proves runPKCS11Use guards against
// clobbering an already-initialized machine identity unless --force is set.
func TestUseRefusesToOverwriteWithoutForce(t *testing.T) {
	mod := hsmtest.Provision(t)
	t.Setenv("HOME", t.TempDir())
	t.Setenv("NVOLT_PKCS11_PIN", "1234")

	uri := "pkcs11:token=nvolt-test;id=%01;type=private"
	if _, err := captureStdout(func() error {
		return runPKCS11Use(mod, uri, "env", false)
	}); err != nil {
		t.Fatal(err)
	}

	out, err := captureStdout(func() error {
		return runPKCS11Use(mod, uri, "env", false)
	})
	if err == nil {
		t.Fatalf("expected error re-enrolling without --force, got output:\n%s", out)
	}

	if _, err := captureStdout(func() error {
		return runPKCS11Use(mod, uri, "env", true)
	}); err != nil {
		t.Fatalf("expected --force to allow re-enroll, got: %v", err)
	}
}

// TestUseForceOverSoftwareMachineRemovesPrivateKey proves that --force
// re-enrolling a PKCS#11 identity over an EXISTING software-backed machine
// removes the now-orphaned software private_key.pem (Fix 3: a lingering
// plaintext key on disk after moving identity to hardware is a security
// hygiene bug). It also exercises the literal-URI banner fix (Fix 1) via
// percentEscapeForUI below.
func TestUseForceOverSoftwareMachineRemovesPrivateKey(t *testing.T) {
	mod := hsmtest.Provision(t)
	t.Setenv("HOME", t.TempDir())
	t.Setenv("NVOLT_PKCS11_PIN", "1234")

	// Start from a SOFTWARE machine identity: InitializeMachine writes
	// private_key.pem + machine-info.json.
	if _, err := vault.InitializeMachine(""); err != nil {
		t.Fatalf("InitializeMachine: %v", err)
	}
	homePaths, err := vault.GetHomePaths()
	if err != nil {
		t.Fatal(err)
	}
	if !vault.FileExists(homePaths.PrivateKey) {
		t.Fatalf("expected software private key at %s after InitializeMachine", homePaths.PrivateKey)
	}

	uri := "pkcs11:token=nvolt-test;id=%01;type=private"
	out, err := captureStdout(func() error {
		return runPKCS11Use(mod, uri, "env", true)
	})
	if err != nil {
		t.Fatalf("runPKCS11Use --force over software machine: %v", err)
	}

	// (a) machine-info now reflects the pkcs11 identity.
	mi := readMachineInfo(t)
	if mi.KeySource == nil || mi.KeySource.Source != "pkcs11" {
		t.Fatalf("expected key_source.source=pkcs11 after --force enroll, got: %+v", mi.KeySource)
	}

	// (b) the orphaned software private key must be gone.
	if vault.FileExists(homePaths.PrivateKey) {
		t.Fatalf("expected orphaned software private key %s to be removed after PKCS#11 --force enroll", homePaths.PrivateKey)
	}

	// Display fix (Fix 1): the banner should contain the literal URI,
	// including the literal "id=%01", not a corrupted "%!" sequence.
	if !strings.Contains(out, "id=%01") {
		t.Fatalf("expected banner to contain literal URI %q, got:\n%s", uri, out)
	}
	if strings.Contains(out, "%!") {
		t.Fatalf("banner shows a corrupted format-verb artifact (%%!), got:\n%s", out)
	}
}

// TestPercentEscapeSurvivesUIDoublePass unit-tests, in isolation from the
// PKCS#11 hardware path, that strings.ReplaceAll(uri, "%", "%%") is exactly
// the escaping needed for a URI to render literally through
// ui.PrintKeyValue -> ui.Info's Sprintf-then-Fprintf double pass (Fix 1).
func TestPercentEscapeSurvivesUIDoublePass(t *testing.T) {
	uri := "pkcs11:token=nvolt-test;id=%01;type=private"
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
