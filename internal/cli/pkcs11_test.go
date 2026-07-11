package cli

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"

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
// RunE body) against a real SoftHSM fixture token and asserts the fixture
// key label appears in the rendered output. Skipped unless
// NVOLT_TEST_PKCS11_MODULE is set (see scripts/test-softhsm-setup.sh).
func TestPKCS11ListShowsKeys(t *testing.T) {
	mod := os.Getenv("NVOLT_TEST_PKCS11_MODULE")
	if mod == "" {
		t.Skip("set NVOLT_TEST_PKCS11_MODULE to run PKCS#11 CLI integration test")
	}

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

func TestPKCS11ListRequiresModule(t *testing.T) {
	out, err := captureStdout(func() error {
		return runPKCS11List("")
	})
	if err == nil {
		t.Fatalf("expected error for empty module, got output:\n%s", out)
	}
}

// TestUseEnrollsPKCS11Machine drives runPKCS11Use (the pkcs11 use command's
// RunE body) against a real SoftHSM fixture token and asserts the resulting
// machine-info.json records the on-card key as this machine's identity.
// Skipped unless NVOLT_TEST_PKCS11_MODULE is set (see
// scripts/test-softhsm-setup.sh).
func TestUseEnrollsPKCS11Machine(t *testing.T) {
	mod := os.Getenv("NVOLT_TEST_PKCS11_MODULE")
	if mod == "" {
		t.Skip("set NVOLT_TEST_PKCS11_MODULE to run PKCS#11 CLI integration test")
	}
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
	mod := os.Getenv("NVOLT_TEST_PKCS11_MODULE")
	if mod == "" {
		t.Skip("set NVOLT_TEST_PKCS11_MODULE to run PKCS#11 CLI integration test")
	}
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
