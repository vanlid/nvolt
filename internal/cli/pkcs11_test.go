package cli

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/iluxav/nvolt/internal/ui"
)

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
