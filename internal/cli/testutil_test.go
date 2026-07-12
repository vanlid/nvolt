package cli

import (
	"bytes"
	"io"
	"os"

	"github.com/iluxav/nvolt/internal/ui"
)

// captureStdout redirects os.Stdout for the duration of f, returning whatever
// was written along with f's error. It also redirects the ui package's
// logger output (which caches os.Stdout at init time rather than reading the
// global var on every call), so ui.Info/ui.Section/etc. are captured too.
//
// Kept untagged (unlike pkcs11_test.go/verbosity_test.go, which only compile
// under -tags pkcs11) because non-PKCS#11 tests (e.g. machine_test.go's
// --pubkey machine-add coverage) use it too.
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
