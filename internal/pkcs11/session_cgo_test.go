//go:build tpm_static && !pkcs11

package pkcs11

import (
	"os"
	"testing"
)

// TestCgoListTokens exercises the static loader's token/key enumeration against
// a real or simulated TPM. It is skipped unless NVOLT_TEST_TPM is set, so
// ordinary CI (which has no TPM/swtpm) stays green while still compiling and
// linking the full cgo enumeration path.
func TestCgoListTokens(t *testing.T) {
	if os.Getenv("NVOLT_TEST_TPM") == "" {
		t.Skip("set NVOLT_TEST_TPM to run against a TPM/swtpm")
	}
	toks, err := ListTokensAndKeys("builtin")
	if err != nil {
		t.Fatalf("ListTokensAndKeys: %v", err)
	}
	if len(toks) == 0 {
		t.Fatal("expected at least one token from the TPM")
	}
}
