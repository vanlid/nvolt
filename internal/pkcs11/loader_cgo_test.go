//go:build tpm_static && !pkcs11

package pkcs11

import "testing"

// TestCgoOpenBuiltin asserts the statically-linked module opens and exposes a
// function list without dlopen. C_Initialize failing for lack of a TPM is fine;
// what matters is that Open returns a usable Module.
func TestCgoOpenBuiltin(t *testing.T) {
	m, err := Open("builtin")
	if err != nil {
		t.Fatalf("Open(builtin): %v", err)
	}
	defer m.Close()
	if m.fnList == nil {
		t.Fatal("nil function list from statically-linked C_GetFunctionList")
	}
}
