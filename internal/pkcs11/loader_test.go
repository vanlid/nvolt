package pkcs11

import (
	"os"
	"testing"
)

func testModulePath(t *testing.T) string {
	p := os.Getenv("NVOLT_TEST_PKCS11_MODULE")
	if p == "" {
		t.Skip("set NVOLT_TEST_PKCS11_MODULE to run PKCS#11 integration tests")
	}
	return p
}

func TestOpenReturnsModuleWithFunctionList(t *testing.T) {
	m, err := Open(testModulePath(t))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer m.Close()
	if m.fnList == 0 {
		t.Fatal("expected non-nil CK_FUNCTION_LIST pointer")
	}
}
