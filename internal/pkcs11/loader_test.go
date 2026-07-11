package pkcs11

import (
	"testing"

	"github.com/iluxav/nvolt/internal/hsmtest"
)

// testModulePath provisions the shared SoftHSM fixture token (see
// internal/hsmtest) and returns the PKCS#11 module path, skipping the test
// cleanly when PKCS#11 integration tests aren't configured/available.
func testModulePath(t *testing.T) string {
	return hsmtest.Provision(t)
}

func TestOpenReturnsModuleWithFunctionList(t *testing.T) {
	m, err := Open(testModulePath(t))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer m.Close()
	if m.fnList == nil {
		t.Fatal("expected non-nil CK_FUNCTION_LIST pointer")
	}
}
