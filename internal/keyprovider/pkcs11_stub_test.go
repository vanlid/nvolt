//go:build !pkcs11 && !wolfpkcs11_static

package keyprovider

import (
	"strings"
	"testing"

	"github.com/iluxav/nvolt/pkg/types"
)

// TestPKCS11KeySourceUnsupportedInDefaultBuild asserts a machine recorded with
// a pkcs11 key source fails clearly (not a panic) in the software-only
// build. loadPKCS11Decrypter is the real dispatch target that
// provider.go's LoadDecrypter switches to on src.Source == "pkcs11"; in the
// default (tag-off) build it must be the stub from pkcs11_stub.go.
func TestPKCS11KeySourceUnsupportedInDefaultBuild(t *testing.T) {
	_, _, err := loadPKCS11Decrypter(&types.KeySource{Source: "pkcs11"})
	if err == nil || !strings.Contains(err.Error(), "not built with PKCS#11") {
		t.Fatalf("want 'not built with PKCS#11' error, got %v", err)
	}
}
