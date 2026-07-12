//go:build !pkcs11 && !wolfpkcs11_static

package cli

import (
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// TestPKCS11UnsupportedInDefaultBuild asserts the default (static) build
// reports an actionable error when a user asks for --pkcs11, instead of
// silently doing nothing or panicking.
//
// pkcs11OptsFromFlags and addPKCS11EnrollFlags (internal/cli/init.go) are
// real, always-compiled helpers: they register/parse the shared --pkcs11*
// flags in every build (see TestSharedPKCS11FlagsArePrefixed in
// flagname_test.go), so init/join keep working unchanged when --pkcs11 is
// not requested. What this build stubs out (pkcs11_stub.go) is the deeper
// module/URI resolution pkcs11OptsFromFlags delegates to
// (resolveEnrollTarget, defined for real in the tag-gated pkcs11.go), so
// asking for --pkcs11 here surfaces errNoPKCS11 instead of silently
// proceeding. Calling pkcs11OptsFromFlags(nil) directly would panic (it
// calls cmd.Flags()), so this test drives it the way callers really do: a
// *cobra.Command with the shared flags registered and --pkcs11 set.
func TestPKCS11UnsupportedInDefaultBuild(t *testing.T) {
	cmd := &cobra.Command{}
	addPKCS11EnrollFlags(cmd)
	if err := cmd.Flags().Set("pkcs11", "true"); err != nil {
		t.Fatalf("set --pkcs11: %v", err)
	}

	_, err := pkcs11OptsFromFlags(cmd)
	if err == nil || !strings.Contains(err.Error(), "not built with PKCS#11") {
		t.Fatalf("want 'not built with PKCS#11' error, got %v", err)
	}
}
