//go:build !pkcs11 && !tpm_static

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
// not requested. pkcs11OptsFromFlags now only CAPTURES the raw flags (no longer
// resolves them), so asking for --pkcs11 no longer errors there; the deeper
// module/URI resolution stubbed out in this build (resolveEnrollTarget in
// pkcs11_stub.go, real in the tag-gated pkcs11.go) is reached lazily by
// ensurePKCS11MachineInitialized's enroll branch. This test drives that path:
// with an isolated (empty) NVOLT config the machine reads as uninitialized, so
// ensurePKCS11MachineInitialized enrolls, hits the stub, and surfaces
// errNoPKCS11 instead of silently proceeding.
func TestPKCS11UnsupportedInDefaultBuild(t *testing.T) {
	// Isolated, empty config dir -> no machine identity -> enroll branch.
	t.Setenv("NVOLT_CONFIG", t.TempDir())

	cmd := &cobra.Command{}
	addPKCS11EnrollFlags(cmd)
	if err := cmd.Flags().Set("pkcs11", "true"); err != nil {
		t.Fatalf("set --pkcs11: %v", err)
	}

	opts, err := pkcs11OptsFromFlags(cmd)
	if err != nil {
		t.Fatalf("pkcs11OptsFromFlags: unexpected error %v", err)
	}
	if opts == nil {
		t.Fatal("pkcs11OptsFromFlags: want non-nil opts when --pkcs11 is set")
	}

	err = ensurePKCS11MachineInitialized(opts)
	if err == nil || !strings.Contains(err.Error(), "not built with PKCS#11") {
		t.Fatalf("want 'not built with PKCS#11' error, got %v", err)
	}
}
