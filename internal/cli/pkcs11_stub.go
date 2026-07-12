//go:build !pkcs11

package cli

import (
	"crypto/rsa"
	"errors"

	"github.com/spf13/cobra"
)

// errNoPKCS11 is returned by every PKCS#11 entry point in a build compiled
// without a PKCS#11 loader (the default fully-static binary). Use the dynamic
// `-tags pkcs11` build (or the static `nvolt-tpm` build) for hardware keys.
var errNoPKCS11 = errors.New("this nvolt was not built with PKCS#11 support; use the pkcs11-enabled build for hardware/TPM keys")

// resolveEnrollTarget is the default build's stub for the real pkcs11.go
// helper of the same name: init/join/rebind/machine all call it to resolve
// the module/URI to enroll or rebind against, but with no PKCS#11 loader
// compiled in there is nothing to resolve.
func resolveEnrollTarget(_, _ string) (module, uri string, err error) {
	return "", "", errNoPKCS11
}

// enrollPKCS11Machine is the default build's stub for the real pkcs11.go
// function: machine_setup.go's ensurePKCS11MachineInitialized calls it to
// enroll an on-card key as this machine's identity.
func enrollPKCS11Machine(_, _, _ string) error {
	return errNoPKCS11
}

// ReadTokenPublicKey is the default build's stub for the real pkcs11.go
// function: machine.go's machineAddPublicKey calls it for `machine add
// --pkcs11`.
func ReadTokenPublicKey(_, _ string) (*rsa.PublicKey, error) {
	return nil, errNoPKCS11
}

// pkcs11Cmd is the default build's stub for the real `nvolt pkcs11` command
// tree (list/generate/import) defined in pkcs11.go under the pkcs11 tag. It is
// registered so the software-only binary still lists `pkcs11` in --help, flagged
// as unavailable in this build — mirroring how the --pkcs11 flags on
// init/join/rebind/machine add stay visible here. Invoking it returns
// errNoPKCS11, whose message names the fix (use the pkcs11-enabled build), so
// the Short need not repeat it. DisableFlagParsing routes any real subcommand or
// flag (list, generate --token, import --privkey, ...) straight to RunE rather
// than tripping an "unknown flag" error first.
var pkcs11Cmd = &cobra.Command{
	Use:                "pkcs11",
	Short:              "Interact with PKCS#11 hardware tokens (unavailable in this build)",
	DisableFlagParsing: true,
	RunE: func(_ *cobra.Command, _ []string) error {
		return errNoPKCS11
	},
}

func init() {
	rootCmd.AddCommand(pkcs11Cmd)
}
