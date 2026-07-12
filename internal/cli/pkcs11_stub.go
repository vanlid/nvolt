//go:build !pkcs11

package cli

import (
	"crypto/rsa"
	"errors"

	"github.com/iluxav/nvolt/internal/vault"
	"github.com/spf13/cobra"
)

// errNoPKCS11 is returned by every PKCS#11 entry point in a build compiled
// without a PKCS#11 loader (the default fully-static binary). When this machine
// already has an identity, it offers both ways out — `rebind` to a software key
// (doable with this binary) or a build with PKCS#11 support. Before any identity
// exists (e.g. `nvolt pkcs11 list`, `init --pkcs11`) the rebind advice would be
// meaningless, so it is dropped.
func errNoPKCS11() error {
	const base = "this nvolt was not built with PKCS#11 support"
	if homePaths, err := vault.GetHomePaths(); err == nil && vault.FileExists(homePaths.MachineInfo) {
		return errors.New(base + "; use rebind to switch config to using a software key or use a build with PKCS#11 support")
	}
	return errors.New(base + "; use a build with PKCS#11 support")
}

// resolveEnrollTarget is the default build's stub for the real pkcs11.go
// helper of the same name: init/join/rebind/machine all call it to resolve
// the module/URI to enroll or rebind against, but with no PKCS#11 loader
// compiled in there is nothing to resolve.
func resolveEnrollTarget(_, _ string) (module, uri string, err error) {
	return "", "", errNoPKCS11()
}

// enrollPKCS11Machine is the default build's stub for the real pkcs11.go
// function: machine_setup.go's ensurePKCS11MachineInitialized calls it to
// enroll an on-card key as this machine's identity.
func enrollPKCS11Machine(_, _, _ string) error {
	return errNoPKCS11()
}

// ReadTokenPublicKey is the default build's stub for the real pkcs11.go
// function: machine.go's machineAddPublicKey calls it for `machine add
// --pkcs11`.
func ReadTokenPublicKey(_, _ string) (*rsa.PublicKey, error) {
	return nil, errNoPKCS11()
}

// pkcs11Cmd is the default build's stub for the real `nvolt pkcs11` command
// tree (list/generate/import) defined in pkcs11.go under the pkcs11 tag. It is
// registered so the software-only binary still lists `pkcs11` in --help, flagged
// as unavailable in this build — mirroring how the --pkcs11 flags on
// init/join/rebind/machine add stay visible here. Invoking it returns
// errNoPKCS11() ("not built with PKCS#11 support") instead of cobra's bare
// "unknown command "pkcs11"". DisableFlagParsing routes any real subcommand or
// flag (list, generate --token, import --privkey, ...) straight to RunE rather
// than tripping an "unknown flag" error first.
var pkcs11Cmd = &cobra.Command{
	Use:                "pkcs11",
	Short:              "Interact with PKCS#11 hardware tokens (unavailable in this build)",
	DisableFlagParsing: true,
	RunE: func(_ *cobra.Command, _ []string) error {
		return errNoPKCS11()
	},
}

func init() {
	rootCmd.AddCommand(pkcs11Cmd)
}
