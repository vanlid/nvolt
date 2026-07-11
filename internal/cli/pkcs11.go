package cli

import (
	"fmt"
	"os"

	"github.com/iluxav/nvolt/internal/pkcs11"
	"github.com/iluxav/nvolt/internal/ui"
	"github.com/spf13/cobra"
)

var pkcs11Module string

var pkcs11Cmd = &cobra.Command{
	Use:   "pkcs11",
	Short: "Interact with PKCS#11 hardware tokens (YubiKey, SoftHSM, etc.)",
	Long: `Discover and use RSA keys stored on PKCS#11 tokens such as a YubiKey
or SoftHSM, via a PKCS#11 module (.so).`,
}

var pkcs11ListCmd = &cobra.Command{
	Use:   "list",
	Short: "List RSA keys visible on a PKCS#11 token",
	Long: `Enumerate tokens and RSA keys visible through a PKCS#11 module.

Discovery does not log in, so it reports whatever RSA key objects the token
exposes without a PIN.

Example:
  nvolt pkcs11 list --module /usr/lib/softhsm/libsofthsm2.so`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runPKCS11List(pkcs11Module)
	},
}

func runPKCS11List(module string) error {
	if module == "" {
		return fmt.Errorf("no PKCS#11 module specified; use --module or set NVOLT_PKCS11_MODULE")
	}

	keys, err := pkcs11.ListRSAKeys(module)
	if err != nil {
		return fmt.Errorf("failed to list PKCS#11 keys: %w", err)
	}

	if len(keys) == 0 {
		ui.Warning("No RSA keys found on module %s", module)
		return nil
	}

	ui.Section(fmt.Sprintf("RSA keys (%d):", len(keys)))
	for _, k := range keys {
		ui.PrintKeyValue("  Token", ui.Cyan(k.TokenLabel))
		ui.PrintKeyValue("  Label", k.Label)
		ui.PrintKeyValue("  ID", fmt.Sprintf("%x", k.ID))
		ui.PrintKeyValue("  Bits", fmt.Sprintf("%d", k.Bits))
		fmt.Println()
	}

	return nil
}

func init() {
	pkcs11Cmd.AddCommand(pkcs11ListCmd)
	pkcs11ListCmd.Flags().StringVar(&pkcs11Module, "module", os.Getenv("NVOLT_PKCS11_MODULE"), "Path to PKCS#11 module (.so)")

	rootCmd.AddCommand(pkcs11Cmd)
}
