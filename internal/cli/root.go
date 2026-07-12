package cli

import (
	"os"
	"path/filepath"

	"github.com/iluxav/nvolt/internal/ui"
	"github.com/iluxav/nvolt/internal/vault"
	"github.com/spf13/cobra"
)

var (
	version = "dev"
	verbose bool
	debug   bool
	quiet   bool
	noColor bool
)

var rootCmd = &cobra.Command{
	Use:   "nvolt",
	Short: "nvolt - GitHub-native, Zero-Trust encrypted environment variable manager",
	Long: `nvolt is a Zero-Trust CLI for managing encrypted environment variables
without a centralized backend, login, or organization model.

All data lives in Git repositories, with encryption/decryption happening
locally using per-machine keypairs. Access control is cryptographically
enforced through wrapped key files.`,
	Version: version,
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		// Disable colors if requested
		if noColor {
			ui.SetColorsEnabled(false)
		}

		// Set log level based on flags
		if debug {
			ui.SetLevel(ui.LevelDebug)
		} else if verbose {
			ui.SetLevel(ui.LevelVerbose)
		} else if quiet {
			ui.SetLevel(ui.LevelError)
		} else {
			ui.SetLevel(ui.LevelInfo)
		}

		// The embedded wolfPKCS11 TPM module prints its device caps banner
		// (manufacturer, firmware, FIPS/CC-EAL) on C_Initialize only when
		// NVOLT_TPM_CAPS is set — build/pkcs11/build-module.sh gates the
		// otherwise-unconditional upstream printf behind it. Surface that detail
		// whenever the user asked for verbose/debug output. Only ever set it
		// (never unset), and never override an operator-provided value.
		if (debug || verbose) && os.Getenv("NVOLT_TPM_CAPS") == "" {
			_ = os.Setenv("NVOLT_TPM_CAPS", "1")
		}

		// Point the embedded wolfPKCS11 module's filesystem token store at
		// nvolt's own config dir (respecting NVOLT_CONFIG via GetHomePaths),
		// unless the operator set WOLFPKCS11_TOKEN_PATH explicitly. Required on
		// Windows: wolfPKCS11's built-in fallback getenv's a literal "%APPDIR%"
		// (a cmd.exe expansion string, not a real variable name) which never
		// resolves, so without this the store path is unset and C_Initialize
		// can't create its token store. Only TPM-wrapped key blobs land here;
		// the private keys never leave the TPM.
		if os.Getenv("WOLFPKCS11_TOKEN_PATH") == "" {
			if hp, err := vault.GetHomePaths(); err == nil {
				_ = os.Setenv("WOLFPKCS11_TOKEN_PATH", filepath.Join(hp.Root, "pkcs11"))
			}
		}
	},
	Run: func(cmd *cobra.Command, args []string) {
		// Show logo when running without subcommand
		ui.PrintLogoWithVersion(version)
		cmd.Help()
	},
}

// Execute runs the root command.
//
// SilenceErrors/SilenceUsage are set so a failing command prints its error
// exactly once (main() does that) rather than twice, and so a runtime failure
// doesn't dump the full flag usage — that's only noise for errors like a wrong
// PIN or an unsupported operation.
func Execute() error {
	rootCmd.SilenceErrors = true
	rootCmd.SilenceUsage = true
	return rootCmd.Execute()
}

func init() {
	// Global flags
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Enable verbose output")
	rootCmd.PersistentFlags().BoolVar(&debug, "debug", false, "Enable debug output (includes verbose)")
	rootCmd.PersistentFlags().BoolVarP(&quiet, "quiet", "q", false, "Suppress all output except errors")
	rootCmd.PersistentFlags().BoolVar(&noColor, "no-color", false, "Disable colored output")

	// Custom version template with logo
	rootCmd.SetVersionTemplate(`{{with .Name}}{{printf "%s " .}}{{end}}{{printf "%s" .Version}}
`)

	// Override version command to show logo
	versionCmd := &cobra.Command{
		Use:   "version",
		Short: "Print the version number",
		Run: func(cmd *cobra.Command, args []string) {
			ui.PrintLogoWithVersion(version)
		},
	}
	rootCmd.AddCommand(versionCmd)
}
