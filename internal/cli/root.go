package cli

import (
	"github.com/iluxav/nvolt/internal/ui"
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
