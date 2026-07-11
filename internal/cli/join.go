package cli

import (
	"github.com/spf13/cobra"
)

var joinCmd = &cobra.Command{
	Use:   "join [org/repo]",
	Short: "Join an existing vault",
	Long: `Register this machine to an existing nvolt vault.

For local mode (vault in current directory):
  nvolt join

For global mode (shared vault repository):
  nvolt join org/repo
  nvolt join --repo org/repo

This command:
1. Generates a keypair for this machine (if not already present)
2. Registers the machine's public key to the vault
3. In global mode: clones the repository to ~/.nvolt/orgs/org/repo

After joining, you'll need someone with push access to grant you
access to specific environments using:
  nvolt machine grant <your-machine-id> -e <environment>`,
	Args: cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		// Get repo from flag or positional argument
		repo, _ := cmd.Flags().GetString("repo")

		// If positional arg provided, use it as repo
		if len(args) > 0 {
			repo = args[0]
		}

		opts, err := pkcs11OptsFromFlags(cmd)
		if err != nil {
			return err
		}

		// Call the same init logic
		return runInit(repo, opts)
	},
}

func init() {
	joinCmd.Flags().StringP("repo", "r", "", "Git repository URL (org/repo format)")
	addPKCS11EnrollFlags(joinCmd)
	rootCmd.AddCommand(joinCmd)
}
