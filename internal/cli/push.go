package cli

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"

	"github.com/iluxav/nvolt/internal/config"
	"github.com/iluxav/nvolt/internal/crypto"
	"github.com/iluxav/nvolt/internal/git"
	"github.com/iluxav/nvolt/internal/keyprovider"
	"github.com/iluxav/nvolt/internal/ui"
	"github.com/iluxav/nvolt/internal/vault"
	"github.com/iluxav/nvolt/pkg/types"
	"github.com/spf13/cobra"
)

var pushCmd = &cobra.Command{
	Use:   "push",
	Short: "Encrypt and push secrets to vault",
	Long: `Encrypt secrets from a .env file or command-line and store them in the vault.

Examples:
  nvolt push -f .env
  nvolt push -k FOO=bar -k BAZ=qux
  nvolt push -f .env -k OVERRIDE=value
  nvolt push -f .env.production -e production
  nvolt push -f .env -p myproject -e staging`,
	RunE: func(cmd *cobra.Command, args []string) error {
		envFile, _ := cmd.Flags().GetString("file")
		environment, _ := cmd.Flags().GetString("env")
		project, _ := cmd.Flags().GetString("project")
		keyValues, _ := cmd.Flags().GetStringSlice("key")
		dryRun, _ := cmd.Flags().GetBool("dry-run")

		return runPush(envFile, environment, project, keyValues, dryRun)
	},
}

func runPush(envFile, environment, project string, keyValues []string, dryRun bool) error {
	// Ensure machine is initialized
	if err := EnsureMachineInitialized(); err != nil {
		return err
	}

	if dryRun {
		ui.Warning("[DRY RUN] Simulating push operation")
	} else {
		ui.Step("Pushing secrets to vault")
	}

	// Find vault path
	vaultPath, err := findVaultPath()
	if err != nil {
		return err
	}

	// Determine project name and get vault paths
	if vault.IsGlobalMode(vaultPath) {
		repoPath := vault.GetRepoPathFromVault(vaultPath)

		// Pull latest changes BEFORE doing any work
		ui.Step("Pulling latest changes from repository")
		if err := git.SafePull(repoPath); err != nil {
			return fmt.Errorf("failed to pull latest changes: %w", err)
		}
		ui.Success("Repository up to date")

		// Detect or use provided project name
		if project == "" {
			cwd, err := os.Getwd()
			if err != nil {
				return fmt.Errorf("failed to get current directory: %w", err)
			}
			detectedProject, _, err := config.GetProjectName(cwd, "")
			if err != nil {
				return fmt.Errorf("failed to detect project name. Use -p flag to specify: %w", err)
			}
			project = detectedProject
			ui.PrintDetected("Project", project)
		}
	}

	// Get vault paths with unified logic (projectName is ignored in local mode)
	paths := vault.GetVaultPaths(vaultPath, project)

	// Collect secrets from file and/or command line
	secrets := make(map[string]string)

	// Load from file if specified and exists
	if envFile != "" && vault.FileExists(envFile) {
		fileSecrets, err := vault.ParseEnvFile(envFile)
		if err != nil {
			return fmt.Errorf("failed to parse env file: %w", err)
		}
		ui.Info(fmt.Sprintf("Loaded %d secrets from %s", len(fileSecrets), ui.Cyan(envFile)))
		for k, v := range fileSecrets {
			secrets[k] = v
		}
	} else if envFile != "" && envFile != ".env" {
		// Only error if a specific file was requested
		return fmt.Errorf("file not found: %s", envFile)
	}

	// Add/override with command-line key=value pairs
	if len(keyValues) > 0 {
		kvSecrets, err := vault.ParseKeyValuePairs(keyValues)
		if err != nil {
			return fmt.Errorf("failed to parse key=value pairs: %w", err)
		}
		ui.Info(fmt.Sprintf("Adding %d secrets from command line", len(kvSecrets)))
		for k, v := range kvSecrets {
			secrets[k] = v
		}
	}

	if len(secrets) == 0 {
		return fmt.Errorf("no secrets to push. Use -f to specify a file or -k to add key=value pairs")
	}

	// Check if master key exists or generate new one
	masterKey, isNew, err := getOrCreateMasterKey(paths, environment)
	if err != nil {
		return err
	}
	// Ensure master key is cleared from memory when done
	defer crypto.ZeroBytes(masterKey)

	if isNew {
		ui.Success("Generated new master key")
	} else {
		ui.Success("Using existing master key")
	}

	// Get current machine info for GrantedBy
	machineInfo, err := vault.LoadMachineInfo()
	if err != nil {
		return fmt.Errorf("failed to load machine info: %w", err)
	}

	// Wrap master key for machines that already have access (and current machine)
	// Use 'nvolt machine grant <machine-id>' to grant access to new machines
	ui.Step("Wrapping master key for machines with access")
	if err := vault.WrapMasterKeyForExistingMachines(paths, environment, masterKey, machineInfo.ID); err != nil {
		return fmt.Errorf("failed to wrap master key: %w", err)
	}
	ui.Success("Master key wrapped for machines with access")

	// Encrypt and save each secret
	ui.Step("%s", fmt.Sprintf("Encrypting %d secrets for environment '%s'", len(secrets), ui.Cyan(environment)))
	for key, value := range secrets {
		encrypted, err := vault.EncryptSecret(masterKey, value)
		if err != nil {
			return fmt.Errorf("failed to encrypt secret %s: %w", key, err)
		}

		if !dryRun {
			if err := vault.SaveEncryptedSecret(paths, environment, key, encrypted); err != nil {
				return fmt.Errorf("failed to save secret %s: %w", key, err)
			}
		} else {
			ui.Info(ui.Gray(fmt.Sprintf("  [DRY RUN] Would save secret: %s", key)))
		}
	}

	ui.Success("%s", fmt.Sprintf("Successfully pushed %d secrets", len(secrets)))
	ui.PrintKeyValue("  Environment", ui.Cyan(environment))
	ui.PrintKeyValue("  Vault", ui.Gray(vaultPath))
	ui.Section("Secrets encrypted:")
	for key := range secrets {
		ui.Substep(key)
	}

	// Auto-commit and push in global mode
	if vault.IsGlobalMode(vaultPath) && !dryRun {
		repoPath := vault.GetRepoPathFromVault(vaultPath)
		ui.Step("Committing and pushing changes to repository")

		// Generate commit message
		commitMsg := fmt.Sprintf("Update secrets for project '%s' environment '%s'", project, environment)

		// Commit and push project directory (not .nvolt which doesn't exist in global mode)
		if err := git.CommitAndPush(repoPath, commitMsg, project, "machines"); err != nil {
			return fmt.Errorf("failed to commit and push changes: %w", err)
		}

		ui.Success("Changes committed and pushed")
	} else if vault.IsGlobalMode(vaultPath) && dryRun {
		ui.Info(ui.Gray("\n[DRY RUN] Would commit and push changes to repository"))
	}

	if dryRun {
		ui.Info(ui.Gray("\n[DRY RUN] No changes were made"))
	}

	return nil
}

// getOrCreateMasterKey gets the existing master key or creates a new one for the specified environment
func getOrCreateMasterKey(paths *vault.Paths, environment string) ([]byte, bool, error) {
	// Try to unwrap existing master key
	masterKey, err := unwrapMasterKey(paths, environment)
	if err == nil {
		return masterKey, false, nil
	}

	// Generate new master key
	masterKey, err = crypto.GenerateAESKey()
	if err != nil {
		return nil, false, fmt.Errorf("failed to generate master key: %w", err)
	}

	return masterKey, true, nil
}

// unwrapMasterKey attempts to load and unwrap the master key for the current machine in a specific environment
func unwrapMasterKey(paths *vault.Paths, environment string) ([]byte, error) {
	// Get current machine ID
	machineID, err := vault.GetCurrentMachineID()
	if err != nil {
		return nil, fmt.Errorf("failed to get current machine ID: %w", err)
	}

	// Load wrapped key
	wrappedKeyPath := paths.GetWrappedKeyPath(environment, machineID)
	data, err := vault.ReadFile(wrappedKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read wrapped key: %w (machine may not have access to '%s' environment)", err, environment)
	}

	var wrappedKeyData types.WrappedKey
	if err := json.Unmarshal(data, &wrappedKeyData); err != nil {
		return nil, fmt.Errorf("failed to parse wrapped key: %w", err)
	}

	// Load this machine's decrypter (software PEM key or PKCS#11-backed token).
	// keyprovider.LoadDecrypter is used rather than vault.LoadPrivateKey so a
	// hardware-backed machine can unwrap at push time; closeDec finalizes the
	// token session (no-op for software).
	dec, closeDec, err := keyprovider.LoadDecrypter()
	if err != nil {
		return nil, fmt.Errorf("failed to load machine key: %w", err)
	}
	defer closeDec()

	// Unwrap master key
	wrappedKey, err := base64.StdEncoding.DecodeString(wrappedKeyData.WrappedKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode wrapped key: %w", err)
	}

	masterKey, err := crypto.UnwrapKey(dec, wrappedKey)
	if err != nil {
		return nil, fmt.Errorf("failed to unwrap master key: %w", err)
	}

	return masterKey, nil
}

func init() {
	pushCmd.Flags().StringP("file", "f", "", "Environment file to encrypt")
	pushCmd.Flags().StringP("env", "e", "default", "Environment name")
	pushCmd.Flags().StringP("project", "p", "", "Project name (auto-detected if not specified)")
	pushCmd.Flags().StringSliceP("key", "k", []string{}, "Key=value pairs (can be specified multiple times)")
	pushCmd.Flags().Bool("dry-run", false, "Show what would be done without making any changes")
	rootCmd.AddCommand(pushCmd)
}
