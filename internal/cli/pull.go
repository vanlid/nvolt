package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/iluxav/nvolt/internal/crypto"
	"github.com/iluxav/nvolt/internal/git"
	"github.com/iluxav/nvolt/internal/keyprovider"
	"github.com/iluxav/nvolt/internal/ui"
	"github.com/iluxav/nvolt/internal/vault"
	"github.com/spf13/cobra"
)

var pullCmd = &cobra.Command{
	Use:   "pull",
	Short: "Decrypt and pull secrets from vault",
	Long: `Decrypt secrets from the vault and output them in .env format.

Examples:
  nvolt pull
  nvolt pull -e production
  nvolt pull -e staging -p myproject
  nvolt pull -p db-connections -p file-storage  # Compose multiple projects
  nvolt pull --write  # Write to .env file`,
	RunE: func(cmd *cobra.Command, args []string) error {
		environment, _ := cmd.Flags().GetString("env")
		projects, _ := cmd.Flags().GetStringSlice("project")
		write, _ := cmd.Flags().GetBool("write")

		return runPull(environment, projects, write)
	},
}

func runPull(environment string, projects []string, write bool) error {
	// Ensure machine is initialized
	if err := EnsureMachineInitialized(); err != nil {
		return err
	}

	ui.Step("Pulling secrets from vault")

	// Resolve projects to load
	projectsToLoad, err := resolveProjects(projects)
	if err != nil {
		return err
	}

	// Show which projects we're loading
	if len(projectsToLoad) > 1 {
		projectNames := make([]string, len(projectsToLoad))
		for i, p := range projectsToLoad {
			projectNames[i] = p.DisplayName
		}
		ui.Info(fmt.Sprintf("Loading projects: %s", ui.Cyan(strings.Join(projectNames, ", "))))
	} else if len(projectsToLoad) == 1 {
		ui.PrintDetected("Project", projectsToLoad[0].DisplayName)
	}

	// Pull git changes if in global mode (only once for the vault)
	if len(projectsToLoad) > 0 && vault.IsGlobalMode(projectsToLoad[0].VaultPath) {
		repoPath := vault.GetRepoPathFromVault(projectsToLoad[0].VaultPath)
		ui.Step("Pulling latest changes from repository")
		if err := git.SafePull(repoPath); err != nil {
			return fmt.Errorf("failed to pull from repository: %w", err)
		}
		ui.Success("Repository up to date")
	}

	// Load this machine's decrypter ONCE for the whole pull: for a PKCS#11
	// machine this opens a single token session (one PIN entry) reused across
	// every project's unwrap, rather than one session per project.
	dec, closeDec, err := keyprovider.LoadDecrypter()
	if err != nil {
		return fmt.Errorf("failed to load machine key: %w", err)
	}
	defer closeDec()

	// Load and merge secrets from all projects
	allSecrets := make(map[string]string)
	for _, projectInfo := range projectsToLoad {
		ui.Info(fmt.Sprintf("  Loading secrets from project: %s", ui.Cyan(projectInfo.DisplayName)))
		paths := vault.GetVaultPaths(projectInfo.VaultPath, projectInfo.ProjectName)

		// Unwrap master key for this project
		masterKey, err := vault.UnwrapMasterKey(paths, environment, dec)
		if err != nil {
			return fmt.Errorf("failed to unwrap master key for project '%s': %w\nMake sure you have pushed secrets first", projectInfo.DisplayName, err)
		}

		// Get list of secret files for this environment
		secretsDir := paths.GetSecretsPath(environment)
		secretFiles, err := vault.ListFiles(secretsDir)
		if err != nil {
			crypto.ZeroBytes(masterKey)
			return fmt.Errorf("failed to list secrets for project '%s': %w", projectInfo.DisplayName, err)
		}

		if len(secretFiles) == 0 {
			crypto.ZeroBytes(masterKey)
			ui.Warning("%s", fmt.Sprintf("No secrets found for project '%s' in environment '%s'", projectInfo.DisplayName, environment))
			continue
		}

		// Decrypt all secrets from this project
		for _, secretFile := range secretFiles {
			// Extract key name from filename (remove .enc.json)
			filename := filepath.Base(secretFile)
			if !filepath.IsAbs(secretFile) {
				secretFile = filepath.Join(secretsDir, filename)
			}

			// Get key name
			key := filename
			if len(key) > 9 && key[len(key)-9:] == ".enc.json" {
				key = key[:len(key)-9]
			}

			// Load and decrypt secret
			encrypted, err := vault.LoadEncryptedSecret(paths, environment, key)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Warning: Failed to load secret %s from project %s: %v\n", key, projectInfo.DisplayName, err)
				continue
			}

			value, err := vault.DecryptSecret(masterKey, encrypted)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Warning: Failed to decrypt secret %s from project %s: %v\n", key, projectInfo.DisplayName, err)
				continue
			}

			// Merge into allSecrets (last one wins on conflicts)
			allSecrets[key] = value
		}

		// Clear master key from memory
		crypto.ZeroBytes(masterKey)
	}

	if len(allSecrets) == 0 {
		return fmt.Errorf("no secrets could be decrypted from any project")
	}

	ui.Success("%s", fmt.Sprintf("Decrypted %d secrets from environment '%s'", len(allSecrets), ui.Cyan(environment)))

	// Format output
	output := vault.FormatEnvOutput(allSecrets)

	if write {
		// Write to .env file
		envFile := ".env"
		if environment != "default" {
			envFile = fmt.Sprintf(".env.%s", environment)
		}

		err := os.WriteFile(envFile, []byte(output), 0644)
		if err != nil {
			return fmt.Errorf("failed to write .env file: %w", err)
		}

		ui.Success("%s", fmt.Sprintf("Written to %s", ui.Cyan(envFile)))
	} else {
		// Print to stdout
		ui.Section("Secrets:")

		// Sort keys for consistent output
		keys := make([]string, 0, len(allSecrets))
		for k := range allSecrets {
			keys = append(keys, k)
		}
		sort.Strings(keys)

		for _, key := range keys {
			fmt.Printf("%s=%s\n", key, allSecrets[key])
		}
	}

	return nil
}

func init() {
	pullCmd.Flags().StringP("env", "e", "default", "Environment name")
	pullCmd.Flags().StringSliceP("project", "p", []string{}, "Project name(s) - can be specified multiple times for composition")
	pullCmd.Flags().BoolP("write", "w", false, "Write output to .env file")
	rootCmd.AddCommand(pullCmd)
}
