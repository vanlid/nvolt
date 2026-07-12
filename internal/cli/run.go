package cli

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/iluxav/nvolt/internal/crypto"
	"github.com/iluxav/nvolt/internal/keyprovider"
	"github.com/iluxav/nvolt/internal/ui"
	"github.com/iluxav/nvolt/internal/vault"
	"github.com/spf13/cobra"
)

var runCmd = &cobra.Command{
	Use:   "run [command]",
	Short: "Run a command with decrypted secrets as environment variables",
	Long: `Load decrypted secrets into environment and execute a command.

Examples:
  nvolt run npm start
  nvolt run -e production ./app
  nvolt run -p db-connections -p file-storage node index.js  # Compose multiple projects
  nvolt run -c "go test ./..."`,
	RunE: func(cmd *cobra.Command, args []string) error {
		environment, _ := cmd.Flags().GetString("env")
		projects, _ := cmd.Flags().GetStringSlice("project")
		command, _ := cmd.Flags().GetString("command")

		var execArgs []string
		if command != "" {
			// Use shell to execute string command
			execArgs = []string{"sh", "-c", command}
		} else if len(args) > 0 {
			// Use args directly
			execArgs = args
		} else {
			return fmt.Errorf("no command specified")
		}

		return runWithSecrets(environment, projects, execArgs)
	},
}

func runWithSecrets(environment string, projects []string, cmdArgs []string) error {
	// Ensure machine is initialized
	if err := EnsureMachineInitialized(); err != nil {
		return err
	}

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
	}

	// Load this machine's decrypter ONCE for the whole run: for a PKCS#11
	// machine this opens a single token session (one PIN entry) reused across
	// every project's unwrap.
	dec, closeDec, err := keyprovider.LoadDecrypter()
	if err != nil {
		return fmt.Errorf("failed to load machine key: %w", err)
	}
	defer func() { _ = closeDec() }()

	// Load and merge secrets from all projects
	allSecrets := make(map[string]string)
	for _, projectInfo := range projectsToLoad {
		paths := vault.GetVaultPaths(projectInfo.VaultPath, projectInfo.ProjectName)

		// Unwrap master key for this project
		masterKey, err := vault.UnwrapMasterKey(paths, environment, dec)
		if err != nil {
			return fmt.Errorf("failed to unwrap master key for project '%s': %w", projectInfo.DisplayName, err)
		}

		// Get list of secret files
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
			filename := filepath.Base(secretFile)

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

	ui.Success("%s", fmt.Sprintf("Loaded %d secrets from environment '%s'", len(allSecrets), ui.Cyan(environment)))
	ui.Info(fmt.Sprintf("Running: %s\n", ui.Gray(strings.Join(cmdArgs, " "))))

	// Prepare environment
	env := os.Environ()
	for key, value := range allSecrets {
		env = append(env, fmt.Sprintf("%s=%s", key, value))
	}

	// Execute command
	cmd := exec.Command(cmdArgs[0], cmdArgs[1:]...)
	cmd.Env = env
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	err = cmd.Run()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			// Command exited with non-zero status
			os.Exit(exitErr.ExitCode())
		}
		return fmt.Errorf("failed to execute command: %w", err)
	}

	return nil
}

func init() {
	runCmd.Flags().StringP("env", "e", "default", "Environment name")
	runCmd.Flags().StringSliceP("project", "p", []string{}, "Project name(s) - can be specified multiple times for composition")
	runCmd.Flags().StringP("command", "c", "", "Command to execute")
	rootCmd.AddCommand(runCmd)
}
