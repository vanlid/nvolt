package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/iluxav/nvolt/internal/config"
	"github.com/iluxav/nvolt/internal/crypto"
	"github.com/iluxav/nvolt/internal/git"
	"github.com/iluxav/nvolt/internal/keyprovider"
	"github.com/iluxav/nvolt/internal/ui"
	"github.com/iluxav/nvolt/internal/vault"
	"github.com/iluxav/nvolt/pkg/types"
	"github.com/spf13/cobra"
)

var machineCmd = &cobra.Command{
	Use:   "machine",
	Short: "Manage machine access and keys",
	Long:  `Add or remove machines from the vault access list.`,
}

var machineAddCmd = &cobra.Command{
	Use:   "add [name]",
	Short: "Add a new machine and generate its keypair",
	Long: `Generate a new keypair for a machine (CI/CD or another device).

Example:
  nvolt machine add ci-server
  nvolt machine add alice-laptop`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		machineName := args[0]
		return runMachineAdd(machineName)
	},
}

var machineRmCmd = &cobra.Command{
	Use:   "rm [name]",
	Short: "Remove a machine and revoke its access",
	Long: `Revoke access for a machine by removing its keys and re-wrapping master key.

Example:
  nvolt machine rm ci-server
  nvolt machine rm alice-laptop`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		machineName := args[0]
		return runMachineRm(machineName)
	},
}

var machineListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all machines with access",
	Long:  `Display all machines that have access to the vault.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runMachineList()
	},
}

var machineGrantCmd = &cobra.Command{
	Use:   "grant [machine-id]",
	Short: "Grant a machine access to an environment",
	Long: `Grant a specific machine access to decrypt secrets in an environment.

Examples:
  nvolt machine grant ci-server
  nvolt machine grant ci-server -e production
  nvolt machine grant alice-laptop -p myproject -e staging`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		machineID := args[0]
		environment, _ := cmd.Flags().GetString("env")
		project, _ := cmd.Flags().GetString("project")
		return runMachineGrant(machineID, environment, project)
	},
}

func runMachineAdd(machineName string) error {
	ui.Step(fmt.Sprintf("Adding machine: %s", ui.Cyan(machineName)))

	// Find vault path (local or global)
	vaultPath, err := findVaultPath()
	if err != nil {
		return err
	}

	// Pull latest changes in global mode BEFORE doing any work
	if vault.IsGlobalMode(vaultPath) {
		repoPath := vault.GetRepoPathFromVault(vaultPath)
		ui.Step("Pulling latest changes from repository")
		if err := git.SafePull(repoPath); err != nil {
			return fmt.Errorf("failed to pull latest changes: %w", err)
		}
		ui.Success("Repository up to date")
	}

	// Generate keypair for new machine
	ui.Step("Generating keypair")
	privateKey, err := crypto.GenerateRSAKeypair()
	if err != nil {
		return fmt.Errorf("failed to generate keypair: %w", err)
	}

	publicKey := &privateKey.PublicKey

	// Encode keys
	privateKeyPEM, err := crypto.EncodePrivateKeyPEM(privateKey)
	if err != nil {
		return fmt.Errorf("failed to encode private key: %w", err)
	}

	publicKeyPEM, err := crypto.EncodePublicKeyPEM(publicKey)
	if err != nil {
		return fmt.Errorf("failed to encode public key: %w", err)
	}

	fingerprint, err := crypto.GenerateFingerprint(publicKey)
	if err != nil {
		return fmt.Errorf("failed to generate fingerprint: %w", err)
	}

	// Create machine info
	// Use custom name from user input, fallback to machineName as hostname
	machineID := vault.GenerateMachineID(machineName, machineName, fingerprint)
	machineInfo := &types.MachineInfo{
		ID:          machineID,
		PublicKey:   string(publicKeyPEM),
		Fingerprint: fingerprint,
		Hostname:    machineName,
		Description: fmt.Sprintf("Machine: %s", machineName),
		CreatedAt:   time.Now(),
	}

	// Add to vault (machines are at root level, so use empty project name)
	paths := vault.GetVaultPaths(vaultPath, "")
	if err := vault.AddMachineToVault(paths, machineInfo); err != nil {
		return fmt.Errorf("failed to add machine to vault: %w", err)
	}

	ui.Success("Machine added successfully")
	ui.PrintKeyValue("  Machine ID", machineID)
	ui.PrintKeyValue("  Fingerprint", fingerprint)
	ui.Section("Private key (save this securely for the new machine):")
	fmt.Printf("%s%s%s\n", ui.Gray("---\n"), string(privateKeyPEM), ui.Gray("---"))
	ui.Section("To use this machine:")
	ui.Info("  1. Save the private key to ~/.nvolt/private_key.pem on the target machine")
	ui.Info("  2. Set permissions: chmod 600 ~/.nvolt/private_key.pem")
	ui.Info("  3. Save the machine info to ~/.nvolt/machines/machine-info.json")

	// Auto-commit and push in global mode
	if vault.IsGlobalMode(vaultPath) {
		repoPath := vault.GetRepoPathFromVault(vaultPath)
		ui.Step("Committing and pushing changes to repository")

		commitMsg := fmt.Sprintf("Add machine: %s", machineName)
		if err := git.CommitAndPush(repoPath, commitMsg, ".nvolt"); err != nil {
			return fmt.Errorf("failed to commit and push changes: %w", err)
		}

		ui.Success("Changes committed and pushed")
	}

	return nil
}

func runMachineRm(machineName string) error {
	ui.Step(fmt.Sprintf("Removing machine: %s", ui.Cyan(machineName)))

	// Find vault path
	vaultPath, err := findVaultPath()
	if err != nil {
		return err
	}

	// Pull latest changes in global mode BEFORE doing any work
	if vault.IsGlobalMode(vaultPath) {
		repoPath := vault.GetRepoPathFromVault(vaultPath)
		ui.Step("Pulling latest changes from repository")
		if err := git.SafePull(repoPath); err != nil {
			return fmt.Errorf("failed to pull latest changes: %w", err)
		}
		ui.Success("Repository up to date")
	}

	// List all machines and find matching ones (machines are at root level)
	paths := vault.GetVaultPaths(vaultPath, "")
	machines, err := vault.ListMachines(paths)
	if err != nil {
		return fmt.Errorf("failed to list machines: %w", err)
	}

	// Find machines matching the hostname or ID
	var matchingMachines []*types.MachineInfo
	for _, m := range machines {
		if m.Hostname == machineName || m.ID == machineName {
			matchingMachines = append(matchingMachines, m)
		}
	}

	if len(matchingMachines) == 0 {
		return fmt.Errorf("no machine found with name or ID: %s", machineName)
	}

	var machineID string
	if len(matchingMachines) == 1 {
		machineID = matchingMachines[0].ID
	} else {
		// Multiple matches - let user choose
		ui.Section("Multiple machines found:")
		for i, m := range matchingMachines {
			ui.Info(fmt.Sprintf("%d. %s (Fingerprint: %s)", i+1, ui.Cyan(m.ID), ui.Gray(m.Fingerprint)))
		}
		fmt.Print("\nEnter number to remove: ")
		var choice int
		fmt.Scanln(&choice)
		if choice < 1 || choice > len(matchingMachines) {
			return fmt.Errorf("invalid choice")
		}
		machineID = matchingMachines[choice-1].ID
	}

	// Confirm removal
	fmt.Printf("\n%s %s? This cannot be undone. (yes/no): ", ui.Yellow("Are you sure you want to remove machine"), ui.Cyan(machineID))
	var response string
	fmt.Scanln(&response)
	if response != "yes" {
		ui.Warning("Aborted")
		return nil
	}

	// Remove machine
	if err := vault.RemoveMachineFromVault(paths, machineID); err != nil {
		return fmt.Errorf("failed to remove machine: %w", err)
	}

	ui.Success(fmt.Sprintf("Machine %s removed successfully", machineID))
	fmt.Println()
	ui.Warning("Note: You should re-wrap the master key using 'nvolt sync' to ensure")
	ui.Warning("      the removed machine cannot decrypt new secrets.")

	// Auto-commit and push in global mode
	if vault.IsGlobalMode(vaultPath) {
		repoPath := vault.GetRepoPathFromVault(vaultPath)
		ui.Step("Committing and pushing changes to repository")

		commitMsg := fmt.Sprintf("Remove machine: %s", machineID)
		if err := git.CommitAndPush(repoPath, commitMsg, ".nvolt"); err != nil {
			return fmt.Errorf("failed to commit and push changes: %w", err)
		}

		ui.Success("Changes committed and pushed")
	}

	return nil
}

func runMachineList() error {
	// Find vault path
	vaultPath, err := findVaultPath()
	if err != nil {
		return err
	}

	// List machines (machines are at root level)
	paths := vault.GetVaultPaths(vaultPath, "")
	machines, err := vault.ListMachines(paths)
	if err != nil {
		return fmt.Errorf("failed to list machines: %w", err)
	}

	if len(machines) == 0 {
		ui.Warning("No machines found in vault")
		return nil
	}

	ui.Section(fmt.Sprintf("Machines (%d):", len(machines)))
	for _, m := range machines {
		ui.PrintKeyValue("  ID", ui.Cyan(m.ID))
		ui.PrintKeyValue("  Hostname", m.Hostname)
		ui.PrintKeyValue("  Fingerprint", ui.Gray(m.Fingerprint))
		ui.PrintKeyValue("  Created", ui.Gray(m.CreatedAt.Format(time.RFC3339)))
		if m.Description != "" {
			ui.PrintKeyValue("  Description", m.Description)
		}
		fmt.Println()
	}

	return nil
}

func runMachineGrant(machineID, environment, project string) error {
	ui.Step(fmt.Sprintf("Granting access to machine: %s", ui.Cyan(machineID)))

	// Ensure machine is initialized
	if err := EnsureMachineInitialized(); err != nil {
		return err
	}

	// Find vault path
	vaultPath, err := findVaultPath()
	if err != nil {
		return err
	}

	// Pull latest changes in global mode BEFORE doing any work
	if vault.IsGlobalMode(vaultPath) {
		repoPath := vault.GetRepoPathFromVault(vaultPath)
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
		}
	}

	// Get vault paths
	paths := vault.GetVaultPaths(vaultPath, project)

	// Get current machine info for grantedBy
	currentMachine, err := vault.LoadMachineInfo()
	if err != nil {
		return fmt.Errorf("failed to load current machine info: %w", err)
	}

	// Display grant details
	fmt.Println()
	if project != "" {
		ui.PrintKeyValue("  Project", ui.Cyan(project))
	}
	ui.PrintKeyValue("  Environment", ui.Cyan(environment))
	ui.PrintKeyValue("  Machine", ui.Cyan(machineID))

	// Confirm with user
	fmt.Printf("\n%s ", ui.Yellow("Are you sure you want to grant access?"))
	fmt.Print("(y/n): ")
	var response string
	fmt.Scanln(&response)

	if response != "y" && response != "yes" {
		ui.Warning("Aborted")
		return nil
	}

	// Load master key for the environment
	ui.Step("Loading master key")
	dec, closeDec, err := keyprovider.LoadDecrypter()
	if err != nil {
		return fmt.Errorf("failed to load machine key: %w", err)
	}
	defer closeDec()
	masterKey, err := vault.UnwrapMasterKey(paths, environment, dec)
	if err != nil {
		// Check if it's an access denied error
		if strings.Contains(err.Error(), "access denied") || strings.Contains(err.Error(), "no such file or directory") {
			ui.Error(fmt.Sprintf("You don't have access to the '%s' environment", ui.Cyan(environment)))
			fmt.Println()
			ui.Info("To grant access to another machine, you must first have access to the environment yourself.")
			ui.Info(fmt.Sprintf("Ask someone with access to run: %s", ui.Gray(fmt.Sprintf("nvolt machine grant %s -e %s", currentMachine.ID, environment))))
			return nil
		}
		return fmt.Errorf("failed to unwrap master key: %w", err)
	}
	defer crypto.ZeroBytes(masterKey)
	ui.Success("Master key loaded")

	// Grant access to the machine
	ui.Step(fmt.Sprintf("Granting access to %s", ui.Cyan(machineID)))
	wasGranted, err := vault.GrantMachineAccess(paths, environment, machineID, masterKey, currentMachine.ID)
	if err != nil {
		return fmt.Errorf("failed to grant access: %w", err)
	}

	if wasGranted {
		ui.Success(fmt.Sprintf("Access granted to %s", ui.Cyan(machineID)))
		fmt.Println()
		ui.Info(fmt.Sprintf("Machine %s can now decrypt secrets in environment %s",
			ui.Cyan(machineID), ui.Cyan(environment)))
	} else {
		ui.Success(fmt.Sprintf("Machine %s already has access to environment %s",
			ui.Cyan(machineID), ui.Cyan(environment)))
		fmt.Println()
		ui.Info("No changes needed")
	}

	// Auto-commit and push in global mode
	if vault.IsGlobalMode(vaultPath) {
		repoPath := vault.GetRepoPathFromVault(vaultPath)
		ui.Step("Committing and pushing changes to repository")

		commitMsg := fmt.Sprintf("Grant %s access to %s environment", machineID, environment)
		if project != "" {
			commitMsg = fmt.Sprintf("Grant %s access to %s/%s", machineID, project, environment)
		}

		// Commit and push
		if err := git.CommitAndPush(repoPath, commitMsg, project, "machines"); err != nil {
			return fmt.Errorf("failed to commit and push changes: %w", err)
		}

		ui.Success("Changes committed and pushed")
	}

	return nil
}

// findVaultPath tries to find the vault in local or global mode
func findVaultPath() (string, error) {
	// Try local mode first
	localPath, err := vault.GetLocalVaultPath()
	if err == nil && vault.IsVaultInitialized(localPath) {
		return localPath, nil
	}

	// Try to find global vault in ~/.nvolt/orgs
	homePaths, err := vault.GetHomePaths()
	if err != nil {
		return "", fmt.Errorf("vault not found. Run 'nvolt init' first")
	}

	// Check if orgs directory exists
	if !vault.FileExists(homePaths.Orgs) {
		return "", fmt.Errorf("vault not found. Run 'nvolt init' first")
	}

	// Scan for vaults in ~/.nvolt/orgs/org/repo
	vaultPath, err := findGlobalVault(homePaths.Orgs)
	if err != nil {
		return "", fmt.Errorf("vault not found. Run 'nvolt init' first")
	}

	return vaultPath, nil
}

// ProjectResolvedInfo contains resolved project information for composition
type ProjectResolvedInfo struct {
	ProjectName string // The project name used for vault paths (empty for local mode)
	VaultPath   string // The vault path (either local .nvolt or global ~/.nvolt/orgs/org/repo)
	DisplayName string // The display name for UI messages
}

// resolveProjects resolves a list of project names into their vault paths
// If no projects are provided, it auto-detects the current project
func resolveProjects(projectNames []string) ([]ProjectResolvedInfo, error) {
	var result []ProjectResolvedInfo

	// Always check for local .nvolt first
	localPath, err := vault.GetLocalVaultPath()
	hasLocal := err == nil && vault.IsVaultInitialized(localPath)

	if hasLocal {
		// Local mode available - add it as base layer
		result = append(result, ProjectResolvedInfo{
			ProjectName: "",
			VaultPath:   localPath,
			DisplayName: "(local)",
		})
	}

	// If no projects specified
	if len(projectNames) == 0 {
		// If we have local, we're done
		if hasLocal {
			return result, nil
		}

		// No local - auto-detect project name from current directory
		cwd, err := os.Getwd()
		if err != nil {
			return nil, fmt.Errorf("failed to get current directory: %w", err)
		}

		detectedProject, _, err := config.GetProjectName(cwd, "")
		if err != nil {
			return nil, fmt.Errorf("failed to detect project name. Use -p flag to specify: %w", err)
		}

		// Find global vault
		vaultPath, err := findVaultPath()
		if err != nil {
			return nil, err
		}

		result = append(result, ProjectResolvedInfo{
			ProjectName: detectedProject,
			VaultPath:   vaultPath,
			DisplayName: detectedProject,
		})
		return result, nil
	}

	// Projects specified - add them all from global mode
	// (on top of local if it exists)
	vaultPath, err := findVaultPath()
	if err != nil {
		return nil, fmt.Errorf("failed to find global vault: %w", err)
	}

	for _, projectName := range projectNames {
		result = append(result, ProjectResolvedInfo{
			ProjectName: projectName,
			VaultPath:   vaultPath,
			DisplayName: projectName,
		})
	}

	return result, nil
}

// findGlobalVault searches for a vault in ~/.nvolt/orgs/
// Returns the first valid repo root found in the structure: ~/.nvolt/orgs/org/repo
// In global mode, the repo root contains machines/ directory at the top level
func findGlobalVault(orgsDir string) (string, error) {
	// List all org directories in ~/.nvolt/orgs
	orgDirs, err := vault.ListDirs(orgsDir)
	if err != nil {
		return "", fmt.Errorf("no global vaults found")
	}

	// Scan each org directory for repos
	for _, orgDir := range orgDirs {
		repoDirs, err := vault.ListDirs(orgDir)
		if err != nil {
			continue
		}

		// Check each repo for a machines/ directory (global mode indicator)
		for _, repoDir := range repoDirs {
			machinesPath := filepath.Join(repoDir, vault.MachinesDir)
			if vault.FileExists(machinesPath) {
				// This is a valid global vault
				return repoDir, nil
			}
		}
	}

	return "", fmt.Errorf("no global vaults found")
}

func init() {
	machineCmd.AddCommand(machineAddCmd)
	machineCmd.AddCommand(machineRmCmd)
	machineCmd.AddCommand(machineListCmd)
	machineCmd.AddCommand(machineGrantCmd)

	// Add flags to grant command
	machineGrantCmd.Flags().StringP("env", "e", "default", "Environment name")
	machineGrantCmd.Flags().StringP("project", "p", "", "Project name (auto-detected if not specified)")

	rootCmd.AddCommand(machineCmd)
}
