package cli

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/iluxav/nvolt/internal/git"
	"github.com/iluxav/nvolt/internal/ui"
	"github.com/iluxav/nvolt/internal/vault"
	"github.com/spf13/cobra"
)

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Initialize nvolt vault and machine keys",
	Long: `Initialize a new nvolt vault and generate machine keypair if needed.

Local mode (current directory):
  nvolt init

Global mode (dedicated GitHub repo):
  nvolt init --repo org/repo

This command will:
- Generate an RSA/Ed25519 keypair for this machine (if not exists)
- Create .nvolt/ directory structure
- Clone the repo (if --repo provided) into ~/.nvolt/orgs/`,
	RunE: func(cmd *cobra.Command, args []string) error {
		repo, _ := cmd.Flags().GetString("repo")

		opts, err := pkcs11OptsFromFlags(cmd)
		if err != nil {
			return err
		}

		return runInit(repo, opts)
	},
}

// pkcs11EnrollOpts carries the --pkcs11 enrollment parameters for init/join.
// A nil *pkcs11EnrollOpts means --pkcs11 was not set (default software path).
type pkcs11EnrollOpts struct {
	module  string
	uri     string
	pinMode string
}

// addPKCS11EnrollFlags registers the shared --pkcs11/--module/--uri/--pin-mode
// flags on init and join.
func addPKCS11EnrollFlags(cmd *cobra.Command) {
	cmd.Flags().Bool("pkcs11", false, "Back this machine's identity with a PKCS#11 token instead of a software keypair")
	cmd.Flags().String("module", os.Getenv("NVOLT_PKCS11_MODULE"), "Path to PKCS#11 module (.so) (with --pkcs11)")
	cmd.Flags().String("uri", "", "PKCS#11 URI of the RSA key to enroll (with --pkcs11)")
	cmd.Flags().String("pin-mode", "prompt", "How to obtain the PIN: prompt, env, or none (with --pkcs11)")
}

// pkcs11OptsFromFlags returns the enrollment options when --pkcs11 is set, or
// nil when it is not (unchanged software init/join). It validates that the
// required --module/--uri are present up front.
func pkcs11OptsFromFlags(cmd *cobra.Command) (*pkcs11EnrollOpts, error) {
	usePKCS11, _ := cmd.Flags().GetBool("pkcs11")
	if !usePKCS11 {
		return nil, nil
	}
	module, _ := cmd.Flags().GetString("module")
	uri, _ := cmd.Flags().GetString("uri")
	pinMode, _ := cmd.Flags().GetString("pin-mode")
	if module == "" {
		return nil, fmt.Errorf("--pkcs11 requires --module (or NVOLT_PKCS11_MODULE)")
	}
	if uri == "" {
		return nil, fmt.Errorf("--pkcs11 requires --uri")
	}
	return &pkcs11EnrollOpts{module: module, uri: uri, pinMode: pinMode}, nil
}

func runInit(repoSpec string, pkcs11Opts *pkcs11EnrollOpts) error {
	ui.PrintBanner("Initializing nvolt vault...")

	// Step 1: Establish this machine's identity.
	//
	// --pkcs11 enrolls the on-card key as the identity (writing machine-info.json
	// with NO software private key on disk). This must NOT fall through to
	// EnsureMachineInitialized: that path keys off IsMachineInitialized(), which
	// requires a software private_key.pem — absent by design for a hardware-backed
	// machine — and would wrongly re-prompt to generate a software keypair.
	// The default (software) path is unchanged.
	if pkcs11Opts != nil {
		ui.Step("Enrolling PKCS#11-backed machine identity")
		if err := enrollPKCS11Machine(pkcs11Opts.module, pkcs11Opts.uri, pkcs11Opts.pinMode, false); err != nil {
			return fmt.Errorf("failed to enroll PKCS#11 machine: %w", err)
		}
	} else {
		ui.Step("Checking machine keypair")
		if err := EnsureMachineInitialized(); err != nil {
			return fmt.Errorf("failed to initialize machine: %w", err)
		}
	}

	// Load machine info
	machineInfo, err := vault.LoadMachineInfo()
	if err != nil {
		return fmt.Errorf("failed to load machine info: %w", err)
	}
	ui.Success("Machine keypair ready")
	ui.PrintKeyValue("  Machine ID", machineInfo.ID)
	ui.PrintKeyValue("  Fingerprint", machineInfo.Fingerprint)

	// Step 2: Determine mode (Local or Global) and initialize vault
	if repoSpec != "" {
		return initGlobalMode(repoSpec)
	}

	return initLocalMode()
}

func initLocalMode() error {
	ui.PrintModeInfo("Local")

	vaultPath, err := vault.GetLocalVaultPath()
	if err != nil {
		return fmt.Errorf("failed to get local vault path: %w", err)
	}

	// Load current machine info
	machineInfo, err := vault.LoadMachineInfo()
	if err != nil {
		return fmt.Errorf("failed to load machine info: %w", err)
	}

	// Check if vault already exists
	vaultExists := vault.IsVaultInitialized(vaultPath)
	if vaultExists {
		ui.Success("Vault already initialized")
		ui.Substep(ui.Gray(vaultPath))

		// Check if current machine is already in the vault
		paths := vault.GetVaultPaths(vaultPath, "")
		machinePath := paths.GetMachineInfoPath(machineInfo.ID)
		if vault.FileExists(machinePath) {
			ui.Success("Machine already registered in vault")
		} else {
			// Add current machine to existing vault
			if err := vault.AddMachineToVault(paths, machineInfo); err != nil {
				return fmt.Errorf("failed to add machine to vault: %w", err)
			}
			ui.Success("Machine added to vault")
		}

		ui.Section("Next steps:")
		ui.PrintBasicUsage()
		return nil
	}

	// Initialize vault directory
	ui.Step("Creating vault directory")
	if err := vault.InitializeVaultDirectory(vaultPath); err != nil {
		return fmt.Errorf("failed to initialize vault directory: %w", err)
	}

	// Add current machine to vault
	paths := vault.GetVaultPaths(vaultPath, "")
	if err := vault.AddMachineToVault(paths, machineInfo); err != nil {
		return fmt.Errorf("failed to add machine to vault: %w", err)
	}

	ui.Success("Vault initialized")
	ui.Substep(ui.Gray(vaultPath))
	ui.Section("Next steps:")
	ui.PrintBasicUsage()

	return nil
}

func initGlobalMode(repoSpec string) error {
	ui.PrintModeInfo("Global")

	// Check if git is available
	if !git.IsGitAvailable() {
		return fmt.Errorf("git is not available in PATH")
	}

	// Parse repository
	org, repo, err := git.GetRepoPath(repoSpec)
	if err != nil {
		return err
	}

	ui.PrintDetected("Repository", fmt.Sprintf("%s/%s", org, repo))

	// Get home paths
	homePaths, err := vault.GetHomePaths()
	if err != nil {
		return err
	}

	// Determine repo root path (no .nvolt subdirectory in global mode)
	repoPath := filepath.Join(homePaths.Orgs, org, repo)

	// Load current machine info
	machineInfo, err := vault.LoadMachineInfo()
	if err != nil {
		return fmt.Errorf("failed to load machine info: %w", err)
	}

	// Check if repository already exists
	repoExists := git.IsGitRepo(repoPath)
	if repoExists {
		ui.Success("Repository already cloned")
		ui.Substep(ui.Gray(repoPath))

		// Check if machines directory exists
		machinesDir := filepath.Join(repoPath, vault.MachinesDir)
		if !vault.FileExists(machinesDir) {
			// Initialize machines directory
			if err := os.MkdirAll(machinesDir, vault.DirPerm); err != nil {
				return fmt.Errorf("failed to create machines directory: %w", err)
			}
		}

		// Check if current machine is already registered
		machinePath := filepath.Join(machinesDir, fmt.Sprintf("%s.json", machineInfo.ID))
		machineExists := vault.FileExists(machinePath)

		if machineExists {
			ui.Success("Machine already registered in vault")
		} else {
			// Add current machine (use empty project name for machines at root level)
			paths := vault.GetVaultPaths(repoPath, "")
			if err := vault.AddMachineToVault(paths, machineInfo); err != nil {
				return fmt.Errorf("failed to add machine to vault: %w", err)
			}
			ui.Success("Machine added to vault")
		}

		// Check if there are uncommitted changes
		hasChanges, err := git.HasUncommittedChanges(repoPath)
		if err == nil && hasChanges {
			// Commit and push the machine
			ui.Step("Committing changes to repository")
			commitMsg := fmt.Sprintf("Add machine %s to vault", machineInfo.ID)
			if err := git.CommitAndPush(repoPath, commitMsg, "machines"); err != nil {
				return fmt.Errorf("failed to commit and push machine: %w", err)
			}
			ui.Success("Changes committed and pushed")
		}

		ui.Section("Next steps:")
		ui.PrintGlobalUsage()
		return nil
	}

	// Clone repository
	repoURL, err := git.ParseRepoURL(repoSpec)
	if err != nil {
		return err
	}

	ui.Step("Cloning repository")
	if err := git.Clone(repoURL, repoPath); err != nil {
		return fmt.Errorf("failed to clone repository: %w", err)
	}

	ui.Success("Repository cloned")
	ui.Substep(ui.Gray(repoPath))

	// Initialize machines directory at repo root
	machinesDir := filepath.Join(repoPath, vault.MachinesDir)
	if err := os.MkdirAll(machinesDir, vault.DirPerm); err != nil {
		return fmt.Errorf("failed to create machines directory: %w", err)
	}

	// Add current machine to vault (use empty project name for machines at root level)
	paths := vault.GetVaultPaths(repoPath, "")
	if err := vault.AddMachineToVault(paths, machineInfo); err != nil {
		return fmt.Errorf("failed to add machine to vault: %w", err)
	}

	// Commit and push the machine's public key to repository
	ui.Step("Committing machine to repository")
	commitMsg := fmt.Sprintf("Add machine %s to vault", machineInfo.ID)
	if err := git.CommitAndPush(repoPath, commitMsg, "machines"); err != nil {
		return fmt.Errorf("failed to commit and push machine: %w", err)
	}
	ui.Success("Machine committed and pushed")

	ui.Success("Global vault initialized")
	ui.Section("Next steps:")
	ui.PrintGlobalUsage()

	return nil
}

func init() {
	initCmd.Flags().StringP("repo", "r", "", "GitHub repository (org/repo) for global mode")
	addPKCS11EnrollFlags(initCmd)
	rootCmd.AddCommand(initCmd)
}
