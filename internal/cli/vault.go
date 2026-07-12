package cli

import (
	"fmt"
	"time"

	"github.com/iluxav/nvolt/internal/keyprovider"
	"github.com/iluxav/nvolt/internal/ui"
	"github.com/iluxav/nvolt/internal/vault"
	"github.com/spf13/cobra"
)

var vaultCmd = &cobra.Command{
	Use:   "vault",
	Short: "Vault management and verification commands",
	Long:  `Show vault information and verify integrity.`,
}

var vaultShowCmd = &cobra.Command{
	Use:   "show",
	Short: "Display vault information and machine access",
	Long: `Show all registered machines, their fingerprints, access timestamps,
and available environments.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runVaultShow()
	},
}

var vaultVerifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Verify vault integrity",
	Long: `Verify the integrity of encrypted files, wrapped keys, and vault structure.

This checks:
- All encrypted files are readable
- Wrapped keys are valid
- Machine public keys match fingerprints
- keyinfo.json structure is valid`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runVaultVerify()
	},
}

func runVaultShow() error {
	// Find vault path
	vaultPath, err := findVaultPath()
	if err != nil {
		return err
	}

	// TODO: In global mode with multiple projects, this should show project-specific info
	// For now, we use empty project name which works for local mode
	paths := vault.GetVaultPaths(vaultPath, "")

	ui.Section("Vault Information")
	fmt.Println()

	// Show vault location
	ui.PrintKeyValue("Vault Location", ui.Gray(vaultPath))
	fmt.Println()

	// Get current machine info
	currentMachineInfo, err := vault.LoadMachineInfo()
	if err != nil {
		ui.Warning("Could not load current machine info: %v\n", err)
	} else {
		ui.Section("Current Machine:")
		ui.PrintKeyValue("  ID", ui.Cyan(currentMachineInfo.ID))
		ui.PrintKeyValue("  Hostname", currentMachineInfo.Hostname)
		ui.PrintKeyValue("  Fingerprint", ui.Gray(currentMachineInfo.Fingerprint))
		fmt.Println()
	}

	// List all machines
	machines, err := vault.ListMachines(paths)
	if err != nil {
		return fmt.Errorf("failed to list machines: %w", err)
	}

	// List environments first to show access per environment
	envDirs, err := vault.ListDirs(paths.Secrets)
	if err != nil {
		ui.Warning("Could not list environments: %v", err)
		envDirs = []string{}
	}

	environments := []string{}
	for _, envDir := range envDirs {
		environments = append(environments, vault.GetDirName(envDir))
	}

	ui.Section(fmt.Sprintf("Registered Machines (%d):", len(machines)))
	if len(machines) == 0 {
		ui.Info(ui.Gray("  (none)"))
	} else {
		for _, m := range machines {
			fmt.Println()
			ui.Info(fmt.Sprintf("  Machine: %s", ui.Cyan(m.ID)))
			ui.PrintKeyValue("    Hostname", m.Hostname)
			ui.PrintKeyValue("    Fingerprint", ui.Gray(m.Fingerprint))
			ui.PrintKeyValue("    Created", ui.Gray(m.CreatedAt.Format(time.RFC3339)))
			if m.Description != "" {
				ui.PrintKeyValue("    Description", m.Description)
			}

			// Check access for each environment
			if len(environments) > 0 {
				ui.Info("    Access:")
				for _, env := range environments {
					wrappedKeyPath := paths.GetWrappedKeyPath(env, m.ID)
					hasKey := vault.FileExists(wrappedKeyPath)
					if hasKey {
						ui.Info(fmt.Sprintf("      %s: %s", ui.Cyan(env), ui.BrightGreen("✓")))
					} else {
						ui.Info(fmt.Sprintf("      %s: %s", ui.Gray(env), ui.Gray("✗")))
					}
				}
			} else {
				ui.Info(ui.Gray("    Access: (no environments)"))
			}
		}
	}

	fmt.Println()

	// List environments
	envDirs, err = vault.ListDirs(paths.Secrets)
	if err != nil {
		ui.Warning("Environments: (error listing: %v)", err)
		fmt.Println()
	} else if len(envDirs) == 0 {
		ui.Info(ui.Gray("Environments: (none)"))
		fmt.Println()
	} else {
		ui.Section(fmt.Sprintf("Environments (%d):", len(envDirs)))
		for _, envDir := range envDirs {
			envName := vault.GetDirName(envDir)
			secretFiles, err := vault.ListFiles(envDir)
			if err != nil {
				ui.Substep(fmt.Sprintf("%s %s", ui.Cyan(envName), ui.Red(fmt.Sprintf("(error: %v)", err))))
			} else {
				ui.Substep(fmt.Sprintf("%s (%d secret(s))", ui.Cyan(envName), len(secretFiles)))
			}
		}
		fmt.Println()
	}

	return nil
}

func runVaultVerify() error {
	// Find vault path
	vaultPath, err := findVaultPath()
	if err != nil {
		return err
	}

	// TODO: In global mode with multiple projects, this should verify all projects
	// For now, we use empty project name which works for local mode
	paths := vault.GetVaultPaths(vaultPath, "")

	ui.Section("Verifying Vault Integrity")
	fmt.Println()

	errors := []string{}
	warnings := []string{}

	// Check vault structure
	ui.Step("Checking vault structure")
	if err := vault.ValidateVaultStructure(vaultPath); err != nil {
		errors = append(errors, fmt.Sprintf("Vault structure invalid: %v", err))
	} else {
		ui.Success("Vault structure is valid")
	}

	// Check Git security
	ui.Step("Checking Git security")
	if err := vault.EnsurePrivateKeysNotInGit(vaultPath); err != nil {
		errors = append(errors, fmt.Sprintf("Private key security issue: %v", err))
	} else {
		ui.Success("Private keys are not in Git repository")
	}

	// Check .gitignore for sensitive patterns
	missing, err := vault.ValidateGitignore(vaultPath)
	if err != nil {
		warnings = append(warnings, fmt.Sprintf("Git ignore validation: %v", err))
	} else if len(missing) > 0 {
		for _, pattern := range missing {
			warnings = append(warnings, fmt.Sprintf("Missing .gitignore pattern: %s", pattern))
		}
	} else {
		ui.Success(".gitignore properly configured for sensitive files")
	}

	// Check current machine
	ui.Step("Checking current machine")
	currentMachine, err := vault.LoadMachineInfo()
	if err != nil {
		errors = append(errors, fmt.Sprintf("Cannot load current machine info: %v", err))
	} else {
		ui.Success("%s", fmt.Sprintf("Current machine: %s", ui.Cyan(currentMachine.ID)))

		// List environments to check access
		envDirs, err := vault.ListDirs(paths.Secrets)
		if err == nil && len(envDirs) > 0 {
			ui.Info("Checking access to environments...")
			// Load this machine's decrypter once for all environment checks.
			// A failure here (e.g. no key / token unavailable) is a warning,
			// not fatal: the rest of the vault report should still render.
			dec, closeDec, derr := keyprovider.LoadDecrypter()
			if derr != nil {
				warnings = append(warnings, fmt.Sprintf("Cannot load machine key to check environment access: %v", derr))
			} else {
				defer func() { _ = closeDec() }()
				for _, envDir := range envDirs {
					envName := vault.GetDirName(envDir)
					_, err := vault.UnwrapMasterKey(paths, envName, dec)
					if err != nil {
						warnings = append(warnings, fmt.Sprintf("Current machine cannot unwrap master key for '%s': %v", envName, err))
					} else {
						ui.Info(fmt.Sprintf("  %s Can access '%s'", ui.BrightGreen("✓"), ui.Cyan(envName)))
					}
				}
			}
		}
	}

	// Check machines
	ui.Step("Checking registered machines")
	machines, err := vault.ListMachines(paths)
	if err != nil {
		errors = append(errors, fmt.Sprintf("Cannot list machines: %v", err))
	} else {
		ui.Success("%s", fmt.Sprintf("Found %d machine(s)", len(machines)))

		// Get list of environments
		envDirs, err := vault.ListDirs(paths.Secrets)
		environments := []string{}
		if err == nil {
			for _, envDir := range envDirs {
				environments = append(environments, vault.GetDirName(envDir))
			}
		}

		// Check each machine has wrapped keys for environments
		if len(environments) > 0 {
			for _, m := range machines {
				hasAnyKey := false
				for _, env := range environments {
					wrappedKeyPath := paths.GetWrappedKeyPath(env, m.ID)
					if vault.FileExists(wrappedKeyPath) {
						hasAnyKey = true
						break
					}
				}
				if !hasAnyKey {
					warnings = append(warnings, fmt.Sprintf("Machine %s has no wrapped keys in any environment", m.ID))
				}
			}
		}
	}

	// Check wrapped keys for orphans
	ui.Step("Checking wrapped keys")

	// Get list of environments
	envDirs, err := vault.ListDirs(paths.Secrets)
	if err != nil {
		errors = append(errors, fmt.Sprintf("Cannot list environments: %v", err))
	} else {
		totalWrappedKeys := 0

		// Check for orphaned wrapped keys
		machineIDs := make(map[string]bool)
		for _, m := range machines {
			machineIDs[m.ID] = true
		}

		// Iterate through each environment's wrapped keys
		for _, envDir := range envDirs {
			envName := vault.GetDirName(envDir)
			wrappedKeysEnvPath := paths.GetWrappedKeysEnvPath(envName)

			wrappedKeyFiles, err := vault.ListFiles(wrappedKeysEnvPath)
			if err != nil {
				// Skip if directory doesn't exist
				continue
			}

			totalWrappedKeys += len(wrappedKeyFiles)

			for _, keyFile := range wrappedKeyFiles {
				// Extract machine ID from filename (remove .json)
				filename := vault.GetDirName(keyFile)
				machineID := filename
				if len(filename) > 5 && filename[len(filename)-5:] == ".json" {
					machineID = filename[:len(filename)-5]
				}

				if !machineIDs[machineID] {
					warnings = append(warnings, fmt.Sprintf("Orphaned wrapped key found: %s/%s", envName, filename))
				}
			}
		}

		ui.Success("%s", fmt.Sprintf("Found %d wrapped key(s) across all environments", totalWrappedKeys))
	}

	// Check secrets
	ui.Step("Checking secrets")
	envDirs, err = vault.ListDirs(paths.Secrets)
	if err != nil {
		errors = append(errors, fmt.Sprintf("Cannot list environments: %v", err))
	} else {
		totalSecrets := 0
		for _, envDir := range envDirs {
			secretFiles, err := vault.ListFiles(envDir)
			if err != nil {
				warnings = append(warnings, fmt.Sprintf("Cannot list secrets in %s: %v", envDir, err))
				continue
			}
			totalSecrets += len(secretFiles)
		}
		ui.Success("%s", fmt.Sprintf("Found %d secret(s) across %d environment(s)", totalSecrets, len(envDirs)))
	}

	// Print summary
	ui.Section("Summary")

	if len(errors) > 0 {
		fmt.Printf("\n%s (%d):\n", ui.Red("Errors"), len(errors))
		for _, e := range errors {
			fmt.Printf("  %s %s\n", ui.Red("✗"), e)
		}
	}

	if len(warnings) > 0 {
		fmt.Printf("\n%s (%d):\n", ui.Yellow("Warnings"), len(warnings))
		for _, w := range warnings {
			fmt.Printf("  %s %s\n", ui.Yellow("⚠"), w)
		}
	}

	if len(errors) == 0 && len(warnings) == 0 {
		fmt.Println()
		ui.Success("Vault is healthy - no issues found")
	} else if len(errors) == 0 {
		fmt.Println()
		ui.Success("Vault is functional but has warnings")
	} else {
		fmt.Println()
		ui.Error("Vault has errors that need attention")
		return fmt.Errorf("vault verification failed with %d error(s)", len(errors))
	}

	return nil
}

func init() {
	vaultCmd.AddCommand(vaultShowCmd)
	vaultCmd.AddCommand(vaultVerifyCmd)
	rootCmd.AddCommand(vaultCmd)
}
