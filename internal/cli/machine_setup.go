package cli

import (
	"fmt"

	"github.com/iluxav/nvolt/internal/ui"
	"github.com/iluxav/nvolt/internal/vault"
)

// EnsureMachineInitialized ensures the machine is initialized with keypair and name
// Prompts for custom machine name if this is the first initialization
func EnsureMachineInitialized() error {
	// Check if machine is already initialized
	initialized, err := vault.IsMachineInitialized()
	if err != nil {
		return err
	}

	if initialized {
		return nil
	}

	// First time setup - prompt for machine name
	ui.Info("")
	ui.Info(ui.Gold("⚙️  First-time Machine Setup"))
	ui.Info("This machine needs to be initialized before using nvolt.")
	ui.Info("")

	customName, err := ui.PromptMachineName()
	if err != nil {
		return err
	}

	// Initialize machine with custom name (or empty for auto-generated)
	machineInfo, err := vault.InitializeMachine(customName)
	if err != nil {
		return err
	}

	ui.Success("Machine initialized successfully")
	ui.Info(ui.Cyan("Machine ID: ") + ui.Bold(machineInfo.ID))
	ui.Info("")

	return nil
}

// pkcs11Name is both the machine-info key_source.source value for a
// hardware-token-backed identity and the `nvolt pkcs11` subcommand name.
const pkcs11Name = "pkcs11"

// pkcs11InitAction enumerates how init/join should treat this machine's
// existing identity (if any) when --pkcs11 is requested.
type pkcs11InitAction int

const (
	// pkcs11ActionEnroll: no identity yet — enroll the on-card key now.
	pkcs11ActionEnroll pkcs11InitAction = iota
	// pkcs11ActionReuse: a PKCS#11 identity already exists — reuse it as-is.
	pkcs11ActionReuse
	// pkcs11ActionSoftwareConflict: a software identity exists. We refuse to
	// silently replace it: overwriting would orphan every secret wrapped to the
	// software key (the master key is not re-wrapped). Switching is a deliberate
	// manual step today, and a proper migration flow is future work.
	pkcs11ActionSoftwareConflict
)

// decidePKCS11InitAction mirrors software init's idempotency for the --pkcs11
// path: an already-enrolled PKCS#11 identity is reused, a software identity is
// left untouched (the caller reports a conflict), and anything else enrolls. It
// is pure so the reuse/conflict/enroll policy is testable without a token or a
// terminal. existingSource is machine-info's key_source.source ("pkcs11",
// "software", or "" when unknown/absent).
func decidePKCS11InitAction(initialized bool, existingSource string) pkcs11InitAction {
	if !initialized {
		return pkcs11ActionEnroll
	}
	if existingSource == pkcs11Name {
		return pkcs11ActionReuse
	}
	return pkcs11ActionSoftwareConflict
}

// ensurePKCS11MachineInitialized establishes a PKCS#11-backed identity for
// init/join, mirroring EnsureMachineInitialized's idempotency: re-running init
// on an already-enrolled hardware machine is a no-op that proceeds to vault
// setup, an existing software identity is reported as a conflict (never
// silently replaced), and a first-time run enrolls the on-card key.
func ensurePKCS11MachineInitialized(opts *pkcs11EnrollOpts) error {
	initialized, err := vault.IsMachineInitialized()
	if err != nil {
		return fmt.Errorf("failed to check machine state: %w", err)
	}

	var existingID, existingSource string
	if initialized {
		mi, err := vault.LoadMachineInfo()
		if err != nil {
			return fmt.Errorf("failed to load machine info: %w", err)
		}
		existingID = mi.ID
		if mi.KeySource != nil {
			existingSource = mi.KeySource.Source
		}
	}

	switch decidePKCS11InitAction(initialized, existingSource) {
	case pkcs11ActionReuse:
		ui.Step("Reusing existing PKCS#11-backed machine identity")
		return nil
	case pkcs11ActionSoftwareConflict:
		homePaths, err := vault.GetHomePaths()
		if err != nil {
			return err
		}
		return fmt.Errorf("this machine already has a software identity %q; switching it to a PKCS#11 key isn't supported yet (it would orphan secrets wrapped to the software key). To re-initialize from scratch, remove %s first", existingID, homePaths.MachineInfo)
	default: // pkcs11ActionEnroll
		ui.Step("Enrolling PKCS#11-backed machine identity")
		if err := enrollPKCS11Machine(opts.module, opts.uri, opts.pinMode); err != nil {
			return fmt.Errorf("failed to enroll PKCS#11 machine: %w", err)
		}
		return nil
	}
}
