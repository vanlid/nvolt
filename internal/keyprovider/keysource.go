package keyprovider

import (
	"encoding/json"
	"fmt"

	"github.com/iluxav/nvolt/internal/vault"
	"github.com/iluxav/nvolt/pkg/types"
)

// loadKeySource returns the key source configured for this machine, read
// from ~/.nvolt/machines/machine-info.json (MachineInfo.KeySource). If the
// file or the field is absent, it defaults to software so existing machines
// keep working without any migration.
func loadKeySource() (types.KeySource, error) {
	homePaths, err := vault.GetHomePaths()
	if err != nil {
		return types.KeySource{}, err
	}

	if !vault.FileExists(homePaths.MachineInfo) {
		return types.KeySource{Source: "software"}, nil
	}

	machineInfo, err := vault.LoadMachineInfoFromFile(homePaths.MachineInfo)
	if err != nil {
		return types.KeySource{}, err
	}

	if machineInfo.KeySource == nil {
		return types.KeySource{Source: "software"}, nil
	}

	return *machineInfo.KeySource, nil
}

// saveKeySource persists the given key source into the current machine's
// machine-info.json, preserving all other machine info fields. It writes
// atomically via vault.WriteFileAtomic, matching SaveMachineInfo's pattern.
func saveKeySource(src *types.KeySource) error {
	homePaths, err := vault.GetHomePaths()
	if err != nil {
		return err
	}

	machineInfo, err := vault.LoadMachineInfoFromFile(homePaths.MachineInfo)
	if err != nil {
		return fmt.Errorf("failed to load machine info: %w", err)
	}

	machineInfo.KeySource = src

	data, err := json.MarshalIndent(machineInfo, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal machine info: %w", err)
	}

	if err := vault.WriteFileAtomic(homePaths.MachineInfo, data, vault.FilePerm); err != nil {
		return fmt.Errorf("failed to write machine info: %w", err)
	}

	return nil
}
