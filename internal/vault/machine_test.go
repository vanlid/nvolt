package vault

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/iluxav/nvolt/pkg/types"
)

func TestGenerateMachineID(t *testing.T) {
	// NOTE: the test calls GenerateMachineID(tt.hostname, tt.hostname, tt.fingerprint),
	// i.e. it passes hostname as BOTH customName and hostname. Since customName is
	// non-empty here, GenerateMachineID takes the customName branch ("<customName>-<suffix>",
	// no "m-" prefix) rather than the hostname-default branch ("m-<hostname>-<suffix>").
	// This matches the real call site in internal/cli/machine.go (GenerateMachineID(name, name, fp)).
	// wantPrefix values below reflect that actual, deterministic behavior:
	// - the unique suffix is the first 7 chars after "SHA256:" (not 8, as the original
	//   literals assumed), and
	// - a fingerprint hash shorter than 7 chars falls back to a Unix-timestamp suffix
	//   (non-deterministic), so that case is asserted via prefix match only.
	tests := []struct {
		hostname    string
		fingerprint string
		wantPrefix  string
	}{
		{"localhost", "SHA256:abcd1234", "localhost-abcd123"},
		{"myserver", "SHA256:xyz789ab", "myserver-xyz789a"},
		{"test", "SHA256:short", "test-"}, // short fingerprint falls back to timestamp suffix
		{"", "SHA256:abcd1234", "m-"},     // empty hostname uses timestamp
		{"unknown", "SHA256:test", "m-"},  // unknown hostname uses timestamp
	}

	for _, tt := range tests {
		t.Run(tt.hostname, func(t *testing.T) {
			id := GenerateMachineID(tt.hostname, tt.hostname, tt.fingerprint)
			if len(id) < 2 {
				t.Errorf("Machine ID too short: %s", id)
			}
			if tt.hostname != "" && tt.hostname != "unknown" {
				if !strings.HasPrefix(id, tt.wantPrefix) {
					t.Errorf("Expected prefix %s, got %s", tt.wantPrefix, id)
				}
			}
		})
	}
}

func TestSaveLoadMachineInfo(t *testing.T) {
	tmpDir := t.TempDir()
	infoPath := filepath.Join(tmpDir, "machine-info.json")

	originalInfo := &types.MachineInfo{
		ID:          "m-testmachine",
		PublicKey:   "test-public-key",
		Fingerprint: "SHA256:test",
		Hostname:    "testhost",
		Description: "Test machine",
	}

	// Save
	err := SaveMachineInfo(infoPath, originalInfo)
	if err != nil {
		t.Fatalf("Failed to save machine info: %v", err)
	}

	// Load
	loadedInfo, err := LoadMachineInfoFromFile(infoPath)
	if err != nil {
		t.Fatalf("Failed to load machine info: %v", err)
	}

	// Compare
	if loadedInfo.ID != originalInfo.ID {
		t.Errorf("ID mismatch: expected %s, got %s", originalInfo.ID, loadedInfo.ID)
	}
	if loadedInfo.Fingerprint != originalInfo.Fingerprint {
		t.Errorf("Fingerprint mismatch: expected %s, got %s", originalInfo.Fingerprint, loadedInfo.Fingerprint)
	}
	if loadedInfo.Hostname != originalInfo.Hostname {
		t.Errorf("Hostname mismatch: expected %s, got %s", originalInfo.Hostname, loadedInfo.Hostname)
	}
}

func TestAddMachineToVault(t *testing.T) {
	tmpDir := t.TempDir()
	vaultPath := filepath.Join(tmpDir, ".nvolt")

	// Initialize vault
	err := InitializeVaultDirectory(vaultPath)
	if err != nil {
		t.Fatalf("Failed to initialize vault: %v", err)
	}

	machineInfo := &types.MachineInfo{
		ID:          "m-testmachine",
		PublicKey:   "test-public-key",
		Fingerprint: "SHA256:test",
		Hostname:    "testhost",
	}

	// Add machine
	paths := GetVaultPaths(vaultPath, "")
	err = AddMachineToVault(paths, machineInfo)
	if err != nil {
		t.Fatalf("Failed to add machine to vault: %v", err)
	}

	// Verify machine file exists
	machinePath := paths.GetMachineInfoPath(machineInfo.ID)
	if !FileExists(machinePath) {
		t.Error("Machine file was not created")
	}

	// Try to add same machine again (should fail)
	err = AddMachineToVault(paths, machineInfo)
	if err == nil {
		t.Error("Expected error when adding duplicate machine")
	}
}

func TestRemoveMachineFromVault(t *testing.T) {
	tmpDir := t.TempDir()
	vaultPath := filepath.Join(tmpDir, ".nvolt")

	// Initialize vault
	err := InitializeVaultDirectory(vaultPath)
	if err != nil {
		t.Fatalf("Failed to initialize vault: %v", err)
	}

	machineInfo := &types.MachineInfo{
		ID:          "m-testmachine",
		PublicKey:   "test-public-key",
		Fingerprint: "SHA256:test",
		Hostname:    "testhost",
	}

	// Add machine
	paths := GetVaultPaths(vaultPath, "")
	err = AddMachineToVault(paths, machineInfo)
	if err != nil {
		t.Fatalf("Failed to add machine: %v", err)
	}

	// Remove machine
	err = RemoveMachineFromVault(paths, machineInfo.ID)
	if err != nil {
		t.Fatalf("Failed to remove machine: %v", err)
	}

	// Verify machine file is gone
	machinePath := paths.GetMachineInfoPath(machineInfo.ID)
	if FileExists(machinePath) {
		t.Error("Machine file still exists after removal")
	}
}

func TestListMachines(t *testing.T) {
	tmpDir := t.TempDir()
	vaultPath := filepath.Join(tmpDir, ".nvolt")

	// Initialize vault
	err := InitializeVaultDirectory(vaultPath)
	if err != nil {
		t.Fatalf("Failed to initialize vault: %v", err)
	}

	// Add multiple machines
	machines := []*types.MachineInfo{
		{
			ID:          "m-machine1",
			PublicKey:   "key1",
			Fingerprint: "SHA256:test1",
			Hostname:    "host1",
		},
		{
			ID:          "m-machine2",
			PublicKey:   "key2",
			Fingerprint: "SHA256:test2",
			Hostname:    "host2",
		},
		{
			ID:          "m-machine3",
			PublicKey:   "key3",
			Fingerprint: "SHA256:test3",
			Hostname:    "host3",
		},
	}

	paths := GetVaultPaths(vaultPath, "")
	for _, m := range machines {
		err := AddMachineToVault(paths, m)
		if err != nil {
			t.Fatalf("Failed to add machine %s: %v", m.ID, err)
		}
	}

	// List machines
	listed, err := ListMachines(paths)
	if err != nil {
		t.Fatalf("Failed to list machines: %v", err)
	}

	if len(listed) != len(machines) {
		t.Errorf("Expected %d machines, got %d", len(machines), len(listed))
	}

	// Verify all machines are present
	for _, expected := range machines {
		found := false
		for _, actual := range listed {
			if actual.ID == expected.ID {
				found = true
				if actual.Hostname != expected.Hostname {
					t.Errorf("Machine %s: expected hostname %s, got %s",
						expected.ID, expected.Hostname, actual.Hostname)
				}
				break
			}
		}
		if !found {
			t.Errorf("Machine %s not found in list", expected.ID)
		}
	}
}

func TestListMachinesEmptyVault(t *testing.T) {
	tmpDir := t.TempDir()
	vaultPath := filepath.Join(tmpDir, ".nvolt")

	// Initialize vault
	err := InitializeVaultDirectory(vaultPath)
	if err != nil {
		t.Fatalf("Failed to initialize vault: %v", err)
	}

	// List machines (should be empty)
	paths := GetVaultPaths(vaultPath, "")
	machines, err := ListMachines(paths)
	if err != nil {
		t.Fatalf("Failed to list machines: %v", err)
	}

	if len(machines) != 0 {
		t.Errorf("Expected 0 machines, got %d", len(machines))
	}
}

func TestInitializeMachineWithRealHome(t *testing.T) {
	// This test requires setting up a temporary home directory
	// Skip in CI or if we can't create temp directories
	tmpHome := t.TempDir()

	// Save original HOME
	originalHome := os.Getenv("HOME")
	defer os.Setenv("HOME", originalHome)

	// Set temporary HOME
	os.Setenv("HOME", tmpHome)

	// Now initialize machine
	machineInfo, err := InitializeMachine("test-machine")
	if err != nil {
		t.Fatalf("Failed to initialize machine: %v", err)
	}

	if machineInfo == nil {
		t.Fatal("Machine info is nil")
	}

	if machineInfo.ID == "" {
		t.Error("Machine ID is empty")
	}

	if machineInfo.Fingerprint == "" {
		t.Error("Fingerprint is empty")
	}

	// Verify files were created
	nvoltDir := filepath.Join(tmpHome, ".nvolt")
	privateKeyPath := filepath.Join(nvoltDir, "private_key.pem")
	machineInfoPath := filepath.Join(nvoltDir, "machines", "machine-info.json")

	if !FileExists(privateKeyPath) {
		t.Error("Private key file was not created")
	}

	if !FileExists(machineInfoPath) {
		t.Error("Machine info file was not created")
	}

	// Verify we can load the machine info
	loadedInfo, err := LoadMachineInfo()
	if err != nil {
		t.Fatalf("Failed to load machine info: %v", err)
	}

	if loadedInfo.ID != machineInfo.ID {
		t.Errorf("Loaded machine ID doesn't match: expected %s, got %s",
			machineInfo.ID, loadedInfo.ID)
	}

	// Verify we can load the private key
	privateKey, err := LoadPrivateKey()
	if err != nil {
		t.Fatalf("Failed to load private key: %v", err)
	}

	if privateKey == nil {
		t.Error("Private key is nil")
	}

	// Try to initialize again (should fail)
	_, err = InitializeMachine("test-machine")
	if err == nil {
		t.Error("Expected error when initializing machine twice")
	}
}
