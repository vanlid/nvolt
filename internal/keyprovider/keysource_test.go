package keyprovider

import (
	"testing"

	"github.com/iluxav/nvolt/internal/vault"
	"github.com/iluxav/nvolt/pkg/types"
)

func TestLoadKeySourceDefaultsToSoftware(t *testing.T) {
	t.Setenv("HOME", t.TempDir()) // no machine.json present
	src, err := loadKeySource()
	if err != nil {
		t.Fatal(err)
	}
	if src.Source != "software" {
		t.Fatalf("want software, got %q", src.Source)
	}
}

// TestSaveKeySourceRoundTrip verifies that saveKeySource persists a
// KeySource into machine-info.json, that loadKeySource reads back exactly
// what was saved, and that all sibling MachineInfo fields (PublicKey,
// Fingerprint, Hostname, ID) survive the write untouched.
func TestSaveKeySourceRoundTrip(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	if _, err := vault.InitializeMachine(""); err != nil {
		t.Fatalf("InitializeMachine() error = %v", err)
	}

	homePaths, err := vault.GetHomePaths()
	if err != nil {
		t.Fatalf("GetHomePaths() error = %v", err)
	}

	before, err := vault.LoadMachineInfo()
	if err != nil {
		t.Fatalf("LoadMachineInfo() (before) error = %v", err)
	}
	if before.KeySource != nil {
		t.Fatalf("expected no key_source before saveKeySource, got %+v", before.KeySource)
	}

	want := types.KeySource{
		Source:   "pkcs11",
		Module:   "/x.so",
		URI:      "pkcs11:token=test;object=key",
		PinMode:  "prompt",
		OAEPMode: "raw",
	}

	if err := saveKeySource(&want); err != nil {
		t.Fatalf("saveKeySource() error = %v", err)
	}

	got, err := loadKeySource()
	if err != nil {
		t.Fatalf("loadKeySource() error = %v", err)
	}
	if got != want {
		t.Fatalf("loadKeySource() = %+v, want %+v", got, want)
	}

	after, err := vault.LoadMachineInfoFromFile(homePaths.MachineInfo)
	if err != nil {
		t.Fatalf("LoadMachineInfoFromFile() (after) error = %v", err)
	}

	if after.PublicKey != before.PublicKey {
		t.Errorf("PublicKey changed: before %q, after %q", before.PublicKey, after.PublicKey)
	}
	if after.Fingerprint != before.Fingerprint {
		t.Errorf("Fingerprint changed: before %q, after %q", before.Fingerprint, after.Fingerprint)
	}
	if after.Hostname != before.Hostname {
		t.Errorf("Hostname changed: before %q, after %q", before.Hostname, after.Hostname)
	}
	if after.ID != before.ID {
		t.Errorf("ID changed: before %q, after %q", before.ID, after.ID)
	}
}
