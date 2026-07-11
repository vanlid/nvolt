package vault

import (
	"testing"
	"time"

	"github.com/iluxav/nvolt/pkg/types"
)

// TestIsMachineInitialized covers the identity-recognition rules that every
// runtime command (push/pull/run, via EnsureMachineInitialized) depends on:
// software machines require a private key on disk, whereas PKCS#11-backed
// machines — which keep no local private key — are recognized from their
// machine-info key_source alone. A regression here would make a hardware-backed
// machine look uninitialized and re-prompt to generate a software keypair.
func TestIsMachineInitialized(t *testing.T) {
	t.Run("no machine info returns false", func(t *testing.T) {
		t.Setenv("HOME", t.TempDir())
		ok, err := IsMachineInitialized()
		if err != nil {
			t.Fatalf("IsMachineInitialized: %v", err)
		}
		if ok {
			t.Fatal("expected false with no machine info")
		}
	})

	t.Run("software machine (info + private key) returns true", func(t *testing.T) {
		t.Setenv("HOME", t.TempDir())
		if _, err := InitializeMachine(""); err != nil {
			t.Fatalf("InitializeMachine: %v", err)
		}
		ok, err := IsMachineInitialized()
		if err != nil {
			t.Fatalf("IsMachineInitialized: %v", err)
		}
		if !ok {
			t.Fatal("expected true for a fully initialized software machine")
		}
	})

	t.Run("software machine info without private key returns false", func(t *testing.T) {
		t.Setenv("HOME", t.TempDir())
		if err := InitializeHomeDirectory(); err != nil {
			t.Fatalf("InitializeHomeDirectory: %v", err)
		}
		homePaths, err := GetHomePaths()
		if err != nil {
			t.Fatal(err)
		}
		// machine-info with a software key_source but NO private_key.pem on disk.
		writeMachineInfo(t, homePaths.MachineInfo, &types.KeySource{Source: "software"})

		ok, err := IsMachineInitialized()
		if err != nil {
			t.Fatalf("IsMachineInitialized: %v", err)
		}
		if ok {
			t.Fatal("expected false: software machine missing its private key")
		}
	})

	t.Run("pkcs11 machine (info only, no private key) returns true", func(t *testing.T) {
		t.Setenv("HOME", t.TempDir())
		if err := InitializeHomeDirectory(); err != nil {
			t.Fatalf("InitializeHomeDirectory: %v", err)
		}
		homePaths, err := GetHomePaths()
		if err != nil {
			t.Fatal(err)
		}
		// A hardware-backed machine has key_source=pkcs11 and deliberately no
		// private_key.pem on disk.
		writeMachineInfo(t, homePaths.MachineInfo, &types.KeySource{
			Source:   "pkcs11",
			Module:   "/x.so",
			URI:      "pkcs11:token=t;id=%01",
			PinMode:  "prompt",
			OAEPMode: "raw",
		})

		ok, err := IsMachineInitialized()
		if err != nil {
			t.Fatalf("IsMachineInitialized: %v", err)
		}
		if !ok {
			t.Fatal("expected true: pkcs11 machine is initialized without a local private key")
		}
	})
}

// writeMachineInfo persists a minimal MachineInfo carrying the given key_source.
func writeMachineInfo(t *testing.T, path string, src *types.KeySource) {
	t.Helper()
	mi := &types.MachineInfo{
		ID:        "m-test",
		PublicKey: "PEM",
		Hostname:  "test",
		CreatedAt: time.Now(),
		KeySource: src,
	}
	if err := SaveMachineInfo(path, mi); err != nil {
		t.Fatalf("SaveMachineInfo: %v", err)
	}
}
