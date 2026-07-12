package keyprovider

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	nvcrypto "github.com/iluxav/nvolt/internal/crypto"
	"github.com/iluxav/nvolt/internal/vault"
)

// withTempNvoltConfig points NVOLT_CONFIG at a fresh temp dir for the
// duration of the test and restores the previous value afterwards.
func withTempNvoltConfig(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), ".nvolt")

	original, had := os.LookupEnv("NVOLT_CONFIG")
	if err := os.Setenv("NVOLT_CONFIG", dir); err != nil {
		t.Fatalf("failed to set NVOLT_CONFIG: %v", err)
	}
	t.Cleanup(func() {
		if had {
			_ = os.Setenv("NVOLT_CONFIG", original)
		} else {
			_ = os.Unsetenv("NVOLT_CONFIG")
		}
	})

	return dir
}

func TestLoadSoftwareDecrypterRoundTrip(t *testing.T) {
	withTempNvoltConfig(t)

	if _, err := vault.InitializeMachine("test-machine"); err != nil {
		t.Fatalf("failed to initialize machine: %v", err)
	}

	dec, closeFn, err := loadSoftwareDecrypter()
	if err != nil {
		t.Fatalf("loadSoftwareDecrypter() error = %v", err)
	}
	if dec == nil {
		t.Fatal("loadSoftwareDecrypter() returned nil decrypter")
	}
	if closeFn == nil {
		t.Fatal("loadSoftwareDecrypter() returned nil close func")
	}
	if err := closeFn(); err != nil {
		t.Fatalf("closeFn() error = %v", err)
	}

	aesKey, err := nvcrypto.GenerateAESKey()
	if err != nil {
		t.Fatalf("GenerateAESKey() error = %v", err)
	}

	// Load the same private key independently to get its public half for
	// wrapping (dec only exposes the crypto.Decrypter interface).
	privKey, err := vault.LoadPrivateKey()
	if err != nil {
		t.Fatalf("vault.LoadPrivateKey() error = %v", err)
	}

	wrapped, err := nvcrypto.WrapKey(&privKey.PublicKey, aesKey)
	if err != nil {
		t.Fatalf("WrapKey() error = %v", err)
	}

	got, err := nvcrypto.UnwrapKey(dec, wrapped)
	if err != nil {
		t.Fatalf("UnwrapKey() error = %v", err)
	}
	if !bytes.Equal(got, aesKey) {
		t.Fatal("unwrapped key does not match original")
	}
}

func TestLoadSoftwareDecrypterNoMachine(t *testing.T) {
	withTempNvoltConfig(t)

	// No InitializeMachine call: no private key on disk.
	_, _, err := loadSoftwareDecrypter()
	if err == nil {
		t.Fatal("expected error when no machine private key exists")
	}
}

func TestLoadDecrypterDefaultsToSoftware(t *testing.T) {
	withTempNvoltConfig(t)

	if _, err := vault.InitializeMachine("test-machine"); err != nil {
		t.Fatalf("failed to initialize machine: %v", err)
	}

	dec, closeFn, err := LoadDecrypter()
	if err != nil {
		t.Fatalf("LoadDecrypter() error = %v", err)
	}
	if dec == nil {
		t.Fatal("LoadDecrypter() returned nil decrypter")
	}
	if closeFn == nil {
		t.Fatal("LoadDecrypter() returned nil close func")
	}
	if err := closeFn(); err != nil {
		t.Fatalf("closeFn() error = %v", err)
	}
}
