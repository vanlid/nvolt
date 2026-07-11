package cli

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"

	nvcrypto "github.com/iluxav/nvolt/internal/crypto"
	"github.com/iluxav/nvolt/internal/vault"
)

func TestSamePublicKey(t *testing.T) {
	a, _ := rsa.GenerateKey(rand.Reader, 2048)
	b, _ := rsa.GenerateKey(rand.Reader, 2048)
	if !samePublicKey(&a.PublicKey, &a.PublicKey) {
		t.Fatal("same key should match")
	}
	if samePublicKey(&a.PublicKey, &b.PublicKey) {
		t.Fatal("different keys should not match")
	}
}

func TestRebindSoftwareToSoftware_NoOpFlipsConfigWithoutDeletingKey(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	if _, err := vault.InitializeMachine(""); err != nil {
		t.Fatalf("InitializeMachine: %v", err)
	}

	homePaths, err := vault.GetHomePaths()
	if err != nil {
		t.Fatalf("GetHomePaths: %v", err)
	}

	// InitializeMachine leaves KeySource nil (implicitly software-backed);
	// rebind --software should still succeed and make it explicit.

	// Reset package-level rebind flags before driving runRebind() directly.
	rebindPKCS11 = false
	rebindSoftware = true
	rebindModule = ""
	rebindURI = ""
	rebindPinMode = "prompt"
	rebindPrivkey = ""

	if err := runRebind(); err != nil {
		t.Fatalf("runRebind: %v", err)
	}

	if !vault.FileExists(homePaths.PrivateKey) {
		t.Fatal("private key file must not be deleted by rebind")
	}

	mi2, err := vault.LoadMachineInfo()
	if err != nil {
		t.Fatalf("LoadMachineInfo after rebind: %v", err)
	}
	if mi2.KeySource == nil || mi2.KeySource.Source != "software" {
		t.Fatalf("expected key_source to be software after rebind, got %+v", mi2.KeySource)
	}
}

func TestRebindSoftware_RefusesWhenExistingKeyDiffers(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	if _, err := vault.InitializeMachine(""); err != nil {
		t.Fatalf("InitializeMachine: %v", err)
	}

	homePaths, err := vault.GetHomePaths()
	if err != nil {
		t.Fatalf("GetHomePaths: %v", err)
	}

	// Overwrite the on-disk private key with an unrelated key so it no
	// longer matches the machine identity's public key.
	other, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	otherPEM, err := nvcrypto.EncodePrivateKeyPEM(other)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if err := vault.WriteFileAtomic(homePaths.PrivateKey, otherPEM, vault.PrivateKeyPerm); err != nil {
		t.Fatalf("WriteFileAtomic: %v", err)
	}

	rebindPKCS11 = false
	rebindSoftware = true
	rebindModule = ""
	rebindURI = ""
	rebindPinMode = "prompt"
	rebindPrivkey = ""

	err = runRebind()
	if err == nil {
		t.Fatal("expected runRebind to refuse when existing key differs from identity")
	}

	if !vault.FileExists(homePaths.PrivateKey) {
		t.Fatal("private key file must not be deleted even on refusal")
	}
}
