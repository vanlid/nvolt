package cli

import (
	"crypto/rand"
	"crypto/rsa"
	"os"
	"strings"
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

func TestRebindSoftware_PrivkeyWritesIntoEmptySlot(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	if _, err := vault.InitializeMachine(""); err != nil {
		t.Fatalf("InitializeMachine: %v", err)
	}

	homePaths, err := vault.GetHomePaths()
	if err != nil {
		t.Fatalf("GetHomePaths: %v", err)
	}

	// Capture identity key A's PEM before removing it from the slot.
	identityPEM, err := os.ReadFile(homePaths.PrivateKey)
	if err != nil {
		t.Fatalf("read identity private key: %v", err)
	}
	identityKey, err := nvcrypto.DecodePrivateKeyPEM(identityPEM)
	if err != nil {
		t.Fatalf("decode identity private key: %v", err)
	}

	// Copy A's PEM out to a separate --privkey file.
	privkeyPath := t.TempDir() + "/identity-a.pem"
	if err := os.WriteFile(privkeyPath, identityPEM, 0600); err != nil {
		t.Fatalf("write privkey file: %v", err)
	}

	// Empty the slot.
	if err := os.Remove(homePaths.PrivateKey); err != nil {
		t.Fatalf("remove private key: %v", err)
	}
	if vault.FileExists(homePaths.PrivateKey) {
		t.Fatal("private key slot should be empty before rebind")
	}

	rebindPKCS11 = false
	rebindSoftware = true
	rebindModule = ""
	rebindURI = ""
	rebindPinMode = "prompt"
	rebindPrivkey = privkeyPath

	if err := runRebind(); err != nil {
		t.Fatalf("runRebind: %v", err)
	}

	if !vault.FileExists(homePaths.PrivateKey) {
		t.Fatal("rebind should have written the private key back into the empty slot")
	}

	written, err := os.ReadFile(homePaths.PrivateKey)
	if err != nil {
		t.Fatalf("read written private key: %v", err)
	}
	writtenKey, err := nvcrypto.DecodePrivateKeyPEM(written)
	if err != nil {
		t.Fatalf("decode written private key: %v", err)
	}
	if !samePublicKey(&writtenKey.PublicKey, &identityKey.PublicKey) {
		t.Fatal("written key's public key must match identity A")
	}

	mi2, err := vault.LoadMachineInfo()
	if err != nil {
		t.Fatalf("LoadMachineInfo after rebind: %v", err)
	}
	if mi2.KeySource == nil || mi2.KeySource.Source != "software" {
		t.Fatalf("expected key_source to be software after rebind, got %+v", mi2.KeySource)
	}
}

func TestRebindSoftware_PrivkeyRefusesWhenExistingDiffers(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	if _, err := vault.InitializeMachine(""); err != nil {
		t.Fatalf("InitializeMachine: %v", err)
	}

	homePaths, err := vault.GetHomePaths()
	if err != nil {
		t.Fatalf("GetHomePaths: %v", err)
	}

	// Capture identity key A's PEM before overwriting the slot.
	identityPEM, err := os.ReadFile(homePaths.PrivateKey)
	if err != nil {
		t.Fatalf("read identity private key: %v", err)
	}

	privkeyPath := t.TempDir() + "/identity-a.pem"
	if err := os.WriteFile(privkeyPath, identityPEM, 0600); err != nil {
		t.Fatalf("write privkey file: %v", err)
	}

	// Overwrite the on-disk slot with a DIFFERENT freshly-generated key B.
	keyB, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	keyBPEM, err := nvcrypto.EncodePrivateKeyPEM(keyB)
	if err != nil {
		t.Fatalf("encode key B: %v", err)
	}
	if err := vault.WriteFileAtomic(homePaths.PrivateKey, keyBPEM, vault.PrivateKeyPerm); err != nil {
		t.Fatalf("WriteFileAtomic: %v", err)
	}

	rebindPKCS11 = false
	rebindSoftware = true
	rebindModule = ""
	rebindURI = ""
	rebindPinMode = "prompt"
	rebindPrivkey = privkeyPath

	err = runRebind()
	if err == nil {
		t.Fatal("expected runRebind to refuse when existing key differs from identity")
	}
	if !strings.Contains(err.Error(), "remove or relocate") {
		t.Fatalf("expected 'remove or relocate' error, got: %v", err)
	}

	// File must survive unchanged, still holding key B (not A).
	if !vault.FileExists(homePaths.PrivateKey) {
		t.Fatal("private key file must not be deleted on refusal")
	}
	after, err := os.ReadFile(homePaths.PrivateKey)
	if err != nil {
		t.Fatalf("read private key after refusal: %v", err)
	}
	afterKey, err := nvcrypto.DecodePrivateKeyPEM(after)
	if err != nil {
		t.Fatalf("decode private key after refusal: %v", err)
	}
	if !samePublicKey(&afterKey.PublicKey, &keyB.PublicKey) {
		t.Fatal("private key on disk must still be key B, unchanged")
	}
}

func TestRebindSoftware_PrivkeyDoesNotMatchIdentity(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	if _, err := vault.InitializeMachine(""); err != nil {
		t.Fatalf("InitializeMachine: %v", err)
	}

	homePaths, err := vault.GetHomePaths()
	if err != nil {
		t.Fatalf("GetHomePaths: %v", err)
	}

	// Preserve the identity key's bytes so we can confirm nothing changed.
	before, err := os.ReadFile(homePaths.PrivateKey)
	if err != nil {
		t.Fatalf("read identity private key: %v", err)
	}

	// An unrelated key C, unconnected to this machine's identity.
	keyC, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	keyCPEM, err := nvcrypto.EncodePrivateKeyPEM(keyC)
	if err != nil {
		t.Fatalf("encode key C: %v", err)
	}
	privkeyPath := t.TempDir() + "/identity-c.pem"
	if err := os.WriteFile(privkeyPath, keyCPEM, 0600); err != nil {
		t.Fatalf("write privkey file: %v", err)
	}

	rebindPKCS11 = false
	rebindSoftware = true
	rebindModule = ""
	rebindURI = ""
	rebindPinMode = "prompt"
	rebindPrivkey = privkeyPath

	err = runRebind()
	if err == nil {
		t.Fatal("expected runRebind to reject a --privkey that doesn't match identity")
	}
	if !strings.Contains(err.Error(), "doesn't match this machine's identity") {
		t.Fatalf("expected identity-mismatch error, got: %v", err)
	}

	after, err := os.ReadFile(homePaths.PrivateKey)
	if err != nil {
		t.Fatalf("read private key after rejection: %v", err)
	}
	if string(after) != string(before) {
		t.Fatal("private key file must be unchanged when --privkey doesn't match identity")
	}
}
