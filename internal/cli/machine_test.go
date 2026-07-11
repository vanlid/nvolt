package cli

import (
	"crypto/rand"
	"crypto/rsa"
	"os"
	"path/filepath"
	"testing"

	nvcrypto "github.com/iluxav/nvolt/internal/crypto"
	"github.com/iluxav/nvolt/internal/hsmtest"
)

// TestMachineAddFromPubkeyFile proves machineAddPublicKey reads and decodes a
// --pubkey PEM file, returning the exact RSA public key it contains. No vault
// is involved: machineAddPublicKey only decodes+validates a pubkey source; it
// does not touch the vault.
func TestMachineAddFromPubkeyFile(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pubPEM, err := nvcrypto.EncodePublicKeyPEM(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	pubPath := filepath.Join(t.TempDir(), "pub.pem")
	if err := os.WriteFile(pubPath, pubPEM, 0o644); err != nil {
		t.Fatal(err)
	}

	pub, err := machineAddPublicKey(machineAddSource{pubkeyFile: pubPath})
	if err != nil {
		t.Fatalf("machineAddPublicKey: %v", err)
	}
	if pub == nil {
		t.Fatal("expected a non-nil pubkey")
	}
	if pub.N.Cmp(priv.N) != 0 {
		t.Fatal("wrong pubkey")
	}
}

// TestMachineAddPublicKeyRejectsSub2048 proves a sub-2048-bit public key from
// --pubkey is rejected, matching the minimum RSA size enforced everywhere
// else in nvolt (software keygen, PKCS#11 enroll).
func TestMachineAddPublicKeyRejectsSub2048(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	pubPEM, err := nvcrypto.EncodePublicKeyPEM(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "small.pem")
	if err := os.WriteFile(p, pubPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := machineAddPublicKey(machineAddSource{pubkeyFile: p}); err == nil {
		t.Fatal("expected sub-2048 rejection")
	}
}

// TestMachineAddSourceMutualExclusion proves --pubkey and --pkcs11 cannot be
// given together: a machine's identity has exactly one source.
func TestMachineAddSourceMutualExclusion(t *testing.T) {
	if _, err := machineAddPublicKey(machineAddSource{pubkeyFile: "a", pkcs11: true}); err == nil {
		t.Fatal("expected error when both --pubkey and --pkcs11 given")
	}
}

// TestMachineAddFromPKCS11 drives machineAddPublicKey's --pkcs11 branch
// against a real SoftHSM fixture token (internal/hsmtest), proving
// ReadTokenPublicKey reads the token's public key with no PIN supplied at
// all: the fixture token has a PIN configured, but this path must never need
// it (machine add --pkcs11 only registers a public key; no decrypt happens).
// Skipped unless NVOLT_TEST_PKCS11_MODULE is set.
func TestMachineAddFromPKCS11(t *testing.T) {
	mod := hsmtest.Provision(t)

	pub, err := machineAddPublicKey(machineAddSource{
		pkcs11: true,
		module: mod,
		uri:    "pkcs11:token=nvolt-test;id=%01;type=private",
	})
	if err != nil {
		t.Fatalf("machineAddPublicKey (pkcs11): %v", err)
	}
	if pub == nil {
		t.Fatal("expected a non-nil pubkey")
	}
	if pub.N.BitLen() < 2048 {
		t.Fatalf("expected >= 2048 bits, got %d", pub.N.BitLen())
	}
}
