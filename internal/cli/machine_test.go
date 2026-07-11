package cli

import (
	"crypto/rand"
	"crypto/rsa"
	"os"
	"path/filepath"
	"strings"
	"testing"

	nvcrypto "github.com/iluxav/nvolt/internal/crypto"
	"github.com/iluxav/nvolt/internal/hsmtest"
	"github.com/iluxav/nvolt/internal/vault"
	"github.com/iluxav/nvolt/pkg/types"
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

// TestMachineAddExternalSourceRegistersPubkeyNoPrivateKey drives runMachineAdd
// end-to-end (not just machineAddPublicKey) with a --pubkey external source
// against a real local vault. It proves the registered vault MachineInfo
// carries the provided public key with no KeySource set, that no software
// private_key.pem is ever written to the machine's home directory (the
// private key never passed through this process — it lives wherever the
// caller already keeps it), and that the printed output announces the
// registration ("Registered") without the "save this private key" hand-off
// section that only applies to the software-keygen path (see runMachineAdd's
// privateKeyPEM != nil branch in internal/cli/machine.go).
func TestMachineAddExternalSourceRegistersPubkeyNoPrivateKey(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	vaultDir := t.TempDir()
	t.Chdir(vaultDir)

	vaultPath := filepath.Join(vaultDir, ".nvolt")
	if err := vault.InitializeVaultDirectory(vaultPath); err != nil {
		t.Fatalf("InitializeVaultDirectory: %v", err)
	}

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

	const machineName = "ext-machine"
	out, err := captureStdout(func() error {
		return runMachineAdd(machineName, machineAddSource{pubkeyFile: pubPath})
	})
	if err != nil {
		t.Fatalf("runMachineAdd: %v\noutput:\n%s", err, out)
	}

	paths := vault.GetVaultPaths(vaultPath, "")
	machines, err := vault.ListMachines(paths)
	if err != nil {
		t.Fatalf("ListMachines: %v", err)
	}
	var mi *types.MachineInfo
	for _, m := range machines {
		if m.Hostname == machineName {
			mi = m
		}
	}
	if mi == nil {
		t.Fatalf("machine %q not found in vault after add; output:\n%s", machineName, out)
	}
	if mi.PublicKey == "" {
		t.Fatal("expected a non-empty registered PublicKey")
	}
	if mi.KeySource != nil {
		t.Fatalf("expected nil KeySource for a --pubkey-sourced machine, got %+v", mi.KeySource)
	}

	homePaths, err := vault.GetHomePaths()
	if err != nil {
		t.Fatal(err)
	}
	if vault.FileExists(homePaths.PrivateKey) {
		t.Fatal("expected no software private_key.pem written for an external-source machine")
	}

	if !strings.Contains(out, "Registered") {
		t.Fatalf("expected output to announce the registration, got:\n%s", out)
	}
	if strings.Contains(out, "save this securely") {
		t.Fatalf("did not expect the software-keygen private-key hand-off text, got:\n%s", out)
	}
}
