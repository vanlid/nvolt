package keyprovider

import (
	"bytes"
	"os"
	"os/exec"
	"testing"
	"time"

	nvcrypto "github.com/iluxav/nvolt/internal/crypto"
	"github.com/iluxav/nvolt/internal/hsmtest"
	"github.com/iluxav/nvolt/internal/vault"
	"github.com/iluxav/nvolt/pkg/types"
)

// TestPushPullThroughPKCS11Machine exercises the full runtime envelope
// round-trip for a PKCS#11-backed machine: enroll an on-card key, persist a
// machine-info.json that points at it (KeySource + matching public key), then
// drive the exact push (wrap) / pull (unwrap) path through LoadDecrypter.
//
// LoadDecrypter dispatches to loadPKCS11Decrypter, which opens a token session
// and returns a crypto.Decrypter bound to the on-card key — the runtime Decrypt
// path Task 6 left without an end-to-end test. It PASSES (not skips) against
// SoftHSM, where the token lacks native OAEP-SHA256 and the decrypter therefore
// takes the "raw" RSA + software-OAEP-unpad branch.
//
// The real work runs in a dedicated CHILD process. Every other PKCS#11 test in
// this package Opens/Closes (C_Initialize/C_Finalize) the resident SoftHSM
// module; SoftHSM leaves that global state poisoned across repeated
// init/finalize cycles within one process, which would corrupt an on-card
// decrypt here (raw RSA returns garbage that fails OAEP unpad). Production never
// hits this — each nvolt invocation is a fresh process with exactly one module
// Open/Close — so a clean child process faithfully mirrors production and keeps
// this test deterministic regardless of test ordering.
func TestPushPullThroughPKCS11Machine(t *testing.T) {
	if os.Getenv("NVOLT_ROUNDTRIP_CHILD") != "1" {
		// Provision in the parent: it sets SOFTHSM2_CONF (via t.Setenv) and
		// creates the fixture token/keys under that temp dir. The child
		// below inherits both through os.Environ(), so it must NOT
		// provision again (that would spin up a second, disconnected
		// SOFTHSM2_CONF/token and leave the inherited one unused).
		hsmtest.Provision(t)

		cmd := exec.Command(os.Args[0], "-test.run", "^TestPushPullThroughPKCS11Machine$", "-test.v")
		cmd.Env = append(os.Environ(), "NVOLT_ROUNDTRIP_CHILD=1")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("round-trip child process failed: %v\n%s", err, out)
		}
		return
	}

	// Child process: NVOLT_TEST_PKCS11_MODULE and SOFTHSM2_CONF were
	// inherited from the parent's environment (set by hsmtest.Provision
	// above), which already provisioned the fixture token/keys.
	mod := os.Getenv("NVOLT_TEST_PKCS11_MODULE")
	if mod == "" {
		t.Skip("set NVOLT_TEST_PKCS11_MODULE to run PKCS#11 round-trip test")
	}

	t.Setenv("HOME", t.TempDir())
	t.Setenv("NVOLT_PKCS11_PIN", "1234")

	// Enroll the on-card key: returns the KeySource to persist plus the card's
	// public key (the private half never leaves the token).
	src, pub, err := Enroll(mod, "pkcs11:token=nvolt-test;id=%01;type=private", "env",
		func() (string, error) { return "1234", nil })
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}

	// Persist a machine-info.json whose stored public key matches the card's
	// private key and whose key_source points at the token, exactly as a real
	// pkcs11-enrolled machine has on disk. machinePublicKey() (used at runtime)
	// reads this stored PEM, so it must be the card's pub for the wrap/unwrap to
	// round-trip.
	if err := vault.InitializeHomeDirectory(); err != nil {
		t.Fatalf("InitializeHomeDirectory: %v", err)
	}
	homePaths, err := vault.GetHomePaths()
	if err != nil {
		t.Fatal(err)
	}
	pubPEM, err := nvcrypto.EncodePublicKeyPEM(pub)
	if err != nil {
		t.Fatalf("EncodePublicKeyPEM: %v", err)
	}
	mi := &types.MachineInfo{
		ID:        "m-test",
		PublicKey: string(pubPEM),
		Hostname:  "test",
		CreatedAt: time.Now(),
		KeySource: &src,
	}
	if err := vault.SaveMachineInfo(homePaths.MachineInfo, mi); err != nil {
		t.Fatalf("SaveMachineInfo: %v", err)
	}

	// Runtime pull/push path: LoadDecrypter opens the token session and returns
	// a crypto.Decrypter bound to the on-card key.
	dec, closeFn, err := LoadDecrypter()
	if err != nil {
		t.Fatalf("LoadDecrypter: %v", err)
	}
	defer closeFn()

	// push-side wrap to the card's public key, pull-side unwrap on the token.
	aes, err := nvcrypto.GenerateAESKey()
	if err != nil {
		t.Fatalf("GenerateAESKey: %v", err)
	}
	wrapped, err := nvcrypto.WrapKey(pub, aes)
	if err != nil {
		t.Fatalf("WrapKey: %v", err)
	}
	got, err := nvcrypto.UnwrapKey(dec, wrapped)
	if err != nil {
		t.Fatalf("UnwrapKey: %v", err)
	}
	if !bytes.Equal(got, aes) {
		t.Fatal("round-trip mismatch: unwrapped key != original master key")
	}
}
