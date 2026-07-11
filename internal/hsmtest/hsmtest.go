// Package hsmtest provisions an isolated SoftHSM2 token for the PKCS#11
// integration tests, in-code (no external setup script). Each call to
// Provision points SOFTHSM2_CONF at a fresh t.TempDir()-scoped token
// directory, so repeated/parallel test runs never share or accumulate
// tokens/keys.
package hsmtest

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// Fixture token/key identifiers the PKCS#11 integration tests target.
const (
	// TokenLabel is the SoftHSM token label Provision creates.
	TokenLabel = "nvolt-test"
	// PIN is the fixture token's user PIN.
	PIN = "1234"
	// SOPIN is the fixture token's security-officer PIN (init-time only).
	SOPIN = "5678"

	// KeyLabel/KeyID identify the 2048-bit RSA key Provision generates.
	KeyLabel = "nvolt-test"
	KeyID    = "01"

	// WeakKeyLabel/WeakKeyID identify the 1024-bit (sub-minimum) RSA key
	// Provision generates, used to exercise the enroll bit-size rejection.
	WeakKeyLabel = "nvolt-weak"
	WeakKeyID    = "02"
)

// Provision creates an isolated SoftHSM2 token (label TokenLabel, PIN PIN)
// holding a 2048-bit RSA key (label/id KeyLabel/KeyID) and a 1024-bit RSA key
// (label/id WeakKeyLabel/WeakKeyID), then returns the PKCS#11 module path to
// use against it (the value of NVOLT_TEST_PKCS11_MODULE).
//
// It skips the calling test cleanly when PKCS#11 integration tests aren't
// configured (NVOLT_TEST_PKCS11_MODULE unset) or the SoftHSM CLI tooling
// isn't installed. SOFTHSM2_CONF is set via t.Setenv against a fresh
// t.TempDir(), so it's automatically scoped to (and cleaned up with) the
// calling test.
func Provision(t testing.TB) string {
	t.Helper()

	module := os.Getenv("NVOLT_TEST_PKCS11_MODULE")
	if module == "" {
		t.Skip("set NVOLT_TEST_PKCS11_MODULE to run PKCS#11 integration tests")
	}
	if _, err := exec.LookPath("softhsm2-util"); err != nil {
		t.Skip("softhsm2-util/pkcs11-tool not installed")
	}
	if _, err := exec.LookPath("pkcs11-tool"); err != nil {
		t.Skip("softhsm2-util/pkcs11-tool not installed")
	}

	dir := t.TempDir()
	tokenDir := filepath.Join(dir, "tokens")
	if err := os.MkdirAll(tokenDir, 0o700); err != nil {
		t.Fatalf("hsmtest: mkdir tokendir: %v", err)
	}
	confPath := filepath.Join(dir, "softhsm2.conf")
	conf := fmt.Sprintf("directories.tokendir = %s\nobjectstore.backend = file\n", tokenDir)
	if err := os.WriteFile(confPath, []byte(conf), 0o600); err != nil {
		t.Fatalf("hsmtest: write softhsm2.conf: %v", err)
	}
	// Scoped to this test: restored by the testing package once the test
	// (and any subtests) complete.
	t.Setenv("SOFTHSM2_CONF", confPath)

	run := func(name string, args ...string) {
		t.Helper()
		cmd := exec.Command(name, args...)
		cmd.Env = os.Environ()
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("hsmtest: %s %v: %v\n%s", name, args, err, out)
		}
	}

	run("softhsm2-util", "--init-token", "--free", "--label", TokenLabel, "--pin", PIN, "--so-pin", SOPIN)
	run("pkcs11-tool", "--module", module, "--token-label", TokenLabel, "--login", "--pin", PIN,
		"--keypairgen", "--key-type", "rsa:2048", "--label", KeyLabel, "--id", KeyID)
	run("pkcs11-tool", "--module", module, "--token-label", TokenLabel, "--login", "--pin", PIN,
		"--keypairgen", "--key-type", "rsa:1024", "--label", WeakKeyLabel, "--id", WeakKeyID)

	return module
}
