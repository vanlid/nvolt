package keyprovider

import (
	"os"
	"strings"
	"testing"

	"github.com/iluxav/nvolt/pkg/types"
)

func TestEnrollValidatesAndSelfTests(t *testing.T) {
	mod := os.Getenv("NVOLT_TEST_PKCS11_MODULE")
	if mod == "" {
		t.Skip("no module")
	}
	src, pub, err := Enroll(mod, "pkcs11:token=nvolt-test;id=%01;type=private", "env",
		func() (string, error) { return "1234", nil })
	if err != nil {
		t.Fatal(err)
	}
	if src.Source != "pkcs11" || src.OAEPMode == "" {
		t.Fatalf("bad source: %+v", src)
	}
	if pub == nil || pub.N.BitLen() < 2048 {
		t.Fatal("bad public key")
	}
}

// TestEnrollRejectsSub2048Key proves the enroll validation gate in
// internal/keyprovider/pkcs11.go rejects RSA keys below the 2048-bit
// minimum, rather than silently accepting a weak key. This is
// load-bearing security behavior: without it, a token holding a legacy
// or misconfigured sub-2048 RSA key could be enrolled and used for key
// wrapping despite being cryptographically too weak.
func TestEnrollRejectsSub2048Key(t *testing.T) {
	mod := os.Getenv("NVOLT_TEST_PKCS11_MODULE")
	if mod == "" {
		t.Skip("no module")
	}
	src, pub, err := Enroll(mod, "pkcs11:token=nvolt-test;id=%02;type=private", "env",
		func() (string, error) { return "1234", nil })
	if err == nil {
		t.Fatal("expected error enrolling sub-2048 RSA key, got nil")
	}
	msg := err.Error()
	if !strings.Contains(msg, "2048") || !strings.Contains(strings.ToLower(msg), "bit") {
		t.Fatalf("error message does not indicate a bit-size rejection: %q", msg)
	}
	if src != (types.KeySource{}) {
		t.Fatalf("expected zero-value KeySource on rejection, got %+v", src)
	}
	if pub != nil {
		t.Fatalf("expected nil public key on rejection, got %+v", pub)
	}
}
