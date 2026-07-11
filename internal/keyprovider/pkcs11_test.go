package keyprovider

import (
	"os"
	"testing"
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
