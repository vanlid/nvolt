package crypto

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"math/big"
	"testing"
)

func TestUnpadOAEPSHA256MatchesStdlib(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	msg := []byte("hello-nvolt")
	ct, _ := rsa.EncryptOAEP(sha256.New(), rand.Reader, &key.PublicKey, msg, nil)
	// raw RSA decrypt (what a token's CKM_RSA_X_509 returns): m = c^d mod n
	c := new(big.Int).SetBytes(ct)
	m := new(big.Int).Exp(c, key.D, key.N)
	k := (key.N.BitLen() + 7) / 8
	em := make([]byte, k)
	m.FillBytes(em)
	got, err := UnpadOAEPSHA256(em, k)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, msg) {
		t.Fatalf("got %q want %q", got, msg)
	}
}
