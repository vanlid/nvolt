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

// rawOAEPBlock encrypts msg with RSA-OAEP-SHA256 under key's public half and
// returns the raw RSA decryption block em = c^d mod n, left-padded to k bytes
// (exactly what a token's CKM_RSA_X_509 yields after normalization).
func rawOAEPBlock(t *testing.T, key *rsa.PrivateKey, msg []byte) (em []byte, k int) {
	t.Helper()
	ct, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, &key.PublicKey, msg, nil)
	if err != nil {
		t.Fatal(err)
	}
	c := new(big.Int).SetBytes(ct)
	m := new(big.Int).Exp(c, key.D, key.N)
	k = (key.N.BitLen() + 7) / 8
	em = make([]byte, k)
	m.FillBytes(em)
	return em, k
}

func TestUnpadOAEPSHA256Messages(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	hLen := sha256.New().Size()
	k := (key.N.BitLen() + 7) / 8
	maxLen := k - 2*hLen - 2

	maxMsg := bytes.Repeat([]byte{0xAB}, maxLen)
	withOnes := []byte{0x01, 0x00, 0x01, 0x01, 0x00, 0x01} // message containing 0x01 bytes

	cases := []struct {
		name string
		msg  []byte
	}{
		{"empty", []byte{}},
		{"one-byte", []byte{0x42}},
		{"max-length", maxMsg},
		{"contains-0x01", withOnes},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			em, k := rawOAEPBlock(t, key, tc.msg)
			got, err := UnpadOAEPSHA256(em, k)
			if err != nil {
				t.Fatalf("unpad: %v", err)
			}
			if !bytes.Equal(got, tc.msg) {
				t.Fatalf("got %x want %x", got, tc.msg)
			}
		})
	}
}

func TestUnpadOAEPSHA256Corrupted(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	em, k := rawOAEPBlock(t, key, []byte("corrupt-me"))
	// Flip a byte inside the lHash region (db[:hLen] starts at em[1+hLen]) so
	// the recovered lHash no longer matches; unpad must reject.
	em[1+sha256.New().Size()] ^= 0xFF
	if _, err := UnpadOAEPSHA256(em, k); err == nil {
		t.Fatal("expected error for corrupted block, got nil")
	}
}
