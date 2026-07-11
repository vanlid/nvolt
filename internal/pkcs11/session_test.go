package pkcs11

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"errors"
	"testing"
	"unsafe"

	"github.com/ebitengine/purego"
	"github.com/iluxav/nvolt/internal/crypto"
)

func TestOAEPRoundTripAgainstToken(t *testing.T) {
	m, err := Open(testModulePath(t))
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	sess, err := m.OpenSession("nvolt-test")
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()
	if err := sess.Login("1234"); err != nil {
		t.Fatal(err)
	}

	priv, err := sess.FindRSAPrivateKey([]byte{0x01})
	if err != nil {
		t.Fatal(err)
	}
	pub, err := sess.RSAPublicKey(priv)
	if err != nil {
		t.Fatal(err)
	}

	msg := []byte("nvolt-master-key-32-bytes-xxxxxx")
	ct, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, msg, nil)
	if err != nil {
		t.Fatal(err)
	}

	got, err := sess.DecryptOAEPSHA256(priv, ct)
	if errors.Is(err, ErrMechanismUnsupported) {
		// Documented mechanism failure (not an FFI bug): the token rejects
		// native OAEP-SHA256. SoftHSM 2.6.1 hardcodes OAEP to SHA-1 and
		// returns CKR_ARGUMENTS_BAD here. The rest of the FFI path
		// (session/login/find-key/pubkey/C_DecryptInit reached) is proven
		// correct; Task 3's raw-RSA + software-OAEP fallback is required and
		// Task 6 selects it via errors.Is(err, ErrMechanismUnsupported).
		t.Skipf("token has no native OAEP-SHA256; fallback required: %v", err)
	}
	if err != nil {
		t.Fatalf("token decrypt: %v", err)
	}
	if !bytes.Equal(got, msg) {
		t.Fatalf("round-trip mismatch: got %q", got)
	}
}

// TestNativeOAEPDecryptPathSHA1 proves the full on-token decrypt FFI path
// (C_DecryptInit + the two-call C_Decrypt length pattern) works end-to-end,
// independent of which OAEP hash the token supports. It uses SHA-1 solely
// because that is the only OAEP hash SoftHSM 2.6.1 accepts; SHA-1 is NOT the
// product wrap format (SHA-256 is). This test is the spike's definitive PASS:
// a wrong CK_FUNCTION_LIST index or header offset would fail it immediately.
func TestNativeOAEPDecryptPathSHA1(t *testing.T) {
	m, err := Open(testModulePath(t))
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	sess, err := m.OpenSession("nvolt-test")
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()
	if err := sess.Login("1234"); err != nil {
		t.Fatal(err)
	}
	priv, err := sess.FindRSAPrivateKey([]byte{0x01})
	if err != nil {
		t.Fatal(err)
	}
	pub, err := sess.RSAPublicKey(priv)
	if err != nil {
		t.Fatal(err)
	}

	msg := []byte("nvolt-master-key-32-bytes-xxxxxx")
	ct, err := rsa.EncryptOAEP(sha1.New(), rand.Reader, pub, msg, nil)
	if err != nil {
		t.Fatal(err)
	}

	const (
		ckmSHA1     uintptr = 0x00000220 // CKM_SHA_1
		ckgMGF1SHA1 uintptr = 0x00000001 // CKG_MGF1_SHA1
	)
	params := ckOAEPParams{HashAlg: ckmSHA1, Mgf: ckgMGF1SHA1, SourceType: CKZ_DATA_SPECIFIED}
	mech := CK_MECHANISM{Mechanism: CKM_RSA_PKCS_OAEP, Param: unsafe.Pointer(&params), ParamLen: unsafe.Sizeof(params)}
	rv, _, _ := purego.SyscallN(sess.m.fn(idxDecryptInit), sess.handle, uintptr(unsafe.Pointer(&mech)), priv)
	if CKRV(rv) != CKR_OK {
		t.Fatalf("C_DecryptInit(OAEP-SHA1): %s", CKRV(rv))
	}
	got, err := sess.doDecrypt(ct)
	if err != nil {
		t.Fatalf("on-token C_Decrypt: %v", err)
	}
	if !bytes.Equal(got, msg) {
		t.Fatalf("SHA-1 round-trip mismatch: got %q want %q", got, msg)
	}
}

// TestRawRSAOAEPRoundTripAgainstToken proves the FULL product OAEP-SHA256
// unwrap path via the raw-RSA fallback, end to end on the token:
//
//	crypto.WrapKey(pub, aes)      -> RSA-OAEP-SHA256 ciphertext
//	sess.DecryptRawRSA(priv, ct)  -> CKM_RSA_X_509 raw block (m = c^d mod n)
//	crypto.UnpadOAEPSHA256(em, k) -> recovered aes
//
// This is the real SHA-256 round-trip that TestOAEPRoundTripAgainstToken cannot
// exercise on SoftHSM 2.6.1 (which only supports OAEP-SHA1 natively). Unlike
// that test, this one MUST pass — it is the working unwrap path for such tokens.
func TestRawRSAOAEPRoundTripAgainstToken(t *testing.T) {
	m, err := Open(testModulePath(t))
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	sess, err := m.OpenSession("nvolt-test")
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()
	if err := sess.Login("1234"); err != nil {
		t.Fatal(err)
	}
	priv, err := sess.FindRSAPrivateKey([]byte{0x01})
	if err != nil {
		t.Fatal(err)
	}
	pub, err := sess.RSAPublicKey(priv)
	if err != nil {
		t.Fatal(err)
	}

	aes, err := crypto.GenerateAESKey()
	if err != nil {
		t.Fatal(err)
	}
	wrapped, err := crypto.WrapKey(pub, aes)
	if err != nil {
		t.Fatalf("WrapKey: %v", err)
	}

	raw, err := sess.DecryptRawRSA(priv, wrapped)
	if err != nil {
		t.Fatalf("DecryptRawRSA: %v", err)
	}

	// DecryptRawRSA returns the RSA block m = c^d mod n. UnpadOAEPSHA256 expects
	// exactly k bytes (the modulus size), but a token may return the block with
	// leading zero bytes stripped (a raw big-endian integer). OAEP's EM always
	// begins with 0x00, so normalize by left-zero-padding to k.
	k := (pub.N.BitLen() + 7) / 8
	em := leftPad(raw, k)
	if len(em) != k {
		t.Fatalf("raw block %d bytes exceeds modulus size %d", len(raw), k)
	}

	got, err := crypto.UnpadOAEPSHA256(em, k)
	if err != nil {
		t.Fatalf("UnpadOAEPSHA256: %v", err)
	}
	if !bytes.Equal(got, aes) {
		t.Fatalf("raw OAEP-SHA256 round-trip mismatch: got %x want %x", got, aes)
	}
}

// leftPad returns b left-padded with zero bytes to length k. If b is already
// k bytes (or longer) it is returned unchanged.
func leftPad(b []byte, k int) []byte {
	if len(b) >= k {
		return b
	}
	out := make([]byte, k)
	copy(out[k-len(b):], b)
	return out
}
