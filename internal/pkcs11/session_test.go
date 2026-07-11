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

// TestImportRSAPrivateKeyRoundTrip proves ImportRSAPrivateKey (C_CreateObject)
// end to end: a freshly generated 2048-bit RSA key is imported onto the
// SoftHSM fixture token, then FindRSAPrivateKey must locate it by its CKA_ID
// and DecryptOAEPSHA256 must recover an OAEP-SHA256 ciphertext produced
// against its public half. This proves both the marshaling (all seven RSA CRT
// components sent to C_CreateObject) and that the resulting object is usable
// for CKM_RSA_PKCS_OAEP.
func TestImportRSAPrivateKeyRoundTrip(t *testing.T) {
	m, err := Open(testModulePath(t))
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	// Creating a token object (CKA_TOKEN=true) requires a read-write session,
	// same as GenerateRSAKeyPair.
	sess, err := m.OpenSessionRW("nvolt-test")
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()
	if err := sess.Login("1234"); err != nil {
		t.Fatal(err)
	}

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	id := []byte{0x09}
	if _, err := sess.ImportRSAPrivateKey("imported", id, priv); err != nil {
		t.Fatalf("ImportRSAPrivateKey: %v", err)
	}

	obj, err := sess.FindRSAPrivateKey(id)
	if err != nil {
		t.Fatalf("find imported key: %v", err)
	}

	ct, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, &priv.PublicKey, []byte("hi"), nil)
	if err != nil {
		t.Fatal(err)
	}
	pt, err := sess.DecryptOAEPSHA256(obj, ct)
	if errors.Is(err, ErrMechanismUnsupported) {
		t.Skipf("token has no native OAEP-SHA256: %v", err)
	}
	if err != nil {
		t.Fatalf("decrypt with imported key: %v", err)
	}
	if string(pt) != "hi" {
		t.Fatalf("got %q", pt)
	}
}

// TestGenerateRSAKeyPair proves on-card RSA keypair generation via
// C_GenerateKeyPair end to end: it generates a fresh 2048-bit key (id 0x03,
// distinct from the setup script's id 01/02 keys), then FindRSAPrivateKey must
// locate it and RSAPublicKey must report a 2048-bit modulus. SoftHSM supports
// C_GenerateKeyPair, so this MUST pass (not skip).
func TestGenerateRSAKeyPair(t *testing.T) {
	m, err := Open(testModulePath(t))
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	// Key generation creates token objects (CKA_TOKEN=true), which requires a
	// read-write session; OpenSessionRW is the RW counterpart to the
	// read-only OpenSession used by every other (read-only) caller.
	sess, err := m.OpenSessionRW("nvolt-test")
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()
	if err := sess.Login("1234"); err != nil {
		t.Fatal(err)
	}

	id := []byte{0x03}
	if _, err := sess.GenerateRSAKeyPair("nvolt-gen", id, 2048); err != nil {
		t.Fatalf("GenerateRSAKeyPair: %v", err)
	}

	priv, err := sess.FindRSAPrivateKey(id)
	if err != nil {
		t.Fatalf("FindRSAPrivateKey after generate: %v", err)
	}
	pub, err := sess.RSAPublicKey(priv)
	if err != nil {
		t.Fatalf("RSAPublicKey: %v", err)
	}
	if bits := pub.N.BitLen(); bits != 2048 {
		t.Fatalf("generated key is %d bits, want 2048", bits)
	}
}

// TestTokenFlagsReadCorrectly proves the CK_TOKEN_INFO.flags offset (96 bytes
// into the struct, per Cryptoki 2.40 LP64 layout: label[32] +
// manufacturerID[32] + model[16] + serialNumber[16]) is read correctly by
// findSlot/openSession. SoftHSM requires a normal user PIN, so it must report
// LoginRequired()==true and ProtectedAuthPath()==false; a wrong offset would
// read garbage bytes from manufacturerID/model/serialNumber instead and very
// likely flip one or both of these booleans.
//
// The protected-auth-path branch (CKF_PROTECTED_AUTHENTICATION_PATH set, e.g.
// a pinpad reader) cannot be exercised here: SoftHSM never sets that flag, and
// there is no way to fake it without undermining what this test proves.
func TestTokenFlagsReadCorrectly(t *testing.T) {
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

	if !sess.LoginRequired() {
		t.Fatal("LoginRequired() = false, want true for SoftHSM token")
	}
	if sess.ProtectedAuthPath() {
		t.Fatal("ProtectedAuthPath() = true, want false for SoftHSM token")
	}
}

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

	// DecryptRawRSA normalizes the RSA block m = c^d mod n to exactly k bytes
	// (the modulus size, == len(ct)), left-zero-padding if the token trimmed
	// leading zeros. UnpadOAEPSHA256 requires exactly k bytes.
	em, err := sess.DecryptRawRSA(priv, wrapped)
	if err != nil {
		t.Fatalf("DecryptRawRSA: %v", err)
	}

	k := (pub.N.BitLen() + 7) / 8
	if len(em) != k {
		t.Fatalf("raw block %d bytes != modulus size %d", len(em), k)
	}

	got, err := crypto.UnpadOAEPSHA256(em, k)
	if err != nil {
		t.Fatalf("UnpadOAEPSHA256: %v", err)
	}
	if !bytes.Equal(got, aes) {
		t.Fatalf("raw OAEP-SHA256 round-trip mismatch: got %x want %x", got, aes)
	}
}
