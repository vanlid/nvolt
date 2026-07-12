//go:build wolfpkcs11_static

package pkcs11

// #include <stdlib.h>
// #include <wolfpkcs11/pkcs11.h>
import "C"

import (
	"bytes"
	"crypto/rsa"
	"errors"
	"fmt"
	"math/big"
	"runtime"
	"unsafe"
)

// ErrMechanismUnsupported reports that the token refused the requested
// mechanism or its parameters (e.g. C_DecryptInit returning
// CKR_MECHANISM_INVALID or CKR_ARGUMENTS_BAD). Callers wrap-test with
// errors.Is to fall back to a software-padding path. This mirrors the purego
// build's sentinel of the same name so internal/keyprovider compiles unchanged
// under either loader tag.
var ErrMechanismUnsupported = errors.New("pkcs11: mechanism or parameters not supported by token")

// Object is a PKCS#11 object handle. Kept as uintptr (not C.CK_OBJECT_HANDLE)
// so the type is identical to the purego build and callers in
// internal/keyprovider and internal/cli compile against one signature.
type Object = uintptr

// Session is an open PKCS#11 session against a single token in the
// statically-linked build. handle/flags are stored as their real C widths;
// flags is the token's CK_TOKEN_INFO.flags captured at open time so PIN
// handling can be auto-detected without a second C_GetTokenInfo round trip.
type Session struct {
	m      *Module
	handle C.CK_SESSION_HANDLE
	flags  C.CK_FLAGS
}

// rvStr renders a CK_RV using the shared ckrvNames table so cgo errors read the
// same as the purego loader's ("CKR_PIN_INCORRECT" etc.).
func rvStr(rv C.CK_RV) string { return CKRV(rv).String() }

// cTemplate builds a CK_ATTRIBUTE array whose value buffers live on the C heap,
// so the array can be passed to C without violating cgo's rule against handing
// C a Go pointer to memory that itself holds Go pointers. Call free() when done.
type cTemplate struct {
	attrs []C.CK_ATTRIBUTE
	frees []unsafe.Pointer
}

// addBytes appends an attribute whose value is a C-heap copy of val. A nil/empty
// val yields a NULL pValue with zero length (used only when a caller wants the
// attribute present with no value, which none currently do).
func (t *cTemplate) addBytes(typ C.CK_ATTRIBUTE_TYPE, val []byte) {
	a := C.CK_ATTRIBUTE{_type: typ}
	if len(val) > 0 {
		p := C.CBytes(val)
		t.frees = append(t.frees, p)
		a.pValue = C.CK_VOID_PTR(p)
		a.ulValueLen = C.CK_ULONG(len(val))
	}
	t.attrs = append(t.attrs, a)
}

// addULong appends a CK_ULONG-valued attribute (CKA_CLASS, CKA_KEY_TYPE,
// CKA_MODULUS_BITS), stored at the platform CK_ULONG width in C memory.
func (t *cTemplate) addULong(typ C.CK_ATTRIBUTE_TYPE, v C.CK_ULONG) {
	p := C.malloc(C.size_t(unsafe.Sizeof(v)))
	t.frees = append(t.frees, p)
	*(*C.CK_ULONG)(p) = v
	t.attrs = append(t.attrs, C.CK_ATTRIBUTE{
		_type:      typ,
		pValue:     C.CK_VOID_PTR(p),
		ulValueLen: C.CK_ULONG(unsafe.Sizeof(v)),
	})
}

// addBool appends a CK_BBOOL attribute set to CK_TRUE (single byte 0x01).
func (t *cTemplate) addBool(typ C.CK_ATTRIBUTE_TYPE) { t.addBytes(typ, []byte{0x01}) }

func (t *cTemplate) ptr() C.CK_ATTRIBUTE_PTR {
	return C.CK_ATTRIBUTE_PTR(unsafe.Pointer(&t.attrs[0]))
}
func (t *cTemplate) count() C.CK_ULONG { return C.CK_ULONG(len(t.attrs)) }
func (t *cTemplate) free() {
	for _, p := range t.frees {
		C.free(p)
	}
}

// aptr returns a CK_ATTRIBUTE_PTR to a one-element template slice (used by
// getAttribute's two-call length pattern, where the single value buffer is
// managed directly rather than through cTemplate).
func aptr(t []C.CK_ATTRIBUTE) C.CK_ATTRIBUTE_PTR {
	return C.CK_ATTRIBUTE_PTR(unsafe.Pointer(&t[0]))
}

// bptr returns a CK_BYTE_PTR into a non-empty Go byte slice.
func bptr(b []byte) C.CK_BYTE_PTR {
	return C.CK_BYTE_PTR(unsafe.Pointer(&b[0]))
}

// OpenSession opens a read-only serial session on the slot whose token label
// matches tokenLabel. Read-only is deliberate: a write-protected token returns
// CKR_TOKEN_WRITE_PROTECTED for a RW C_OpenSession, which would break the core
// decrypt/list paths. Use OpenSessionRW for key generation/import.
func (m *Module) OpenSession(tokenLabel string) (*Session, error) {
	return m.openSession(tokenLabel, false)
}

// OpenSessionRW opens a read-write serial session (CKF_RW_SESSION), required to
// create token objects (CKA_TOKEN=true) in GenerateRSAKeyPair/ImportRSAPrivateKey.
func (m *Module) OpenSessionRW(tokenLabel string) (*Session, error) {
	return m.openSession(tokenLabel, true)
}

// openSession initializes the module (once), finds the slot whose token label
// matches tokenLabel, and opens a serial session on it, read-write only when rw.
func (m *Module) openSession(tokenLabel string, rw bool) (*Session, error) {
	if err := m.initialize(); err != nil {
		return nil, err
	}
	slot, tokenFlags, err := m.findSlot(tokenLabel)
	if err != nil {
		return nil, err
	}
	flags := C.CK_FLAGS(C.CKF_SERIAL_SESSION)
	if rw {
		flags |= C.CKF_RW_SESSION
	}
	var handle C.CK_SESSION_HANDLE
	rv := C.C_OpenSession(slot, flags, nil, nil, &handle)
	if rv != C.CKR_OK {
		return nil, fmt.Errorf("C_OpenSession: %s", rvStr(rv))
	}
	return &Session{m: m, handle: handle, flags: tokenFlags}, nil
}

// slotList returns the ids of all token-present slots.
func (m *Module) slotList() ([]C.CK_SLOT_ID, error) {
	var count C.CK_ULONG
	if rv := C.C_GetSlotList(C.CK_TRUE, nil, &count); rv != C.CKR_OK {
		return nil, fmt.Errorf("C_GetSlotList(count): %s", rvStr(rv))
	}
	if count == 0 {
		return nil, nil
	}
	slots := make([]C.CK_SLOT_ID, int(count))
	if rv := C.C_GetSlotList(C.CK_TRUE, &slots[0], &count); rv != C.CKR_OK {
		return nil, fmt.Errorf("C_GetSlotList: %s", rvStr(rv))
	}
	return slots[:int(count)], nil
}

// findSlot returns the slot id and CK_TOKEN_INFO.flags of the token whose label
// matches tokenLabel.
func (m *Module) findSlot(tokenLabel string) (C.CK_SLOT_ID, C.CK_FLAGS, error) {
	slots, err := m.slotList()
	if err != nil {
		return 0, 0, err
	}
	if len(slots) == 0 {
		return 0, 0, fmt.Errorf("no token-present slots")
	}
	want := []byte(tokenLabel)
	for _, slot := range slots {
		var info C.CK_TOKEN_INFO
		if rv := C.C_GetTokenInfo(slot, &info); rv != C.CKR_OK {
			continue
		}
		label := bytes.TrimRight(C.GoBytes(unsafe.Pointer(&info.label[0]), 32), " ")
		if bytes.Equal(label, want) {
			return slot, info.flags, nil
		}
	}
	return 0, 0, fmt.Errorf("no token with label %q", tokenLabel)
}

// tokenLabel reads the space-trimmed CKA label from a slot's CK_TOKEN_INFO.
func (m *Module) tokenLabel(slot C.CK_SLOT_ID) (string, error) {
	var info C.CK_TOKEN_INFO
	if rv := C.C_GetTokenInfo(slot, &info); rv != C.CKR_OK {
		return "", fmt.Errorf("C_GetTokenInfo: %s", rvStr(rv))
	}
	return string(bytes.TrimRight(C.GoBytes(unsafe.Pointer(&info.label[0]), 32), " ")), nil
}

// Login authenticates as the normal (user) role with the given PIN. An empty
// pin returns nil without calling C_Login (the pin_mode=none convention), which
// also avoids &pinB[0] on an empty slice.
func (s *Session) Login(pin string) error {
	if len(pin) == 0 {
		return nil
	}
	pinB := []byte(pin)
	rv := C.C_Login(s.handle, C.CKU_USER, bptr(pinB), C.CK_ULONG(len(pinB)))
	runtime.KeepAlive(pinB)
	if rv != C.CKR_OK {
		return fmt.Errorf("C_Login: %s", rvStr(rv))
	}
	return nil
}

// ProtectedAuthPath reports whether the token sets
// CKF_PROTECTED_AUTHENTICATION_PATH (reader/pinpad collects the PIN itself).
func (s *Session) ProtectedAuthPath() bool {
	return s.flags&C.CKF_PROTECTED_AUTHENTICATION_PATH != 0
}

// LoginRequired reports whether the token sets CKF_LOGIN_REQUIRED.
func (s *Session) LoginRequired() bool {
	return s.flags&C.CKF_LOGIN_REQUIRED != 0
}

// LoginProtected authenticates on a protected-authentication-path token by
// calling C_Login with a NULL PIN so the reader/pinpad prompts the user.
func (s *Session) LoginProtected() error {
	rv := C.C_Login(s.handle, C.CKU_USER, nil, 0)
	if rv != C.CKR_OK {
		return fmt.Errorf("C_Login (protected authentication path): %s", rvStr(rv))
	}
	return nil
}

// Close closes the session.
func (s *Session) Close() error {
	if s.handle == 0 {
		return nil
	}
	rv := C.C_CloseSession(s.handle)
	s.handle = 0
	if rv != C.CKR_OK {
		return fmt.Errorf("C_CloseSession: %s", rvStr(rv))
	}
	return nil
}

// FindRSAPrivateKey returns the first RSA private key object matching id.
// A nil/empty id matches any RSA private key.
func (s *Session) FindRSAPrivateKey(id []byte) (Object, error) {
	objs, err := s.findRSAObjects(C.CKO_PRIVATE_KEY, id)
	if err != nil {
		return 0, err
	}
	if len(objs) == 0 {
		return 0, fmt.Errorf("no RSA private key found for id %x", id)
	}
	return objs[0], nil
}

// findRSAObjects returns all handles of RSA objects of the given class,
// optionally filtered to a specific CKA_ID (nil id means no id filter).
func (s *Session) findRSAObjects(class C.CK_ULONG, id []byte) ([]Object, error) {
	tmpl := &cTemplate{}
	tmpl.addULong(C.CKA_CLASS, class)
	tmpl.addULong(C.CKA_KEY_TYPE, C.CKK_RSA)
	if len(id) > 0 {
		tmpl.addBytes(C.CKA_ID, id)
	}
	defer tmpl.free()

	if rv := C.C_FindObjectsInit(s.handle, tmpl.ptr(), tmpl.count()); rv != C.CKR_OK {
		return nil, fmt.Errorf("C_FindObjectsInit: %s", rvStr(rv))
	}

	const batch = 32
	var out []Object
	for {
		objs := make([]C.CK_OBJECT_HANDLE, batch)
		var found C.CK_ULONG
		rv := C.C_FindObjects(s.handle, &objs[0], batch, &found)
		if rv != C.CKR_OK {
			C.C_FindObjectsFinal(s.handle)
			return nil, fmt.Errorf("C_FindObjects: %s", rvStr(rv))
		}
		f := int(found)
		for i := 0; i < f; i++ {
			out = append(out, Object(objs[i]))
		}
		if f < batch {
			break
		}
	}
	if rv := C.C_FindObjectsFinal(s.handle); rv != C.CKR_OK {
		return nil, fmt.Errorf("C_FindObjectsFinal: %s", rvStr(rv))
	}
	return out, nil
}

// getAttribute fetches one attribute value using the two-call length pattern.
func (s *Session) getAttribute(obj C.CK_OBJECT_HANDLE, typ C.CK_ATTRIBUTE_TYPE) ([]byte, error) {
	tmpl := []C.CK_ATTRIBUTE{{_type: typ}}
	if rv := C.C_GetAttributeValue(s.handle, obj, aptr(tmpl), 1); rv != C.CKR_OK {
		return nil, fmt.Errorf("C_GetAttributeValue(size 0x%x): %s", uint(typ), rvStr(rv))
	}
	n := tmpl[0].ulValueLen
	if n == 0 {
		return nil, nil
	}
	buf := C.malloc(C.size_t(n))
	defer C.free(buf)
	tmpl[0].pValue = C.CK_VOID_PTR(buf)
	if rv := C.C_GetAttributeValue(s.handle, obj, aptr(tmpl), 1); rv != C.CKR_OK {
		return nil, fmt.Errorf("C_GetAttributeValue(0x%x): %s", uint(typ), rvStr(rv))
	}
	return C.GoBytes(buf, C.int(tmpl[0].ulValueLen)), nil
}

// rsaKeyInfo reads CKA_ID, CKA_LABEL and CKA_MODULUS from an RSA object.
func (s *Session) rsaKeyInfo(tokenLabel string, obj Object) (KeyInfo, error) {
	h := C.CK_OBJECT_HANDLE(obj)
	id, _ := s.getAttribute(h, C.CKA_ID)
	label, _ := s.getAttribute(h, C.CKA_LABEL)
	mod, err := s.getAttribute(h, C.CKA_MODULUS)
	if err != nil {
		return KeyInfo{}, err
	}
	return KeyInfo{
		TokenLabel: tokenLabel,
		Label:      string(label),
		ID:         id,
		Bits:       new(big.Int).SetBytes(mod).BitLen(),
	}, nil
}

// listRSAKeysOnToken enumerates RSA private- then public-key objects on the
// session's token, returning one KeyInfo per distinct CKA_ID.
func (s *Session) listRSAKeysOnToken(tokenLabel string) []KeyInfo {
	seen := map[string]bool{}
	var out []KeyInfo
	for _, class := range []C.CK_ULONG{C.CKO_PRIVATE_KEY, C.CKO_PUBLIC_KEY} {
		objs, err := s.findRSAObjects(class, nil)
		if err != nil {
			continue
		}
		for _, obj := range objs {
			ki, err := s.rsaKeyInfo(tokenLabel, obj)
			if err != nil {
				continue
			}
			key := fmt.Sprintf("%x", ki.ID)
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, ki)
		}
	}
	return out
}

// RSAPublicKeyByID reads the RSA public key material for the key identified by
// CKA_ID id without logging in. It tries CKO_PUBLIC_KEY first (visible pre-login
// on every token), then falls back to CKO_PRIVATE_KEY for tokens that expose
// private objects without authentication.
func (s *Session) RSAPublicKeyByID(id []byte) (*rsa.PublicKey, error) {
	for _, class := range []C.CK_ULONG{C.CKO_PUBLIC_KEY, C.CKO_PRIVATE_KEY} {
		objs, err := s.findRSAObjects(class, id)
		if err != nil {
			return nil, err
		}
		if len(objs) == 0 {
			continue
		}
		return s.RSAPublicKey(objs[0])
	}
	return nil, fmt.Errorf("no RSA key found for id %x", id)
}

// RSAPublicKey reads CKA_MODULUS and CKA_PUBLIC_EXPONENT from an RSA key object
// and reconstructs the public key.
func (s *Session) RSAPublicKey(obj Object) (*rsa.PublicKey, error) {
	h := C.CK_OBJECT_HANDLE(obj)
	mod, err := s.getAttribute(h, C.CKA_MODULUS)
	if err != nil {
		return nil, err
	}
	exp, err := s.getAttribute(h, C.CKA_PUBLIC_EXPONENT)
	if err != nil {
		return nil, err
	}
	return &rsa.PublicKey{
		N: new(big.Int).SetBytes(mod),
		E: int(new(big.Int).SetBytes(exp).Int64()),
	}, nil
}

// DecryptOAEPSHA256 performs CKM_RSA_PKCS_OAEP (SHA-256, MGF1-SHA256) on the token.
func (s *Session) DecryptOAEPSHA256(priv Object, ct []byte) ([]byte, error) {
	params := (*C.CK_RSA_PKCS_OAEP_PARAMS)(C.malloc(C.size_t(unsafe.Sizeof(C.CK_RSA_PKCS_OAEP_PARAMS{}))))
	defer C.free(unsafe.Pointer(params))
	params.hashAlg = C.CKM_SHA256
	params.mgf = C.CKG_MGF1_SHA256
	params.source = C.CKZ_DATA_SPECIFIED
	params.pSourceData = nil
	params.ulSourceDataLen = 0

	mech := C.CK_MECHANISM{
		mechanism:      C.CKM_RSA_PKCS_OAEP,
		pParameter:     C.CK_VOID_PTR(unsafe.Pointer(params)),
		ulParameterLen: C.CK_ULONG(unsafe.Sizeof(*params)),
	}
	rv := C.C_DecryptInit(s.handle, &mech, C.CK_OBJECT_HANDLE(priv))
	if rv != C.CKR_OK {
		if rv == C.CKR_MECHANISM_INVALID || rv == C.CKR_ARGUMENTS_BAD {
			return nil, fmt.Errorf("C_DecryptInit(OAEP): %s: %w", rvStr(rv), ErrMechanismUnsupported)
		}
		return nil, fmt.Errorf("C_DecryptInit(OAEP): %s", rvStr(rv))
	}
	return s.doDecrypt(ct)
}

// DecryptRawRSA performs CKM_RSA_X_509 (raw RSA, no padding) on the token,
// returning the k-byte, left-zero-padded decryption block. Callers strip OAEP
// padding in software. This is the fallback for tokens lacking native
// OAEP-SHA256; see ErrMechanismUnsupported.
func (s *Session) DecryptRawRSA(priv Object, ct []byte) ([]byte, error) {
	mech := C.CK_MECHANISM{mechanism: C.CKM_RSA_X_509}
	rv := C.C_DecryptInit(s.handle, &mech, C.CK_OBJECT_HANDLE(priv))
	if rv != C.CKR_OK {
		if rv == C.CKR_MECHANISM_INVALID || rv == C.CKR_ARGUMENTS_BAD {
			return nil, fmt.Errorf("C_DecryptInit(RSA_X_509): %s: %w", rvStr(rv), ErrMechanismUnsupported)
		}
		return nil, fmt.Errorf("C_DecryptInit(RSA_X_509): %s", rvStr(rv))
	}
	raw, err := s.doDecrypt(ct)
	if err != nil {
		return nil, err
	}
	// Raw RSA output length equals the modulus length (len(ct)); a token may
	// trim leading zero bytes. UnpadOAEPSHA256 needs exactly k bytes, so
	// left-zero-pad to len(ct).
	k := len(ct)
	if len(raw) >= k {
		return raw, nil
	}
	em := make([]byte, k)
	copy(em[k-len(raw):], raw)
	return em, nil
}

// doDecrypt runs the two-call C_Decrypt length pattern.
func (s *Session) doDecrypt(ct []byte) ([]byte, error) {
	var outLen C.CK_ULONG
	rv := C.C_Decrypt(s.handle, bptr(ct), C.CK_ULONG(len(ct)), nil, &outLen)
	runtime.KeepAlive(ct)
	if rv != C.CKR_OK {
		return nil, fmt.Errorf("C_Decrypt(size): %s", rvStr(rv))
	}
	if outLen == 0 {
		return nil, nil
	}
	out := make([]byte, int(outLen))
	rv = C.C_Decrypt(s.handle, bptr(ct), C.CK_ULONG(len(ct)), bptr(out), &outLen)
	runtime.KeepAlive(ct)
	runtime.KeepAlive(out)
	if rv != C.CKR_OK {
		return nil, fmt.Errorf("C_Decrypt: %s", rvStr(rv))
	}
	return out[:int(outLen)], nil
}

// GenerateRSAKeyPair generates an RSA keypair on the token via
// C_GenerateKeyPair(CKM_RSA_PKCS_KEY_PAIR_GEN) and returns the private-key
// object handle. label/id tag both objects; bits is the modulus size. Public
// exponent is fixed at 65537.
func (s *Session) GenerateRSAKeyPair(label string, id []byte, bits int) (Object, error) {
	mech := C.CK_MECHANISM{mechanism: C.CKM_RSA_PKCS_KEY_PAIR_GEN}

	pub := &cTemplate{}
	pub.addULong(C.CKA_MODULUS_BITS, C.CK_ULONG(bits))
	pub.addBytes(C.CKA_PUBLIC_EXPONENT, []byte{0x01, 0x00, 0x01}) // 65537
	pub.addBool(C.CKA_TOKEN)
	pub.addBool(C.CKA_ENCRYPT)
	pub.addBool(C.CKA_VERIFY)
	pub.addBool(C.CKA_WRAP)
	pub.addBytes(C.CKA_LABEL, []byte(label))
	if len(id) > 0 {
		pub.addBytes(C.CKA_ID, id)
	}
	defer pub.free()

	priv := &cTemplate{}
	priv.addBool(C.CKA_TOKEN)
	priv.addBool(C.CKA_PRIVATE)
	priv.addBool(C.CKA_SENSITIVE)
	priv.addBool(C.CKA_DECRYPT)
	priv.addBool(C.CKA_SIGN)
	priv.addBool(C.CKA_UNWRAP)
	priv.addBytes(C.CKA_LABEL, []byte(label))
	if len(id) > 0 {
		priv.addBytes(C.CKA_ID, id)
	}
	defer priv.free()

	var pubH, privH C.CK_OBJECT_HANDLE
	rv := C.C_GenerateKeyPair(s.handle, &mech,
		pub.ptr(), pub.count(), priv.ptr(), priv.count(), &pubH, &privH)
	if rv != C.CKR_OK {
		if rv == C.CKR_FUNCTION_NOT_SUPPORTED {
			return 0, fmt.Errorf("C_GenerateKeyPair: %s: this token does not support "+
				"on-card key generation via PKCS#11; generate the key directly on the "+
				"device instead, e.g.:\n"+
				"  ykman piv keys generate 9d pub.pem\n"+
				"  yubico-piv-tool -a generate -s 9d", rvStr(rv))
		}
		return 0, fmt.Errorf("C_GenerateKeyPair: %s", rvStr(rv))
	}
	return Object(privH), nil
}

// ImportRSAPrivateKey creates a token (persistent) RSA private key object from
// priv via C_CreateObject, marked CKA_DECRYPT so nvolt can unwrap with it.
// Returns the created object handle.
func (s *Session) ImportRSAPrivateKey(label string, id []byte, priv *rsa.PrivateKey) (Object, error) {
	priv.Precompute()
	tmpl := &cTemplate{}
	tmpl.addULong(C.CKA_CLASS, C.CKO_PRIVATE_KEY)
	tmpl.addULong(C.CKA_KEY_TYPE, C.CKK_RSA)
	tmpl.addBool(C.CKA_TOKEN)
	tmpl.addBool(C.CKA_PRIVATE)
	tmpl.addBool(C.CKA_DECRYPT)
	tmpl.addBytes(C.CKA_LABEL, []byte(label))
	tmpl.addBytes(C.CKA_MODULUS, priv.N.Bytes())
	tmpl.addBytes(C.CKA_PUBLIC_EXPONENT, big.NewInt(int64(priv.E)).Bytes())
	tmpl.addBytes(C.CKA_PRIVATE_EXPONENT, priv.D.Bytes())
	tmpl.addBytes(C.CKA_PRIME_1, priv.Primes[0].Bytes())
	tmpl.addBytes(C.CKA_PRIME_2, priv.Primes[1].Bytes())
	tmpl.addBytes(C.CKA_EXPONENT_1, priv.Precomputed.Dp.Bytes())
	tmpl.addBytes(C.CKA_EXPONENT_2, priv.Precomputed.Dq.Bytes())
	tmpl.addBytes(C.CKA_COEFFICIENT, priv.Precomputed.Qinv.Bytes())
	if len(id) > 0 {
		tmpl.addBytes(C.CKA_ID, id)
	}
	defer tmpl.free()

	var objH C.CK_OBJECT_HANDLE
	rv := C.C_CreateObject(s.handle, tmpl.ptr(), tmpl.count(), &objH)
	if rv != C.CKR_OK {
		if rv == C.CKR_FUNCTION_NOT_SUPPORTED {
			return 0, fmt.Errorf("C_CreateObject: %s: this token does not support PKCS#11 "+
				"key import; import the key with the device's own tool instead, e.g.:\n"+
				"  ykman piv keys import 9d key.pem", rvStr(rv))
		}
		return 0, fmt.Errorf("C_CreateObject: %s", rvStr(rv))
	}
	return Object(objH), nil
}

// ListTokensAndKeys enumerates every token-present slot and returns one
// TokenListing per token, including tokens with no RSA keys. It does not log in;
// it reports RSA key objects visible without authentication, deduplicated by
// (token, id). Mirrors the purego discover.go implementation using C structs.
func ListTokensAndKeys(module string) ([]TokenListing, error) {
	m, err := Open(module)
	if err != nil {
		return nil, err
	}
	defer m.Close()
	if err := m.initialize(); err != nil {
		return nil, err
	}

	slots, err := m.slotList()
	if err != nil {
		return nil, err
	}

	var out []TokenListing
	for _, slot := range slots {
		label, err := m.tokenLabel(slot)
		if err != nil {
			continue // slot without a readable token; skip
		}
		var handle C.CK_SESSION_HANDLE
		rv := C.C_OpenSession(slot, C.CKF_SERIAL_SESSION, nil, nil, &handle)
		if rv != C.CKR_OK {
			continue
		}
		s := &Session{m: m, handle: handle}
		keys := s.listRSAKeysOnToken(label)
		_ = s.Close()
		out = append(out, TokenListing{Label: label, Keys: keys})
	}
	return out, nil
}

// ListRSAKeys enumerates RSA keys across every token-present slot, flattening
// ListTokensAndKeys's per-token grouping into a single slice.
func ListRSAKeys(module string) ([]KeyInfo, error) {
	tokens, err := ListTokensAndKeys(module)
	if err != nil {
		return nil, err
	}
	var out []KeyInfo
	for _, t := range tokens {
		out = append(out, t.Keys...)
	}
	return out, nil
}
