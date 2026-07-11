package pkcs11

import (
	"bytes"
	"crypto/rsa"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"runtime"
	"unsafe"

	"github.com/ebitengine/purego"
)

// ErrMechanismUnsupported reports that the token refused the requested
// mechanism or its parameters (e.g. C_DecryptInit returning
// CKR_MECHANISM_INVALID or CKR_ARGUMENTS_BAD). Callers wrap-test with
// errors.Is to fall back to a software-padding path (Task 3). Notably,
// SoftHSM 2.6.1 supports RSA-OAEP only with SHA-1 and returns
// CKR_ARGUMENTS_BAD for SHA-256 params.
var ErrMechanismUnsupported = errors.New("pkcs11: mechanism or parameters not supported by token")

// Session is an open PKCS#11 session against a single token.
type Session struct {
	m      *Module
	handle uintptr
	// flags is the token's CK_TOKEN_INFO.flags, captured by openSession at
	// C_OpenSession time so callers can auto-detect PIN handling
	// (CKF_LOGIN_REQUIRED / CKF_PROTECTED_AUTHENTICATION_PATH) without a
	// second C_GetTokenInfo round trip.
	flags uintptr
}

// Object is a PKCS#11 object handle.
type Object = uintptr

// OpenSession initializes the module (once), finds the slot whose token label
// matches tokenLabel, and opens a read-only serial session on it. Most
// callers (decrypt, enroll, list/use, discovery) only ever read objects and
// must not request CKF_RW_SESSION: a read-only or write-protected token
// returns CKR_TOKEN_WRITE_PROTECTED for a RW C_OpenSession, which would
// otherwise break the core decrypt path. Use OpenSessionRW for the one
// caller that creates token objects (key generation).
func (m *Module) OpenSession(tokenLabel string) (*Session, error) {
	return m.openSession(tokenLabel, false)
}

// OpenSessionRW opens a read-write serial session (CKF_RW_SESSION), required
// to create token objects (CKA_TOKEN=true) in GenerateRSAKeyPair. Only the
// key-generation path should use this; every other caller should use the
// read-only OpenSession.
func (m *Module) OpenSessionRW(tokenLabel string) (*Session, error) {
	return m.openSession(tokenLabel, true)
}

// openSession finds the slot whose token label matches tokenLabel and opens
// a serial session on it, read-write only when rw is true.
func (m *Module) openSession(tokenLabel string, rw bool) (*Session, error) {
	if err := m.initialize(); err != nil {
		return nil, err
	}
	slot, tokenFlags, err := m.findSlot(tokenLabel)
	if err != nil {
		return nil, err
	}
	flags := uintptr(CKF_SERIAL_SESSION)
	if rw {
		flags |= CKF_RW_SESSION
	}
	var handle uintptr
	rv, _, _ := purego.SyscallN(m.fn(idxOpenSession), slot, flags,
		0, 0, uintptr(unsafe.Pointer(&handle)))
	if CKRV(rv) != CKR_OK {
		return nil, fmt.Errorf("C_OpenSession: %s", CKRV(rv))
	}
	return &Session{m: m, handle: handle, flags: tokenFlags}, nil
}

// findSlot returns the slot id and CK_TOKEN_INFO.flags of the token whose
// label matches tokenLabel.
func (m *Module) findSlot(tokenLabel string) (uintptr, uintptr, error) {
	var count uintptr
	// tokenPresent = CK_TRUE (1)
	rv, _, _ := purego.SyscallN(m.fn(idxGetSlotList), 1, 0, uintptr(unsafe.Pointer(&count)))
	if CKRV(rv) != CKR_OK {
		return 0, 0, fmt.Errorf("C_GetSlotList(count): %s", CKRV(rv))
	}
	if count == 0 {
		return 0, 0, fmt.Errorf("no token-present slots")
	}
	slots := make([]uintptr, count)
	rv, _, _ = purego.SyscallN(m.fn(idxGetSlotList), 1,
		uintptr(unsafe.Pointer(&slots[0])), uintptr(unsafe.Pointer(&count)))
	if CKRV(rv) != CKR_OK {
		return 0, 0, fmt.Errorf("C_GetSlotList: %s", CKRV(rv))
	}

	want := []byte(tokenLabel)
	for _, slot := range slots[:count] {
		// CK_TOKEN_INFO (Cryptoki 2.40, LP64) begins with label[32]
		// (space-padded, not NUL-terminated), followed by manufacturerID[32]
		// + model[16] + serialNumber[16] = 96 bytes, then flags (CK_ULONG,
		// 8 bytes) at byte offset 96.
		var info [256]byte
		rv, _, _ = purego.SyscallN(m.fn(idxGetTokenInfo), slot, uintptr(unsafe.Pointer(&info[0])))
		if CKRV(rv) != CKR_OK {
			continue
		}
		label := bytes.TrimRight(info[:32], " ")
		if bytes.Equal(label, want) {
			flags := uintptr(binary.LittleEndian.Uint64(info[96:104]))
			return slot, flags, nil
		}
	}
	return 0, 0, fmt.Errorf("no token with label %q", tokenLabel)
}

// Login authenticates as the normal (user) role with the given PIN. An empty
// pin is treated as "no login" and returns nil without calling C_Login: this
// is the CKF_PROTECTED_AUTHENTICATION_PATH convention (pin_mode=none), and it
// also defends against &pinB[0] on an empty slice, which would panic with an
// index-out-of-range. Callers already guard on pin != "" before calling
// Login, but this keeps Login itself safe for any future caller.
func (s *Session) Login(pin string) error {
	if len(pin) == 0 {
		return nil
	}
	pinB := []byte(pin)
	rv, _, _ := purego.SyscallN(s.m.fn(idxLogin), s.handle, CKU_USER,
		uintptr(unsafe.Pointer(&pinB[0])), uintptr(len(pinB)))
	runtime.KeepAlive(pinB)
	if CKRV(rv) != CKR_OK {
		return fmt.Errorf("C_Login: %s", CKRV(rv))
	}
	return nil
}

// ProtectedAuthPath reports whether the token sets
// CKF_PROTECTED_AUTHENTICATION_PATH: the reader/pinpad collects the PIN
// itself, so the application must call LoginProtected (a NULL-PIN C_Login)
// rather than prompting for and supplying a PIN.
func (s *Session) ProtectedAuthPath() bool {
	return s.flags&CKF_PROTECTED_AUTHENTICATION_PATH != 0
}

// LoginRequired reports whether the token sets CKF_LOGIN_REQUIRED. When
// false, private objects are accessible without ever calling C_Login.
func (s *Session) LoginRequired() bool {
	return s.flags&CKF_LOGIN_REQUIRED != 0
}

// LoginProtected authenticates as the normal (user) role on a token whose
// CKF_PROTECTED_AUTHENTICATION_PATH flag is set. It always calls C_Login
// with a NULL PIN pointer and zero length so the reader/pinpad prompts the
// user directly; the application must not (and, lacking the flag's
// out-of-band channel, cannot) supply a PIN itself.
func (s *Session) LoginProtected() error {
	rv, _, _ := purego.SyscallN(s.m.fn(idxLogin), s.handle, CKU_USER, 0, 0)
	if CKRV(rv) != CKR_OK {
		return fmt.Errorf("C_Login (protected authentication path): %s", CKRV(rv))
	}
	return nil
}

// Close closes the session.
func (s *Session) Close() error {
	if s.handle == 0 {
		return nil
	}
	rv, _, _ := purego.SyscallN(s.m.fn(idxCloseSession), s.handle)
	s.handle = 0
	if CKRV(rv) != CKR_OK {
		return fmt.Errorf("C_CloseSession: %s", CKRV(rv))
	}
	return nil
}

// FindRSAPrivateKey returns the first RSA private key object matching id.
// A nil/empty id matches any RSA private key.
func (s *Session) FindRSAPrivateKey(id []byte) (Object, error) {
	class := CKO_PRIVATE_KEY
	keyType := CKK_RSA
	attrs := []CK_ATTRIBUTE{
		{Type: CKA_CLASS, Value: unsafe.Pointer(&class), Len: unsafe.Sizeof(class)},
		{Type: CKA_KEY_TYPE, Value: unsafe.Pointer(&keyType), Len: unsafe.Sizeof(keyType)},
	}
	if len(id) > 0 {
		attrs = append(attrs, CK_ATTRIBUTE{Type: CKA_ID, Value: unsafe.Pointer(&id[0]), Len: uintptr(len(id))})
	}

	rv, _, _ := purego.SyscallN(s.m.fn(idxFindObjectsInit), s.handle,
		uintptr(unsafe.Pointer(&attrs[0])), uintptr(len(attrs)))
	runtime.KeepAlive(attrs)
	runtime.KeepAlive(id)
	if CKRV(rv) != CKR_OK {
		return 0, fmt.Errorf("C_FindObjectsInit: %s", CKRV(rv))
	}

	var obj uintptr
	var found uintptr
	rv, _, _ = purego.SyscallN(s.m.fn(idxFindObjects), s.handle,
		uintptr(unsafe.Pointer(&obj)), 1, uintptr(unsafe.Pointer(&found)))
	findErr := CKRV(rv)

	rvF, _, _ := purego.SyscallN(s.m.fn(idxFindObjectsFinal), s.handle)
	if findErr != CKR_OK {
		return 0, fmt.Errorf("C_FindObjects: %s", findErr)
	}
	if CKRV(rvF) != CKR_OK {
		return 0, fmt.Errorf("C_FindObjectsFinal: %s", CKRV(rvF))
	}
	if found == 0 {
		return 0, fmt.Errorf("no RSA private key found for id %x", id)
	}
	return obj, nil
}

// RSAPublicKey reads CKA_MODULUS and CKA_PUBLIC_EXPONENT from an RSA key
// object and reconstructs the public key.
func (s *Session) RSAPublicKey(obj Object) (*rsa.PublicKey, error) {
	mod, err := s.getAttribute(obj, CKA_MODULUS)
	if err != nil {
		return nil, err
	}
	exp, err := s.getAttribute(obj, CKA_PUBLIC_EXPONENT)
	if err != nil {
		return nil, err
	}
	return &rsa.PublicKey{
		N: new(big.Int).SetBytes(mod),
		E: int(new(big.Int).SetBytes(exp).Int64()),
	}, nil
}

// getAttribute fetches one attribute value using the two-call length pattern.
func (s *Session) getAttribute(obj Object, attrType uintptr) ([]byte, error) {
	tmpl := []CK_ATTRIBUTE{{Type: attrType, Value: nil, Len: 0}}
	rv, _, _ := purego.SyscallN(s.m.fn(idxGetAttributeValue), s.handle, obj,
		uintptr(unsafe.Pointer(&tmpl[0])), 1)
	if CKRV(rv) != CKR_OK {
		return nil, fmt.Errorf("C_GetAttributeValue(size 0x%x): %s", attrType, CKRV(rv))
	}
	if tmpl[0].Len == 0 {
		return nil, nil
	}
	buf := make([]byte, tmpl[0].Len)
	tmpl[0].Value = unsafe.Pointer(&buf[0])
	rv, _, _ = purego.SyscallN(s.m.fn(idxGetAttributeValue), s.handle, obj,
		uintptr(unsafe.Pointer(&tmpl[0])), 1)
	runtime.KeepAlive(buf)
	if CKRV(rv) != CKR_OK {
		return nil, fmt.Errorf("C_GetAttributeValue(0x%x): %s", attrType, CKRV(rv))
	}
	return buf[:tmpl[0].Len], nil
}

// GenerateRSAKeyPair generates an RSA keypair on the token via
// C_GenerateKeyPair(CKM_RSA_PKCS_KEY_PAIR_GEN) and returns the private-key
// object handle. label/id tag both objects; bits is the modulus size (e.g.
// 2048). Public exponent is fixed at 65537.
//
// If the token does not implement C_GenerateKeyPair (CKR_FUNCTION_NOT_SUPPORTED,
// as some PIV tokens surface via PKCS#11), the returned error spells out the
// manual on-card generation fallback (ykman / yubico-piv-tool).
func (s *Session) GenerateRSAKeyPair(label string, id []byte, bits int) (Object, error) {
	mech := CK_MECHANISM{Mechanism: CKM_RSA_PKCS_KEY_PAIR_GEN, Param: nil, ParamLen: 0}

	// CK_BBOOL is a single byte; CK_TRUE == 0x01. modulusBits is a CK_ULONG
	// (uintptr, 8 bytes on linux/amd64). Keep the backing values addressable
	// for the whole call and pin them with runtime.KeepAlive below, exactly as
	// FindObjects/Decrypt do with their attribute-backing slices.
	ckTrue := []byte{0x01}
	modulusBits := uintptr(bits)
	publicExponent := []byte{0x01, 0x00, 0x01} // 65537
	labelB := []byte(label)

	boolAttr := func(t uintptr) CK_ATTRIBUTE {
		return CK_ATTRIBUTE{Type: t, Value: unsafe.Pointer(&ckTrue[0]), Len: 1}
	}
	labelIDAttrs := func() []CK_ATTRIBUTE {
		attrs := []CK_ATTRIBUTE{{Type: CKA_LABEL, Value: unsafe.Pointer(&labelB[0]), Len: uintptr(len(labelB))}}
		if len(id) > 0 {
			attrs = append(attrs, CK_ATTRIBUTE{Type: CKA_ID, Value: unsafe.Pointer(&id[0]), Len: uintptr(len(id))})
		}
		return attrs
	}

	pubTemplate := []CK_ATTRIBUTE{
		{Type: CKA_MODULUS_BITS, Value: unsafe.Pointer(&modulusBits), Len: unsafe.Sizeof(modulusBits)},
		{Type: CKA_PUBLIC_EXPONENT, Value: unsafe.Pointer(&publicExponent[0]), Len: uintptr(len(publicExponent))},
		boolAttr(CKA_TOKEN),
		boolAttr(CKA_ENCRYPT),
		boolAttr(CKA_VERIFY),
		boolAttr(CKA_WRAP),
	}
	pubTemplate = append(pubTemplate, labelIDAttrs()...)

	privTemplate := []CK_ATTRIBUTE{
		boolAttr(CKA_TOKEN),
		boolAttr(CKA_PRIVATE),
		boolAttr(CKA_SENSITIVE),
		boolAttr(CKA_DECRYPT),
		boolAttr(CKA_SIGN),
		boolAttr(CKA_UNWRAP),
	}
	privTemplate = append(privTemplate, labelIDAttrs()...)

	var pubHandle, privHandle uintptr
	rv, _, _ := purego.SyscallN(s.m.fn(idxGenerateKeyPair), s.handle,
		uintptr(unsafe.Pointer(&mech)),
		uintptr(unsafe.Pointer(&pubTemplate[0])), uintptr(len(pubTemplate)),
		uintptr(unsafe.Pointer(&privTemplate[0])), uintptr(len(privTemplate)),
		uintptr(unsafe.Pointer(&pubHandle)), uintptr(unsafe.Pointer(&privHandle)))
	runtime.KeepAlive(&mech)
	runtime.KeepAlive(ckTrue)
	runtime.KeepAlive(&modulusBits)
	runtime.KeepAlive(publicExponent)
	runtime.KeepAlive(labelB)
	runtime.KeepAlive(id)
	runtime.KeepAlive(pubTemplate)
	runtime.KeepAlive(privTemplate)

	if code := CKRV(rv); code != CKR_OK {
		if code == CKR_FUNCTION_NOT_SUPPORTED {
			return 0, fmt.Errorf("C_GenerateKeyPair: %s: this token does not support "+
				"on-card key generation via PKCS#11; generate the key directly on the "+
				"device instead, e.g.:\n"+
				"  ykman piv keys generate 9d pub.pem\n"+
				"  yubico-piv-tool -a generate -s 9d", code)
		}
		return 0, fmt.Errorf("C_GenerateKeyPair: %s", code)
	}
	return privHandle, nil
}

// DecryptOAEPSHA256 performs CKM_RSA_PKCS_OAEP (SHA-256, MGF1-SHA256) on the token.
func (s *Session) DecryptOAEPSHA256(priv Object, ct []byte) ([]byte, error) {
	params := ckOAEPParams{HashAlg: CKM_SHA256, Mgf: CKG_MGF1_SHA256, SourceType: CKZ_DATA_SPECIFIED}
	mech := CK_MECHANISM{
		Mechanism: CKM_RSA_PKCS_OAEP,
		Param:     unsafe.Pointer(&params),
		ParamLen:  unsafe.Sizeof(params),
	}
	rv, _, _ := purego.SyscallN(s.m.fn(idxDecryptInit), s.handle,
		uintptr(unsafe.Pointer(&mech)), priv)
	runtime.KeepAlive(&params)
	runtime.KeepAlive(&mech)
	if code := CKRV(rv); code != CKR_OK {
		if code == CKR_MECHANISM_INVALID || code == CKR_ARGUMENTS_BAD {
			return nil, fmt.Errorf("C_DecryptInit(OAEP): %s: %w", code, ErrMechanismUnsupported)
		}
		return nil, fmt.Errorf("C_DecryptInit(OAEP): %s", code)
	}
	return s.doDecrypt(ct)
}

// DecryptRawRSA performs CKM_RSA_X_509 (raw RSA, no padding) on the token,
// returning the k-byte, left-zero-padded RSA decryption block m = c^d mod n.
// Callers strip OAEP-SHA256 padding in software via crypto.UnpadOAEPSHA256.
// This is the fallback path for tokens (e.g. SoftHSM 2.6.1) that do not expose
// native RSA-OAEP-SHA256; see ErrMechanismUnsupported.
func (s *Session) DecryptRawRSA(priv Object, ct []byte) ([]byte, error) {
	mech := CK_MECHANISM{
		Mechanism: CKM_RSA_X_509,
		Param:     nil,
		ParamLen:  0,
	}
	rv, _, _ := purego.SyscallN(s.m.fn(idxDecryptInit), s.handle,
		uintptr(unsafe.Pointer(&mech)), priv)
	runtime.KeepAlive(&mech)
	if code := CKRV(rv); code != CKR_OK {
		if code == CKR_MECHANISM_INVALID || code == CKR_ARGUMENTS_BAD {
			return nil, fmt.Errorf("C_DecryptInit(RSA_X_509): %s: %w", code, ErrMechanismUnsupported)
		}
		return nil, fmt.Errorf("C_DecryptInit(RSA_X_509): %s", code)
	}
	raw, err := s.doDecrypt(ct)
	if err != nil {
		return nil, err
	}
	// For raw RSA the plaintext block length equals the modulus length, which
	// equals len(ct). A token may return the result as a big-endian integer
	// with leading zero bytes trimmed; UnpadOAEPSHA256 requires exactly k bytes
	// (the OAEP EM always starts with 0x00), so left-zero-pad to len(ct).
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
	var outLen uintptr
	rv, _, _ := purego.SyscallN(s.m.fn(idxDecrypt), s.handle,
		uintptr(unsafe.Pointer(&ct[0])), uintptr(len(ct)), 0, uintptr(unsafe.Pointer(&outLen)))
	if CKRV(rv) != CKR_OK {
		return nil, fmt.Errorf("C_Decrypt(size): %s", CKRV(rv))
	}
	out := make([]byte, outLen)
	rv, _, _ = purego.SyscallN(s.m.fn(idxDecrypt), s.handle,
		uintptr(unsafe.Pointer(&ct[0])), uintptr(len(ct)),
		uintptr(unsafe.Pointer(&out[0])), uintptr(unsafe.Pointer(&outLen)))
	runtime.KeepAlive(ct)
	runtime.KeepAlive(out)
	if CKRV(rv) != CKR_OK {
		return nil, fmt.Errorf("C_Decrypt: %s", CKRV(rv))
	}
	return out[:outLen], nil
}
