package pkcs11

import (
	"bytes"
	"crypto/rsa"
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
	// phSession is a CK_SESSION_HANDLE out-param (CK_ULONG width): 4 bytes on
	// Windows, so a plain Go uintptr would leave garbage in its upper half.
	handle := newCKULongOut()
	rv, _, _ := purego.SyscallN(m.fn(idxOpenSession), slot, flags,
		0, 0, uintptr(handle.ptr()))
	runtime.KeepAlive(handle)
	if rvOf(rv) != CKR_OK {
		return nil, fmt.Errorf("C_OpenSession: %s", rvOf(rv))
	}
	return &Session{m: m, handle: handle.get(), flags: tokenFlags}, nil
}

// findSlot returns the slot id and CK_TOKEN_INFO.flags of the token whose
// label matches tokenLabel.
func (m *Module) findSlot(tokenLabel string) (uintptr, uintptr, error) {
	// count is a CK_ULONG in/out param (slot count): 4 bytes on Windows.
	count := newCKULongOut()
	// tokenPresent = CK_TRUE (1)
	rv, _, _ := purego.SyscallN(m.fn(idxGetSlotList), 1, 0, uintptr(count.ptr()))
	runtime.KeepAlive(count)
	if rvOf(rv) != CKR_OK {
		return 0, 0, fmt.Errorf("C_GetSlotList(count): %s", rvOf(rv))
	}
	n := int(count.get())
	if n == 0 {
		return 0, 0, fmt.Errorf("no token-present slots")
	}
	// The slot-id array holds n CK_SLOT_IDs (CK_ULONG width): 4-byte stride on
	// Windows, so a []uintptr would mis-stride.
	slots := newCKULongArr(n)
	rv, _, _ = purego.SyscallN(m.fn(idxGetSlotList), 1,
		uintptr(slots.ptr()), uintptr(count.ptr()))
	runtime.KeepAlive(slots)
	runtime.KeepAlive(count)
	if rvOf(rv) != CKR_OK {
		return 0, 0, fmt.Errorf("C_GetSlotList: %s", rvOf(rv))
	}

	want := []byte(tokenLabel)
	for i := 0; i < int(count.get()); i++ {
		slot := slots.get(i)
		// CK_TOKEN_INFO begins with label[32] (space-padded, not
		// NUL-terminated), followed by manufacturerID[32] + model[16] +
		// serialNumber[16] = 96 bytes, then flags (CK_ULONG) at byte offset 96.
		// The 96 offset is the same on both ABIs (it is after four CK_CHAR
		// arrays, unaffected by CK_ULONG width or packing), but flags is read
		// at the CK_ULONG width: 8 bytes on unix, 4 on Windows.
		var info [256]byte
		rv, _, _ = purego.SyscallN(m.fn(idxGetTokenInfo), slot, uintptr(unsafe.Pointer(&info[0])))
		if rvOf(rv) != CKR_OK {
			continue
		}
		label := bytes.TrimRight(info[:32], " ")
		if bytes.Equal(label, want) {
			flags := getCKULong(info[96 : 96+ckULongSize])
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
	if rvOf(rv) != CKR_OK {
		return fmt.Errorf("C_Login: %s", rvOf(rv))
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
	if rvOf(rv) != CKR_OK {
		return fmt.Errorf("C_Login (protected authentication path): %s", rvOf(rv))
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
	if rvOf(rv) != CKR_OK {
		return fmt.Errorf("C_CloseSession: %s", rvOf(rv))
	}
	return nil
}

// FindRSAPrivateKey returns the first RSA private key object matching id.
// A nil/empty id matches any RSA private key.
func (s *Session) FindRSAPrivateKey(id []byte) (Object, error) {
	// CKA_CLASS/CKA_KEY_TYPE values are CK_ULONGs, so encodeCKULong sizes them
	// per ABI (8 bytes unix, 4 Windows) and the template is marshaled into the
	// packed CK_ATTRIBUTE layout by packTemplate.
	attrs := []attr{
		{typ: CKA_CLASS, val: encodeCKULong(CKO_PRIVATE_KEY)},
		{typ: CKA_KEY_TYPE, val: encodeCKULong(CKK_RSA)},
	}
	if len(id) > 0 {
		attrs = append(attrs, attr{typ: CKA_ID, val: id})
	}
	tmpl := packTemplate(attrs)

	rv, _, _ := purego.SyscallN(s.m.fn(idxFindObjectsInit), s.handle,
		uintptr(tmpl.ptr()), tmpl.count())
	runtime.KeepAlive(tmpl)
	if rvOf(rv) != CKR_OK {
		return 0, fmt.Errorf("C_FindObjectsInit: %s", rvOf(rv))
	}

	// phObject array (1 slot) and pulObjectCount are CK_ULONG-width out-params.
	obj := newCKULongArr(1)
	found := newCKULongOut()
	rv, _, _ = purego.SyscallN(s.m.fn(idxFindObjects), s.handle,
		uintptr(obj.ptr()), 1, uintptr(found.ptr()))
	runtime.KeepAlive(obj)
	runtime.KeepAlive(found)
	findErr := rvOf(rv)

	rvF, _, _ := purego.SyscallN(s.m.fn(idxFindObjectsFinal), s.handle)
	if findErr != CKR_OK {
		return 0, fmt.Errorf("C_FindObjects: %s", findErr)
	}
	if rvOf(rvF) != CKR_OK {
		return 0, fmt.Errorf("C_FindObjectsFinal: %s", rvOf(rvF))
	}
	if found.get() == 0 {
		return 0, fmt.Errorf("no RSA private key found for id %x", id)
	}
	return obj.get(0), nil
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
	// First call: nil val (pValue=NULL, ulValueLen=0) asks the token for the
	// required size, which it writes back into ulValueLen.
	tmpl := packTemplate([]attr{{typ: attrType}})
	rv, _, _ := purego.SyscallN(s.m.fn(idxGetAttributeValue), s.handle, obj,
		uintptr(tmpl.ptr()), 1)
	runtime.KeepAlive(tmpl)
	if rvOf(rv) != CKR_OK {
		return nil, fmt.Errorf("C_GetAttributeValue(size 0x%x): %s", attrType, rvOf(rv))
	}
	n := tmpl.valueLen(0)
	if n == 0 {
		return nil, nil
	}
	// Second call: point pValue at buf and fetch. valueLen(0) reads the actual
	// length the token wrote back (at the ABI's CK_ULONG width).
	buf := make([]byte, n)
	tmpl.setValue(0, unsafe.Pointer(&buf[0]), n)
	rv, _, _ = purego.SyscallN(s.m.fn(idxGetAttributeValue), s.handle, obj,
		uintptr(tmpl.ptr()), 1)
	runtime.KeepAlive(tmpl)
	runtime.KeepAlive(buf)
	if rvOf(rv) != CKR_OK {
		return nil, fmt.Errorf("C_GetAttributeValue(0x%x): %s", attrType, rvOf(rv))
	}
	return buf[:tmpl.valueLen(0)], nil
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
	mech := packMechanismSimple(CKM_RSA_PKCS_KEY_PAIR_GEN)

	// CK_BBOOL is a single byte on every ABI; CK_TRUE == 0x01. CKA_MODULUS_BITS
	// is a CK_ULONG, so encodeCKULong sizes it per ABI. The packed templates
	// copy every value into their own backing buffer, so the only keep-alive
	// anchors needed across the syscall are the packed templates themselves.
	publicExponent := []byte{0x01, 0x00, 0x01} // 65537
	labelB := []byte(label)

	boolAttr := func(t uintptr) attr { return attr{typ: t, val: []byte{0x01}} }
	labelIDAttrs := func() []attr {
		attrs := []attr{{typ: CKA_LABEL, val: labelB}}
		if len(id) > 0 {
			attrs = append(attrs, attr{typ: CKA_ID, val: id})
		}
		return attrs
	}

	pubAttrs := []attr{
		{typ: CKA_MODULUS_BITS, val: encodeCKULong(uintptr(bits))},
		{typ: CKA_PUBLIC_EXPONENT, val: publicExponent},
		boolAttr(CKA_TOKEN),
		boolAttr(CKA_ENCRYPT),
		boolAttr(CKA_VERIFY),
		boolAttr(CKA_WRAP),
	}
	pubAttrs = append(pubAttrs, labelIDAttrs()...)

	privAttrs := []attr{
		boolAttr(CKA_TOKEN),
		boolAttr(CKA_PRIVATE),
		boolAttr(CKA_SENSITIVE),
		boolAttr(CKA_DECRYPT),
		boolAttr(CKA_SIGN),
		boolAttr(CKA_UNWRAP),
	}
	privAttrs = append(privAttrs, labelIDAttrs()...)

	pubTemplate := packTemplate(pubAttrs)
	privTemplate := packTemplate(privAttrs)

	// phPublicKey/phPrivateKey are CK_OBJECT_HANDLE out-params (CK_ULONG width).
	pubHandle := newCKULongOut()
	privHandle := newCKULongOut()
	rv, _, _ := purego.SyscallN(s.m.fn(idxGenerateKeyPair), s.handle,
		uintptr(mech.ptr()),
		uintptr(pubTemplate.ptr()), pubTemplate.count(),
		uintptr(privTemplate.ptr()), privTemplate.count(),
		uintptr(pubHandle.ptr()), uintptr(privHandle.ptr()))
	runtime.KeepAlive(mech)
	runtime.KeepAlive(pubTemplate)
	runtime.KeepAlive(privTemplate)
	runtime.KeepAlive(pubHandle)
	runtime.KeepAlive(privHandle)

	if code := rvOf(rv); code != CKR_OK {
		if code == CKR_FUNCTION_NOT_SUPPORTED {
			return 0, fmt.Errorf("C_GenerateKeyPair: %s: this token does not support "+
				"on-card key generation via PKCS#11; generate the key directly on the "+
				"device instead, e.g.:\n"+
				"  ykman piv keys generate 9d pub.pem\n"+
				"  yubico-piv-tool -a generate -s 9d", code)
		}
		return 0, fmt.Errorf("C_GenerateKeyPair: %s", code)
	}
	return privHandle.get(), nil
}

// DecryptOAEPSHA256 performs CKM_RSA_PKCS_OAEP (SHA-256, MGF1-SHA256) on the token.
func (s *Session) DecryptOAEPSHA256(priv Object, ct []byte) ([]byte, error) {
	mech := packMechanismOAEP(CKM_RSA_PKCS_OAEP, CKM_SHA256, CKG_MGF1_SHA256, CKZ_DATA_SPECIFIED)
	rv, _, _ := purego.SyscallN(s.m.fn(idxDecryptInit), s.handle,
		uintptr(mech.ptr()), priv)
	runtime.KeepAlive(mech)
	if code := rvOf(rv); code != CKR_OK {
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
	mech := packMechanismSimple(CKM_RSA_X_509)
	rv, _, _ := purego.SyscallN(s.m.fn(idxDecryptInit), s.handle,
		uintptr(mech.ptr()), priv)
	runtime.KeepAlive(mech)
	if code := rvOf(rv); code != CKR_OK {
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
	// pulDataLen is a CK_ULONG in/out param (4 bytes on Windows).
	outLen := newCKULongOut()
	rv, _, _ := purego.SyscallN(s.m.fn(idxDecrypt), s.handle,
		uintptr(unsafe.Pointer(&ct[0])), uintptr(len(ct)), 0, uintptr(outLen.ptr()))
	runtime.KeepAlive(ct)
	runtime.KeepAlive(outLen)
	if rvOf(rv) != CKR_OK {
		return nil, fmt.Errorf("C_Decrypt(size): %s", rvOf(rv))
	}
	out := make([]byte, outLen.get())
	rv, _, _ = purego.SyscallN(s.m.fn(idxDecrypt), s.handle,
		uintptr(unsafe.Pointer(&ct[0])), uintptr(len(ct)),
		uintptr(unsafe.Pointer(&out[0])), uintptr(outLen.ptr()))
	runtime.KeepAlive(ct)
	runtime.KeepAlive(out)
	runtime.KeepAlive(outLen)
	if rvOf(rv) != CKR_OK {
		return nil, fmt.Errorf("C_Decrypt: %s", rvOf(rv))
	}
	return out[:outLen.get()], nil
}
