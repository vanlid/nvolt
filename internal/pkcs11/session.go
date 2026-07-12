//go:build pkcs11

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

// packed reports the struct-packing convention of this session's module: true
// for #pragma pack(1), false for natural alignment. It is derived from the
// header offset detectHeaderOffset measured at Open and threaded into every
// CK_* struct marshaling call (see abipack.go / mechPacked). On unix the value
// is ignored (real Go structs), so this is only load-bearing on Windows.
func (s *Session) packed() bool { return mechPacked(s.m.headerOffset) }

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

// EnsureTokenInitialized brings a blank/uninitialized token up so it can be
// used, returning whether it actually had to initialize it. It is safe to call
// unconditionally before using a token to create keys (generate/import): if the
// token is already live (CKF_TOKEN_INITIALIZED and CKF_USER_PIN_INITIALIZED
// both set) it does nothing and returns false, so an existing token's keys are
// never touched. Otherwise it runs the standard Cryptoki bring-up:
//
//  1. C_InitToken(slot, soPin, label) — sets the SO PIN and labels the (blank)
//     token. Reached only when tokenNeedsInit is true, so it never wipes a live
//     token.
//  2. open a RW session, C_Login(CKU_SO), C_InitPIN(userPin), C_Logout, close.
//
// nvolt's token is single-user / self-managed, so pin is used as BOTH the SO
// PIN and the user PIN. An empty pin (pin_mode=none) initializes with an empty
// user PIN, which wolfPKCS11 accepts. onInit, if non-nil, is invoked once — after
// the token is detected as needing initialization but before any state changes —
// so the caller (which owns the ui layer) can announce it; a live token never
// calls it.
func (m *Module) EnsureTokenInitialized(tokenLabel, pin string, onInit func()) (bool, error) {
	if err := m.initialize(); err != nil {
		return false, err
	}
	slot, flags, err := m.findSlot(tokenLabel)
	if err != nil {
		return false, err
	}
	if !tokenNeedsInit(flags) {
		return false, nil
	}
	// A blank token can only be brought up when we have a PIN to set as its SO
	// and user PIN: PKCS#11 (and wolfPKCS11 in particular, which returns
	// CKR_ARGUMENTS_BAD) reject C_InitToken with an empty SO PIN. A no-PIN flow
	// (pin_mode=none) never performs a user login anyway, so an uninitialized
	// token is used as-is — exactly the pre-existing behavior.
	if pin == "" {
		return false, nil
	}
	if onInit != nil {
		onInit()
	}
	if err := m.initToken(slot, tokenLabel, pin); err != nil {
		return false, err
	}
	if err := m.initUserPIN(slot, pin); err != nil {
		return false, err
	}
	return true, nil
}

// initToken calls C_InitToken(slot, soPin, label). Cryptoki requires the label
// to be exactly 32 bytes, space-padded and NOT NUL-terminated. A blank soPin is
// passed as a NULL pointer with zero length (avoids &pinB[0] on an empty slice).
func (m *Module) initToken(slot uintptr, label, soPin string) error {
	var lbl [32]byte
	for i := range lbl {
		lbl[i] = ' '
	}
	copy(lbl[:], label)
	pinB := []byte(soPin)
	var pinPtr uintptr
	if len(pinB) > 0 {
		pinPtr = uintptr(unsafe.Pointer(&pinB[0]))
	}
	rv, _, _ := purego.SyscallN(m.fn(idxInitToken), slot, pinPtr, uintptr(len(pinB)),
		uintptr(unsafe.Pointer(&lbl[0])))
	runtime.KeepAlive(pinB)
	runtime.KeepAlive(&lbl)
	if rvOf(rv) != CKR_OK {
		return fmt.Errorf("C_InitToken: %s", rvOf(rv))
	}
	return nil
}

// initUserPIN opens a RW session on slot, logs in as the SO role, sets the
// normal-user PIN via C_InitPIN, then logs out and closes the session. C_InitPIN
// must be called on a session where the SO is logged in, and C_InitToken (the
// caller's prior step) leaves no session open, so this opens its own.
func (m *Module) initUserPIN(slot uintptr, pin string) error {
	handle := newCKULongOut()
	rv, _, _ := purego.SyscallN(m.fn(idxOpenSession), slot,
		CKF_SERIAL_SESSION|CKF_RW_SESSION, 0, 0, uintptr(handle.ptr()))
	runtime.KeepAlive(handle)
	if rvOf(rv) != CKR_OK {
		return fmt.Errorf("C_OpenSession (SO): %s", rvOf(rv))
	}
	sh := handle.get()
	defer func() { _, _, _ = purego.SyscallN(m.fn(idxCloseSession), sh) }()

	pinB := []byte(pin)
	var pinPtr uintptr
	if len(pinB) > 0 {
		pinPtr = uintptr(unsafe.Pointer(&pinB[0]))
	}
	rv, _, _ = purego.SyscallN(m.fn(idxLogin), sh, CKU_SO, pinPtr, uintptr(len(pinB)))
	runtime.KeepAlive(pinB)
	if rvOf(rv) != CKR_OK {
		return fmt.Errorf("C_Login (SO): %s", rvOf(rv))
	}

	rv, _, _ = purego.SyscallN(m.fn(idxInitPIN), sh, pinPtr, uintptr(len(pinB)))
	runtime.KeepAlive(pinB)
	if rvOf(rv) != CKR_OK {
		return fmt.Errorf("C_InitPIN: %s", rvOf(rv))
	}

	if rv, _, _ = purego.SyscallN(m.fn(idxLogout), sh); rvOf(rv) != CKR_OK {
		return fmt.Errorf("C_Logout: %s", rvOf(rv))
	}
	return nil
}

// ListKeyIDs returns the CKA_ID of every RSA key (public or private) visible on
// the session's token, deduplicated by id. It is used before key generation to
// auto-pick the next free id or reject a colliding explicit --id. On tokens that
// hide private objects until login it still sees the public-key objects (which
// carry the same CKA_ID), and the session should already be logged in for those
// that hide both.
func (s *Session) ListKeyIDs() [][]byte {
	keys := s.listRSAKeysOnToken("")
	ids := make([][]byte, 0, len(keys))
	for _, k := range keys {
		ids = append(ids, k.ID)
	}
	return ids
}

// DeleteKeyByID destroys every RSA key object (both the private and the public
// half) on the session's token whose CKA_ID equals id, via C_DestroyObject, and
// returns the number of objects destroyed. The session must be logged in to
// reach private objects. It reuses findRSAObjects — the same by-id enumeration
// used by discovery and generation — destroying the private half first, then the
// public. A destroy failure aborts and returns the count destroyed so far.
func (s *Session) DeleteKeyByID(id []byte) (int, error) {
	if len(id) == 0 {
		return 0, fmt.Errorf("DeleteKeyByID: empty id")
	}
	count := 0
	for _, class := range []uintptr{CKO_PRIVATE_KEY, CKO_PUBLIC_KEY} {
		objs, err := s.findRSAObjects(class, id)
		if err != nil {
			return count, err
		}
		for _, obj := range objs {
			rv, _, _ := purego.SyscallN(s.m.fn(idxDestroyObject), s.handle, obj)
			if rvOf(rv) != CKR_OK {
				return count, fmt.Errorf("C_DestroyObject: %s", rvOf(rv))
			}
			count++
		}
	}
	return count, nil
}

// RelabelKeyByID sets CKA_LABEL to label on every RSA key object (both the
// private and the public half) whose CKA_ID equals id, via C_SetAttributeValue,
// and returns the number of objects updated. The session must be logged in to
// modify private objects. Reuses findRSAObjects to locate the halves.
func (s *Session) RelabelKeyByID(id []byte, label string) (int, error) {
	if len(id) == 0 {
		return 0, fmt.Errorf("RelabelKeyByID: empty id")
	}
	count := 0
	for _, class := range []uintptr{CKO_PRIVATE_KEY, CKO_PUBLIC_KEY} {
		objs, err := s.findRSAObjects(class, id)
		if err != nil {
			return count, err
		}
		for _, obj := range objs {
			tmpl := packTemplate([]attr{{typ: CKA_LABEL, val: []byte(label)}}, s.packed())
			rv, _, _ := purego.SyscallN(s.m.fn(idxSetAttributeValue), s.handle, obj,
				uintptr(tmpl.ptr()), tmpl.count())
			runtime.KeepAlive(tmpl)
			if rvOf(rv) != CKR_OK {
				return count, fmt.Errorf("C_SetAttributeValue: %s", rvOf(rv))
			}
			count++
		}
	}
	return count, nil
}

// findSlot returns the slot id and CK_TOKEN_INFO.flags of the token whose
// label matches tokenLabel.
func (m *Module) findSlot(tokenLabel string) (slotID, tokenFlags uintptr, err error) {
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
	if pin == "" {
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
	tmpl := packTemplate(attrs, s.packed())

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

// RSAPublicKeyByID reads the RSA public key material (CKA_MODULUS +
// CKA_PUBLIC_EXPONENT) for the key identified by CKA_ID id, without logging
// in. It tries CKO_PUBLIC_KEY first — the object class every token exposes
// pre-login, per ListTokensAndKeys's discovery comment — then falls back to
// CKO_PRIVATE_KEY for tokens that don't hide private objects before
// authentication. This lets callers that only need the public half (e.g.
// `machine add --pkcs11`, which registers someone's public key with no
// decrypt involved) skip C_Login entirely, even on tokens like SoftHSM where
// the private object is CKA_PRIVATE=true and invisible pre-login.
func (s *Session) RSAPublicKeyByID(id []byte) (*rsa.PublicKey, error) {
	for _, class := range []uintptr{CKO_PUBLIC_KEY, CKO_PRIVATE_KEY} {
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
	tmpl := packTemplate([]attr{{typ: attrType}}, s.packed())
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
	mech := packMechanismSimple(CKM_RSA_PKCS_KEY_PAIR_GEN, s.packed())

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

	pubTemplate := packTemplate(pubAttrs, s.packed())
	privTemplate := packTemplate(privAttrs, s.packed())

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

// ImportRSAPrivateKey creates a token (persistent) RSA private key object from
// priv via C_CreateObject. The key is marked CKA_DECRYPT so nvolt can unwrap
// with it. Returns the created object handle. Tokens that forbid PKCS#11 key
// import (e.g. YubiKey via OpenSC) return the token's error unchanged.
func (s *Session) ImportRSAPrivateKey(label string, id []byte, priv *rsa.PrivateKey) (Object, error) {
	priv.Precompute()
	bytesOf := func(i *big.Int) []byte { return i.Bytes() }
	eBytes := big.NewInt(int64(priv.E)).Bytes()

	boolAttr := func(t uintptr) attr { return attr{typ: t, val: []byte{0x01}} }
	attrs := []attr{
		{typ: CKA_CLASS, val: encodeCKULong(CKO_PRIVATE_KEY)},
		{typ: CKA_KEY_TYPE, val: encodeCKULong(CKK_RSA)},
		boolAttr(CKA_TOKEN),
		boolAttr(CKA_PRIVATE),
		boolAttr(CKA_DECRYPT),
		{typ: CKA_LABEL, val: []byte(label)},
		{typ: CKA_MODULUS, val: bytesOf(priv.N)},
		{typ: CKA_PUBLIC_EXPONENT, val: eBytes},
		{typ: CKA_PRIVATE_EXPONENT, val: bytesOf(priv.D)},
		{typ: CKA_PRIME_1, val: bytesOf(priv.Primes[0])},
		{typ: CKA_PRIME_2, val: bytesOf(priv.Primes[1])},
		{typ: CKA_EXPONENT_1, val: bytesOf(priv.Precomputed.Dp)},
		{typ: CKA_EXPONENT_2, val: bytesOf(priv.Precomputed.Dq)},
		{typ: CKA_COEFFICIENT, val: bytesOf(priv.Precomputed.Qinv)},
	}
	if len(id) > 0 {
		attrs = append(attrs, attr{typ: CKA_ID, val: id})
	}
	tmpl := packTemplate(attrs, s.packed())
	objHandle := newCKULongOut()
	rv, _, _ := purego.SyscallN(s.m.fn(idxCreateObject), s.handle,
		uintptr(tmpl.ptr()), tmpl.count(), uintptr(objHandle.ptr()))
	runtime.KeepAlive(tmpl)
	runtime.KeepAlive(objHandle)
	if code := rvOf(rv); code != CKR_OK {
		if code == CKR_FUNCTION_NOT_SUPPORTED {
			return 0, fmt.Errorf("C_CreateObject: %s: this token does not support PKCS#11 "+
				"key import; import the key with the device's own tool instead, e.g.:\n"+
				"  ykman piv keys import 9d key.pem", code)
		}
		return 0, fmt.Errorf("C_CreateObject: %s", code)
	}

	// Also create the matching CKO_PUBLIC_KEY object. C_GenerateKeyPair yields
	// both a public and a private object; C_CreateObject creates only what we
	// hand it, so without this second create an imported key has no public-key
	// object — and because the private object is CKA_PRIVATE=true (hidden
	// pre-login), the key would be invisible to no-login discovery
	// (`pkcs11 list`) and to RSAPublicKeyByID's fingerprint path. Mirror
	// GenerateRSAKeyPair's public template. Best-effort: a token that
	// auto-derives the public half (or otherwise rejects a second create) must
	// not fail an import whose private object already succeeded; wolfPKCS11 needs
	// the explicit object and accepts it here.
	pubAttrs := []attr{
		{typ: CKA_CLASS, val: encodeCKULong(CKO_PUBLIC_KEY)},
		{typ: CKA_KEY_TYPE, val: encodeCKULong(CKK_RSA)},
		boolAttr(CKA_TOKEN),
		boolAttr(CKA_ENCRYPT),
		boolAttr(CKA_VERIFY),
		boolAttr(CKA_WRAP),
		{typ: CKA_LABEL, val: []byte(label)},
		{typ: CKA_MODULUS, val: bytesOf(priv.N)},
		{typ: CKA_PUBLIC_EXPONENT, val: eBytes},
	}
	if len(id) > 0 {
		pubAttrs = append(pubAttrs, attr{typ: CKA_ID, val: id})
	}
	pubTmpl := packTemplate(pubAttrs, s.packed())
	pubHandle := newCKULongOut()
	_, _, _ = purego.SyscallN(s.m.fn(idxCreateObject), s.handle,
		uintptr(pubTmpl.ptr()), pubTmpl.count(), uintptr(pubHandle.ptr()))
	runtime.KeepAlive(pubTmpl)
	runtime.KeepAlive(pubHandle)

	return objHandle.get(), nil
}

// oaepDecryptAttempts bounds transient-error retries in DecryptOAEPSHA256.
// Sized for flaky TPMs (the AMD fTPM fails an OAEP decrypt intermittently); a
// handful of in-process retries absorbs isolated hiccups.
const oaepDecryptAttempts = 5

// DecryptOAEPSHA256 performs CKM_RSA_PKCS_OAEP (SHA-256, MGF1-SHA256) on the
// token, with a bounded retry. Some TPMs (AMD fTPM via wolfPKCS11) intermittently
// fail an OAEP decrypt and succeed on retry — this affects BOTH the enroll
// self-test and the runtime master-key unwrap (pull). A permanent failure still
// fails on every attempt, and the capability error (ErrMechanismUnsupported) is
// never retried, so a genuine "can't do OAEP-SHA256" still falls through fast.
func (s *Session) DecryptOAEPSHA256(priv Object, ct []byte) ([]byte, error) {
	var out []byte
	var err error
	for attempt := 0; attempt < oaepDecryptAttempts; attempt++ {
		if out, err = s.decryptOAEPSHA256Once(priv, ct); err == nil || errors.Is(err, ErrMechanismUnsupported) {
			break
		}
	}
	return out, err
}

func (s *Session) decryptOAEPSHA256Once(priv Object, ct []byte) ([]byte, error) {
	mech := packMechanismOAEP(CKM_RSA_PKCS_OAEP, CKM_SHA256, CKG_MGF1_SHA256, CKZ_DATA_SPECIFIED, s.packed())
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
	mech := packMechanismSimple(CKM_RSA_X_509, s.packed())
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
