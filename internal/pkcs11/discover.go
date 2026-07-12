//go:build pkcs11

package pkcs11

import (
	"bytes"
	"fmt"
	"math/big"
	"runtime"
	"unsafe"

	"github.com/ebitengine/purego"
)

// ListTokensAndKeys enumerates every token-present slot of the module and
// returns one TokenListing per token, including tokens with no RSA keys at
// all (e.g. a freshly-provisioned YubiKey PIV slot): unlike ListRSAKeys, an
// empty token is still represented in the result instead of disappearing, so
// "card detected, no key yet" is distinguishable from "no card detected".
// It does not log in; it reports the RSA key objects that are visible without
// authentication (private-key objects where the token exposes them, otherwise
// the public-key objects that describe the same keypair), deduplicated by
// (token, id) so a keypair surfaces once.
func ListTokensAndKeys(module string) ([]TokenListing, error) {
	m, err := Open(module)
	if err != nil {
		return nil, err
	}
	defer func() { _ = m.Close() }()
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
		// phSession is a CK_SESSION_HANDLE out-param (CK_ULONG width).
		handle := newCKULongOut()
		rv, _, _ := purego.SyscallN(m.fn(idxOpenSession), slot, CKF_SERIAL_SESSION,
			0, 0, uintptr(handle.ptr()))
		runtime.KeepAlive(handle)
		if rvOf(rv) != CKR_OK {
			continue
		}
		s := &Session{m: m, handle: handle.get()}
		keys := s.listRSAKeysOnToken(label)
		_ = s.Close()
		out = append(out, TokenListing{Label: label, Keys: keys})
	}
	return out, nil
}

// ListRSAKeys enumerates RSA keys across every token-present slot of the
// module, flattening ListTokensAndKeys's per-token grouping into a single
// slice (a token with no RSA keys contributes nothing, same as before this
// was reimplemented in terms of ListTokensAndKeys). It does not log in; it
// reports the RSA key objects that are visible without authentication
// (private-key objects where the token exposes them, otherwise the
// public-key objects that describe the same keypair), deduplicated by
// (token, id) so a keypair surfaces once.
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

// slotList returns the ids of all token-present slots.
func (m *Module) slotList() ([]uintptr, error) {
	// count is a CK_ULONG in/out param; the slot array holds CK_ULONG-width
	// CK_SLOT_IDs (4-byte stride on Windows).
	count := newCKULongOut()
	rv, _, _ := purego.SyscallN(m.fn(idxGetSlotList), 1, 0, uintptr(count.ptr()))
	runtime.KeepAlive(count)
	if rvOf(rv) != CKR_OK {
		return nil, fmt.Errorf("C_GetSlotList(count): %s", rvOf(rv))
	}
	n := int(count.get())
	if n == 0 {
		return nil, nil
	}
	slots := newCKULongArr(n)
	rv, _, _ = purego.SyscallN(m.fn(idxGetSlotList), 1,
		uintptr(slots.ptr()), uintptr(count.ptr()))
	runtime.KeepAlive(slots)
	runtime.KeepAlive(count)
	if rvOf(rv) != CKR_OK {
		return nil, fmt.Errorf("C_GetSlotList: %s", rvOf(rv))
	}
	out := make([]uintptr, count.get())
	for i := range out {
		out[i] = slots.get(i)
	}
	return out, nil
}

// tokenLabel reads the space-trimmed CKA label from a slot's CK_TOKEN_INFO.
func (m *Module) tokenLabel(slot uintptr) (string, error) {
	var info [256]byte
	rv, _, _ := purego.SyscallN(m.fn(idxGetTokenInfo), slot, uintptr(unsafe.Pointer(&info[0])))
	if rvOf(rv) != CKR_OK {
		return "", fmt.Errorf("C_GetTokenInfo: %s", rvOf(rv))
	}
	return string(bytes.TrimRight(info[:32], " ")), nil
}

// listRSAKeysOnToken enumerates RSA private- then public-key objects on the
// session's token, returning one KeyInfo per distinct CKA_ID.
func (s *Session) listRSAKeysOnToken(tokenLabel string) []KeyInfo {
	seen := map[string]bool{}
	var out []KeyInfo
	for _, class := range []uintptr{CKO_PRIVATE_KEY, CKO_PUBLIC_KEY} {
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

// findRSAObjects returns all handles of RSA objects of the given class,
// optionally filtered to a specific CKA_ID. A nil id means "no id filter"
// (match any RSA object of the class); a non-nil id adds a CKA_ID term to
// the search template so only the object(s) with that id are returned.
func (s *Session) findRSAObjects(class uintptr, id []byte) ([]Object, error) {
	// CKA_CLASS/CKA_KEY_TYPE values are CK_ULONGs (encodeCKULong sizes per ABI).
	attrs := []attr{
		{typ: CKA_CLASS, val: encodeCKULong(class)},
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
		return nil, fmt.Errorf("C_FindObjectsInit: %s", rvOf(rv))
	}

	const batch = 32
	var out []Object
	for {
		// phObject array (CK_ULONG-width handles) + pulObjectCount out-param.
		objs := newCKULongArr(batch)
		found := newCKULongOut()
		rv, _, _ = purego.SyscallN(s.m.fn(idxFindObjects), s.handle,
			uintptr(objs.ptr()), uintptr(batch), uintptr(found.ptr()))
		runtime.KeepAlive(objs)
		runtime.KeepAlive(found)
		if rvOf(rv) != CKR_OK {
			_, _, _ = purego.SyscallN(s.m.fn(idxFindObjectsFinal), s.handle)
			return nil, fmt.Errorf("C_FindObjects: %s", rvOf(rv))
		}
		f := int(found.get())
		if f == 0 {
			break
		}
		for i := 0; i < f; i++ {
			out = append(out, objs.get(i))
		}
		if f < batch {
			break
		}
	}
	rvF, _, _ := purego.SyscallN(s.m.fn(idxFindObjectsFinal), s.handle)
	if rvOf(rvF) != CKR_OK {
		return nil, fmt.Errorf("C_FindObjectsFinal: %s", rvOf(rvF))
	}
	return out, nil
}

// rsaKeyInfo reads CKA_ID, CKA_LABEL and CKA_MODULUS from an RSA object.
func (s *Session) rsaKeyInfo(tokenLabel string, obj Object) (KeyInfo, error) {
	id, _ := s.getAttribute(obj, CKA_ID)
	label, _ := s.getAttribute(obj, CKA_LABEL)
	mod, err := s.getAttribute(obj, CKA_MODULUS)
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
