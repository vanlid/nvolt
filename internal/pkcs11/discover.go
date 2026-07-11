package pkcs11

import (
	"bytes"
	"fmt"
	"math/big"
	"runtime"
	"unsafe"

	"github.com/ebitengine/purego"
)

// KeyInfo describes an RSA key discovered on a token. Discovery runs without a
// PIN, so on tokens that hide private objects until login (e.g. SoftHSM) the
// data is read from the matching public-key object, which shares the same
// CKA_ID/CKA_LABEL and modulus.
type KeyInfo struct {
	TokenLabel string
	Label      string
	ID         []byte
	Bits       int
}

// TokenListing describes one token seen by ListTokensAndKeys: the token's
// label and whatever RSA keys are visible on it without a PIN. Keys is empty
// (not omitted) for a token that has no RSA keys yet, so callers can render
// the token as detected while pointing the user at how to create one.
type TokenListing struct {
	Label string
	Keys  []KeyInfo
}

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
		var handle uintptr
		rv, _, _ := purego.SyscallN(m.fn(idxOpenSession), slot, CKF_SERIAL_SESSION,
			0, 0, uintptr(unsafe.Pointer(&handle)))
		if CKRV(rv) != CKR_OK {
			continue
		}
		s := &Session{m: m, handle: handle}
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
	var count uintptr
	rv, _, _ := purego.SyscallN(m.fn(idxGetSlotList), 1, 0, uintptr(unsafe.Pointer(&count)))
	if CKRV(rv) != CKR_OK {
		return nil, fmt.Errorf("C_GetSlotList(count): %s", CKRV(rv))
	}
	if count == 0 {
		return nil, nil
	}
	slots := make([]uintptr, count)
	rv, _, _ = purego.SyscallN(m.fn(idxGetSlotList), 1,
		uintptr(unsafe.Pointer(&slots[0])), uintptr(unsafe.Pointer(&count)))
	if CKRV(rv) != CKR_OK {
		return nil, fmt.Errorf("C_GetSlotList: %s", CKRV(rv))
	}
	return slots[:count], nil
}

// tokenLabel reads the space-trimmed CKA label from a slot's CK_TOKEN_INFO.
func (m *Module) tokenLabel(slot uintptr) (string, error) {
	var info [256]byte
	rv, _, _ := purego.SyscallN(m.fn(idxGetTokenInfo), slot, uintptr(unsafe.Pointer(&info[0])))
	if CKRV(rv) != CKR_OK {
		return "", fmt.Errorf("C_GetTokenInfo: %s", CKRV(rv))
	}
	return string(bytes.TrimRight(info[:32], " ")), nil
}

// listRSAKeysOnToken enumerates RSA private- then public-key objects on the
// session's token, returning one KeyInfo per distinct CKA_ID.
func (s *Session) listRSAKeysOnToken(tokenLabel string) []KeyInfo {
	seen := map[string]bool{}
	var out []KeyInfo
	for _, class := range []uintptr{CKO_PRIVATE_KEY, CKO_PUBLIC_KEY} {
		objs, err := s.findRSAObjects(class)
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

// findRSAObjects returns all handles of RSA objects of the given class.
func (s *Session) findRSAObjects(class uintptr) ([]Object, error) {
	keyType := CKK_RSA
	attrs := []CK_ATTRIBUTE{
		{Type: CKA_CLASS, Value: unsafe.Pointer(&class), Len: unsafe.Sizeof(class)},
		{Type: CKA_KEY_TYPE, Value: unsafe.Pointer(&keyType), Len: unsafe.Sizeof(keyType)},
	}
	rv, _, _ := purego.SyscallN(s.m.fn(idxFindObjectsInit), s.handle,
		uintptr(unsafe.Pointer(&attrs[0])), uintptr(len(attrs)))
	runtime.KeepAlive(attrs)
	if CKRV(rv) != CKR_OK {
		return nil, fmt.Errorf("C_FindObjectsInit: %s", CKRV(rv))
	}

	const batch = 32
	var out []Object
	for {
		objs := make([]uintptr, batch)
		var found uintptr
		rv, _, _ = purego.SyscallN(s.m.fn(idxFindObjects), s.handle,
			uintptr(unsafe.Pointer(&objs[0])), uintptr(batch), uintptr(unsafe.Pointer(&found)))
		if CKRV(rv) != CKR_OK {
			_, _, _ = purego.SyscallN(s.m.fn(idxFindObjectsFinal), s.handle)
			return nil, fmt.Errorf("C_FindObjects: %s", CKRV(rv))
		}
		if found == 0 {
			break
		}
		out = append(out, objs[:found]...)
		if found < batch {
			break
		}
	}
	rvF, _, _ := purego.SyscallN(s.m.fn(idxFindObjectsFinal), s.handle)
	if CKRV(rvF) != CKR_OK {
		return nil, fmt.Errorf("C_FindObjectsFinal: %s", CKRV(rvF))
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
