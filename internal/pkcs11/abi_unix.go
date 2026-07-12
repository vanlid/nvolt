//go:build pkcs11 && !windows

package pkcs11

import "unsafe"

// Unix (Linux, macOS) is LP64 with naturally-aligned Cryptoki structs, so
// CK_ULONG is 8 bytes. maskRV is the identity: the full 64-bit CK_RV register
// is already the value.
const ckULongSize = 8

func maskRV(rv uintptr) uintptr { return rv }

// ckTemplate is a marshaled CK_ATTRIBUTE array. On unix it wraps the real
// []CK_ATTRIBUTE Go struct so the layout, and the GC's scanning of the
// unsafe.Pointer Value fields (which keeps the pointed-to value bytes alive
// and correct across a stack move), are exactly as they were before this
// abstraction was introduced — the LP64 behavior is unchanged.
type ckTemplate struct {
	arr  []CK_ATTRIBUTE
	vals [][]byte // keep-alive anchors for the value byte slices
}

// packTemplate builds a CK_ATTRIBUTE array from attrs. A nil val is the
// zero-length query form (Value=nil, Len=0). The packed flag exists only to
// match the Windows signature (see abi_windows.go); unix uses a real Go struct
// whose layout the compiler fixes, so alignment is not a runtime choice here.
func packTemplate(attrs []attr, _ bool) *ckTemplate {
	t := &ckTemplate{arr: make([]CK_ATTRIBUTE, len(attrs))}
	for i, a := range attrs {
		t.arr[i].Type = a.typ
		if len(a.val) == 0 {
			continue
		}
		v := a.val
		t.vals = append(t.vals, v)
		t.arr[i].Value = unsafe.Pointer(&v[0])
		t.arr[i].Len = uintptr(len(v))
	}
	return t
}

func (t *ckTemplate) ptr() unsafe.Pointer { return unsafe.Pointer(&t.arr[0]) }
func (t *ckTemplate) count() uintptr      { return uintptr(len(t.arr)) }
func (t *ckTemplate) valueLen(i int) uintptr {
	return t.arr[i].Len
}

// setValue points entry i's pValue at p and sets its ulValueLen to n. Used by
// the two-call C_GetAttributeValue pattern for the second (fetch) call.
func (t *ckTemplate) setValue(i int, p unsafe.Pointer, n uintptr) {
	t.arr[i].Value = p
	t.arr[i].Len = n
}

// ckMech is a marshaled CK_MECHANISM. On unix it wraps the real Go structs;
// keeping the ckMech alive keeps m (and, via its scanned Param field, the OAEP
// params) alive across the syscall.
type ckMech struct {
	m    CK_MECHANISM
	oaep *ckOAEPParams
}

// packMechanismSimple builds a CK_MECHANISM with no parameter (e.g.
// CKM_RSA_X_509, CKM_RSA_PKCS_KEY_PAIR_GEN). The packed flag is ignored on unix
// (see packTemplate); it exists only to match the Windows signature.
func packMechanismSimple(mechanism uintptr, _ bool) *ckMech {
	return &ckMech{m: CK_MECHANISM{Mechanism: mechanism}}
}

// packMechanismOAEP builds a CK_MECHANISM whose parameter is a
// CK_RSA_PKCS_OAEP_PARAMS (CKZ_DATA_SPECIFIED style; no source data). The packed
// flag is ignored on unix (see packTemplate).
func packMechanismOAEP(mechanism, hashAlg, mgf, source uintptr, _ bool) *ckMech {
	p := &ckOAEPParams{HashAlg: hashAlg, Mgf: mgf, SourceType: source}
	return &ckMech{
		m:    CK_MECHANISM{Mechanism: mechanism, Param: unsafe.Pointer(p), ParamLen: unsafe.Sizeof(*p)},
		oaep: p,
	}
}

func (c *ckMech) ptr() unsafe.Pointer { return unsafe.Pointer(&c.m) }

// The unix (LP64, naturally-aligned) Cryptoki structs. Only the unix ABI path
// uses the real Go structs; the Windows path hand-marshals into []byte (see
// abipack.go), so these live here under `pkcs11 && !windows` rather than in the
// untagged types.go.

// CK_ATTRIBUTE mirrors the Cryptoki attribute template entry.
type CK_ATTRIBUTE struct {
	Type  uintptr
	Value unsafe.Pointer
	Len   uintptr
}

// CK_MECHANISM mirrors the Cryptoki mechanism struct.
type CK_MECHANISM struct {
	Mechanism uintptr
	Param     unsafe.Pointer
	ParamLen  uintptr
}

// ckOAEPParams is CK_RSA_PKCS_OAEP_PARAMS for CKM_RSA_PKCS_OAEP.
type ckOAEPParams struct {
	HashAlg    uintptr
	Mgf        uintptr
	SourceType uintptr
	SourceData unsafe.Pointer
	SourceLen  uintptr
}
