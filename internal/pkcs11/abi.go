package pkcs11

// This file defines the platform-neutral PKCS#11 ABI helpers that every call
// site in this package funnels through. The Cryptoki ABI differs between the
// two platform families nvolt targets:
//
//   - Unix (Linux, macOS) uses the LP64 model: CK_ULONG is 8 bytes and the
//     Cryptoki structs are naturally aligned (the reference pkcs11.h has no
//     #pragma pack). So CK_ATTRIBUTE is 24 bytes, CK_MECHANISM 24 bytes and
//     CK_RSA_PKCS_OAEP_PARAMS 40 bytes, and handles/counts/flags are 8 bytes.
//     Go structs can express this layout exactly, so the unix path keeps using
//     the real Go structs (CK_ATTRIBUTE / CK_MECHANISM / ckOAEPParams).
//
//   - Windows uses the LLP64 model: `long` (hence CK_ULONG) is 4 bytes, and
//     the Windows Cryptoki headers wrap the structs in #pragma pack(1) (no
//     padding). A Go struct CANNOT express this — a uint32 field before an
//     8-byte pointer is re-padded to 8-byte alignment by the Go compiler — so
//     the Windows path hand-marshals these structs into []byte buffers with
//     the exact packed offsets (see abipack.go).
//
// The size of CK_ULONG (ckULongSize) and the return-value mask (maskRV) are
// the two primitives that vary; they are defined per platform in abi_unix.go
// and abi_windows.go. Everything here is written in terms of them.

import (
	"encoding/binary"
	"unsafe"
)

// attr is a platform-neutral CK_ATTRIBUTE template entry: an attribute type and
// its value as raw bytes already at the token's expected width. Callers build
// CK_ULONG-typed values (CKA_CLASS, CKA_KEY_TYPE, CKA_MODULUS_BITS, ...) with
// encodeCKULong so they are 8 bytes on unix and 4 bytes on Windows; byte-string
// values (CKA_ID, CKA_LABEL, CKA_PUBLIC_EXPONENT, ...) are passed as-is. A nil
// val is the zero-length "query" form used by C_GetAttributeValue's first call.
type attr struct {
	typ uintptr
	val []byte
}

// encodeCKULong encodes v as a CK_ULONG in the platform's width (little-endian;
// every platform nvolt targets — amd64/arm64 — is little-endian). Used for both
// CK_ULONG attribute VALUES and any standalone CK_ULONG we hand to the token.
func encodeCKULong(v uintptr) []byte {
	b := make([]byte, ckULongSize)
	putCKULong(b, v)
	return b
}

// putCKULong writes v as a CK_ULONG (platform width) at the start of b.
func putCKULong(b []byte, v uintptr) {
	if ckULongSize == 4 {
		binary.LittleEndian.PutUint32(b, uint32(v))
		return
	}
	binary.LittleEndian.PutUint64(b, uint64(v))
}

// getCKULong reads a CK_ULONG (platform width) from the start of b.
func getCKULong(b []byte) uintptr {
	if ckULongSize == 4 {
		return uintptr(binary.LittleEndian.Uint32(b))
	}
	return uintptr(binary.LittleEndian.Uint64(b))
}

// rvOf normalizes a raw SyscallN return into a CKRV. C_* functions return a
// CK_RV, which is a CK_ULONG: 4 bytes on Windows. purego.SyscallN yields the
// full 64-bit register, whose upper 32 bits are unspecified for a 32-bit C
// return, so maskRV drops them on Windows (identity on unix) before comparison
// with the CKR_* constants.
func rvOf(rv uintptr) CKRV { return CKRV(maskRV(rv)) }

// ckULongOut is a buffer sized to receive exactly one CK_ULONG-width value
// (a handle, session id, slot count, object count, ...) written back by a C_*
// call, read at the platform width. A plain Go `var x uintptr` is WRONG on
// Windows: the token writes only its low 4 bytes, leaving the upper 4 bytes of
// the 8-byte Go word uninitialized garbage.
type ckULongOut struct{ b []byte }

func newCKULongOut() *ckULongOut { return &ckULongOut{b: make([]byte, ckULongSize)} }

func (o *ckULongOut) ptr() unsafe.Pointer { return unsafe.Pointer(&o.b[0]) }
func (o *ckULongOut) get() uintptr        { return getCKULong(o.b) }

// ckULongArr is an array buffer that receives n CK_ULONG-width values (e.g. the
// slot-id array from C_GetSlotList or the object-handle array from
// C_FindObjects). Stride is the platform CK_ULONG width, not Go's 8-byte
// uintptr, so a []uintptr would mis-stride on Windows.
type ckULongArr struct {
	b []byte
	n int
}

func newCKULongArr(n int) *ckULongArr { return &ckULongArr{b: make([]byte, n*ckULongSize), n: n} }

func (a *ckULongArr) ptr() unsafe.Pointer { return unsafe.Pointer(&a.b[0]) }
func (a *ckULongArr) get(i int) uintptr   { return getCKULong(a.b[i*ckULongSize:]) }
