//go:build pkcs11 && windows

package pkcs11

import (
	"encoding/binary"
	"unsafe"
)

// Windows is LLP64: CK_ULONG (C `long`) is 4 bytes. A 32-bit C return leaves
// the upper 32 bits of the 64-bit syscall-return register unspecified, so
// maskRV keeps only the low 32 bits before the value is compared to CKR_*.
const ckULongSize = 4

func maskRV(rv uintptr) uintptr { return rv & 0xFFFFFFFF }

// ckTemplate is a marshaled CK_ATTRIBUTE array in the Windows (pack(1), LLP64)
// ABI: 16-byte elements, values stored in the same buffer (see packAttrsWindows).
// The single []byte is the keep-alive anchor for the whole template — the value
// bytes live inside it and heap allocations never move.
type ckTemplate struct {
	buf []byte
	n   int
}

func packTemplate(attrs []attr) *ckTemplate {
	return &ckTemplate{buf: packAttrsWindows(attrs), n: len(attrs)}
}

func (t *ckTemplate) ptr() unsafe.Pointer { return unsafe.Pointer(&t.buf[0]) }
func (t *ckTemplate) count() uintptr      { return uintptr(t.n) }

// valueLen reads entry i's ulValueLen (CK_ULONG, 4 bytes @ elem+12). Used after
// C_GetAttributeValue writes back the value size / actual length.
func (t *ckTemplate) valueLen(i int) uintptr {
	return uintptr(binary.LittleEndian.Uint32(t.buf[i*winAttrSize+winAttrLenOff:]))
}

// setValue points entry i's pValue (8 bytes @ elem+4) at p and sets its
// ulValueLen (4 bytes @ elem+12) to n, for C_GetAttributeValue's fetch call.
func (t *ckTemplate) setValue(i int, p unsafe.Pointer, n uintptr) {
	binary.LittleEndian.PutUint64(t.buf[i*winAttrSize+winAttrValueOff:], uint64(uintptr(p)))
	binary.LittleEndian.PutUint32(t.buf[i*winAttrSize+winAttrLenOff:], uint32(n))
}

// ckMech is a marshaled CK_MECHANISM (16-byte packed; any parameter stored in
// the same buffer). The []byte is the sole keep-alive anchor.
type ckMech struct {
	buf []byte
}

func packMechanismSimple(mechanism uintptr) *ckMech {
	return &ckMech{buf: packMechWindows(mechanism, nil)}
}

func packMechanismOAEP(mechanism, hashAlg, mgf, source uintptr) *ckMech {
	return &ckMech{buf: packMechWindows(mechanism, packOAEPWindows(hashAlg, mgf, source))}
}

func (c *ckMech) ptr() unsafe.Pointer { return unsafe.Pointer(&c.buf[0]) }
