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

// ckTemplate is a marshaled CK_ATTRIBUTE array in the Windows (LLP64) ABI,
// values stored in the same buffer (see packAttrsWindows). The `packed` flag
// selects the element layout (pack(1) 16-byte vs natural 24-byte) so the
// getters/setters index at matching offsets. The single []byte is the
// keep-alive anchor for the whole template — the value bytes live inside it and
// heap allocations never move.
type ckTemplate struct {
	buf    []byte
	n      int
	packed bool
}

func packTemplate(attrs []attr, packed bool) *ckTemplate {
	return &ckTemplate{buf: packAttrsWindows(attrs, packed), n: len(attrs), packed: packed}
}

func (t *ckTemplate) ptr() unsafe.Pointer { return unsafe.Pointer(&t.buf[0]) }
func (t *ckTemplate) count() uintptr      { return uintptr(t.n) }

// valueLen reads entry i's ulValueLen (CK_ULONG, 4 bytes) at the ABI's element
// stride/offset. Used after C_GetAttributeValue writes back the value size /
// actual length.
func (t *ckTemplate) valueLen(i int) uintptr {
	elemSize, _, lenOff := attrLayout(t.packed)
	return uintptr(binary.LittleEndian.Uint32(t.buf[i*elemSize+lenOff:]))
}

// setValue points entry i's pValue (8 bytes) at p and sets its ulValueLen
// (4 bytes) to n, at the ABI's element stride/offsets, for
// C_GetAttributeValue's fetch call.
func (t *ckTemplate) setValue(i int, p unsafe.Pointer, n uintptr) {
	elemSize, valueOff, lenOff := attrLayout(t.packed)
	binary.LittleEndian.PutUint64(t.buf[i*elemSize+valueOff:], uint64(uintptr(p)))
	binary.LittleEndian.PutUint32(t.buf[i*elemSize+lenOff:], uint32(n))
}

// ckMech is a marshaled CK_MECHANISM (pack(1) or natural per the module; any
// parameter stored in the same buffer). The []byte is the sole keep-alive
// anchor.
type ckMech struct {
	buf []byte
}

func packMechanismSimple(mechanism uintptr, packed bool) *ckMech {
	return &ckMech{buf: packMechWindows(mechanism, nil, packed)}
}

func packMechanismOAEP(mechanism, hashAlg, mgf, source uintptr, packed bool) *ckMech {
	return &ckMech{buf: packMechWindows(mechanism, packOAEPWindows(hashAlg, mgf, source, packed), packed)}
}

func (c *ckMech) ptr() unsafe.Pointer { return unsafe.Pointer(&c.buf[0]) }
