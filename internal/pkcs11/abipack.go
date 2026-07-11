package pkcs11

// Windows (LLP64 + #pragma pack(1)) struct marshaling. These functions are
// deliberately NOT build-tagged so they can be unit-tested on any host (see
// abipack_test.go); abi_windows.go wires them into the platform helpers, and
// nothing on unix calls them at runtime.
//
// Every function returns a self-contained []byte: any pointer field that must
// point at data (an attribute value, a mechanism parameter) is stored in a
// storage area appended to the SAME buffer, and the pointer is written to point
// into that area. Go never relocates heap allocations, so as long as the
// returned slice is kept alive across the syscall (runtime.KeepAlive), every
// interior pointer stays valid. This is why the buffer, not the individual
// values, is the single keep-alive anchor on Windows.

import (
	"encoding/binary"
	"unsafe"
)

// Windows CK_ATTRIBUTE (pack(1), LLP64): 16 bytes total.
//
//	offset 0  type        CK_ATTRIBUTE_TYPE (CK_ULONG) — 4 bytes
//	offset 4  pValue      CK_VOID_PTR                   — 8 bytes
//	offset 12 ulValueLen  CK_ULONG                      — 4 bytes
const (
	winAttrSize     = 16
	winAttrTypeOff  = 0
	winAttrValueOff = 4
	winAttrLenOff   = 12
)

// packAttrsWindows marshals attrs into a Windows-ABI CK_ATTRIBUTE array. Each
// element is 16 bytes with no inter-element padding. Attribute values are
// copied into a storage region appended after the array, and each element's
// pValue points into that region. A nil val encodes pValue=NULL / ulValueLen=0
// (C_GetAttributeValue's first, length-query call).
func packAttrsWindows(attrs []attr) []byte {
	header := winAttrSize * len(attrs)
	total := header
	for _, a := range attrs {
		total += len(a.val)
	}
	buf := make([]byte, total)
	off := header
	for i, a := range attrs {
		base := i * winAttrSize
		binary.LittleEndian.PutUint32(buf[base+winAttrTypeOff:], uint32(a.typ))
		if len(a.val) == 0 {
			// pValue and ulValueLen stay zero (buf is zero-initialized).
			continue
		}
		copy(buf[off:], a.val)
		p := uint64(uintptr(unsafe.Pointer(&buf[off])))
		binary.LittleEndian.PutUint64(buf[base+winAttrValueOff:], p)
		binary.LittleEndian.PutUint32(buf[base+winAttrLenOff:], uint32(len(a.val)))
		off += len(a.val)
	}
	return buf
}

// Windows CK_MECHANISM (pack(1), LLP64): 16 bytes total.
//
//	offset 0  mechanism       CK_MECHANISM_TYPE (CK_ULONG) — 4 bytes
//	offset 4  pParameter      CK_VOID_PTR                   — 8 bytes
//	offset 12 ulParameterLen  CK_ULONG                      — 4 bytes
const (
	winMechSize     = 16
	winMechTypeOff  = 0
	winMechParamOff = 4
	winMechLenOff   = 12
)

// packMechWindows marshals a Windows-ABI CK_MECHANISM. When param is non-nil it
// is copied into the buffer after the 16-byte header and pParameter points at
// it; otherwise pParameter is NULL and ulParameterLen is 0.
func packMechWindows(mechanism uintptr, param []byte) []byte {
	buf := make([]byte, winMechSize+len(param))
	binary.LittleEndian.PutUint32(buf[winMechTypeOff:], uint32(mechanism))
	if len(param) > 0 {
		copy(buf[winMechSize:], param)
		p := uint64(uintptr(unsafe.Pointer(&buf[winMechSize])))
		binary.LittleEndian.PutUint64(buf[winMechParamOff:], p)
		binary.LittleEndian.PutUint32(buf[winMechLenOff:], uint32(len(param)))
	}
	return buf
}

// Windows CK_RSA_PKCS_OAEP_PARAMS (pack(1), LLP64): 24 bytes total.
//
//	offset 0  hashAlg          CK_MECHANISM_TYPE (CK_ULONG) — 4 bytes
//	offset 4  mgf              CK_RSA_PKCS_MGF_TYPE          — 4 bytes
//	offset 8  source           CK_RSA_PKCS_OAEP_SOURCE_TYPE — 4 bytes
//	offset 12 pSourceData      CK_VOID_PTR                   — 8 bytes (NULL)
//	offset 20 ulSourceDataLen  CK_ULONG                      — 4 bytes (0)
//
// nvolt never supplies OAEP source (label) data, so pSourceData is always NULL
// and ulSourceDataLen 0.
const (
	winOAEPSize       = 24
	winOAEPHashOff    = 0
	winOAEPMgfOff     = 4
	winOAEPSourceOff  = 8
	winOAEPSrcDataOff = 12
	winOAEPSrcLenOff  = 20
)

// packOAEPWindows marshals a Windows-ABI CK_RSA_PKCS_OAEP_PARAMS with no source
// data (pSourceData=NULL, ulSourceDataLen=0).
func packOAEPWindows(hashAlg, mgf, source uintptr) []byte {
	buf := make([]byte, winOAEPSize)
	binary.LittleEndian.PutUint32(buf[winOAEPHashOff:], uint32(hashAlg))
	binary.LittleEndian.PutUint32(buf[winOAEPMgfOff:], uint32(mgf))
	binary.LittleEndian.PutUint32(buf[winOAEPSourceOff:], uint32(source))
	// pSourceData @12 (8 bytes) and ulSourceDataLen @20 (4 bytes) stay zero.
	return buf
}
