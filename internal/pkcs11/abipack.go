//go:build pkcs11

package pkcs11

// Windows (LLP64) struct marshaling. These functions carry no OS constraint
// (only the pkcs11 tag) so they can be unit-tested on any host via
// `go test -tags pkcs11` (see abipack_test.go); abi_windows.go wires them into
// the platform helpers, and nothing on unix calls them at runtime.
//
// Two Windows ABIs are supported, selected per-module by the `packed` argument:
//
//   - packed==true  → #pragma pack(1): no padding. This is what the Windows
//     Cryptoki reference headers (and OpenSC) use: CK_MECHANISM/CK_ATTRIBUTE
//     are 16 bytes with the 8-byte pointer at offset 4.
//   - packed==false → natural alignment: some modules (notably wolfPKCS11, whose
//     headers carry no #pragma pack) leave the structs naturally aligned, so on
//     LLP64 the 8-byte pointer sits at offset 8 (4 bytes of padding after the
//     leading 4-byte CK_ULONG) and the structs are larger. Marshaling pack(1)
//     bytes to such a module makes it read pParameter/ulParameterLen past the end
//     of the buffer and fail with CKR_MECHANISM_PARAM_INVALID.
//
// The alignment is derived from Module.headerOffset (2 for pack(1), 8 for
// natural), which detectHeaderOffset already measures per module; mechPacked
// maps it to the boolean threaded through here.
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

// mechPacked maps a module's detected CK_FUNCTION_LIST header offset to the
// struct-packing convention its Cryptoki headers were compiled with. Offset 2
// means #pragma pack(1) (packed); offset 8 means natural alignment. The same
// packing governs every CK_* struct nvolt marshals (mechanism, attribute,
// OAEP params), so this single predicate is threaded through all of them.
func mechPacked(headerOffset int) bool { return headerOffset == 2 }

// Windows CK_ATTRIBUTE (LLP64). pack(1): 16 bytes, pValue @4. natural: 24 bytes,
// pValue @8 (4 bytes of padding after the leading CK_ULONG). type is @0 either
// way.
//
//	pack(1):  type@0 (u32), pValue@4  (ptr8), ulValueLen@12 (u32)   size 16
//	natural:  type@0 (u32), pValue@8  (ptr8), ulValueLen@16 (u32)   size 24
const (
	winAttrSize     = 16
	winAttrTypeOff  = 0
	winAttrValueOff = 4
	winAttrLenOff   = 12

	natAttrSize     = 24
	natAttrValueOff = 8
	natAttrLenOff   = 16
)

// attrLayout returns the CK_ATTRIBUTE element size and the byte offsets of its
// pValue and ulValueLen fields for the selected ABI. type is always at offset 0.
func attrLayout(packed bool) (elemSize, valueOff, lenOff int) {
	if packed {
		return winAttrSize, winAttrValueOff, winAttrLenOff
	}
	return natAttrSize, natAttrValueOff, natAttrLenOff
}

// packAttrsWindows marshals attrs into a Windows-ABI CK_ATTRIBUTE array (element
// size per attrLayout, no inter-element padding). Attribute values are copied
// into a storage region appended after the array, and each element's pValue
// points into that region. A nil val encodes pValue=NULL / ulValueLen=0
// (C_GetAttributeValue's first, length-query call).
func packAttrsWindows(attrs []attr, packed bool) []byte {
	elemSize, valueOff, lenOff := attrLayout(packed)
	header := elemSize * len(attrs)
	total := header
	for _, a := range attrs {
		total += len(a.val)
	}
	buf := make([]byte, total)
	off := header
	for i, a := range attrs {
		base := i * elemSize
		binary.LittleEndian.PutUint32(buf[base+winAttrTypeOff:], uint32(a.typ))
		if len(a.val) == 0 {
			// pValue and ulValueLen stay zero (buf is zero-initialized).
			continue
		}
		copy(buf[off:], a.val)
		p := uint64(uintptr(unsafe.Pointer(&buf[off])))
		binary.LittleEndian.PutUint64(buf[base+valueOff:], p)
		binary.LittleEndian.PutUint32(buf[base+lenOff:], uint32(len(a.val)))
		off += len(a.val)
	}
	return buf
}

// Windows CK_MECHANISM (LLP64). pack(1): 16 bytes, pParameter @4. natural:
// 24 bytes, pParameter @8. mechanism is @0 either way.
//
//	pack(1):  mechanism@0 (u32), pParameter@4 (ptr8), ulParameterLen@12 (u32)  size 16
//	natural:  mechanism@0 (u32), pParameter@8 (ptr8), ulParameterLen@16 (u32)  size 24
const (
	winMechSize     = 16
	winMechTypeOff  = 0
	winMechParamOff = 4
	winMechLenOff   = 12

	natMechSize     = 24
	natMechParamOff = 8
	natMechLenOff   = 16
)

// mechLayout returns the CK_MECHANISM header size and the byte offsets of its
// pParameter and ulParameterLen fields for the selected ABI. mechanism is
// always at offset 0.
func mechLayout(packed bool) (size, paramOff, lenOff int) {
	if packed {
		return winMechSize, winMechParamOff, winMechLenOff
	}
	return natMechSize, natMechParamOff, natMechLenOff
}

// packMechWindows marshals a Windows-ABI CK_MECHANISM. When param is non-nil it
// is copied into the buffer after the header and pParameter points at it;
// otherwise pParameter is NULL and ulParameterLen is 0.
func packMechWindows(mechanism uintptr, param []byte, packed bool) []byte {
	size, paramOff, lenOff := mechLayout(packed)
	buf := make([]byte, size+len(param))
	binary.LittleEndian.PutUint32(buf[winMechTypeOff:], uint32(mechanism))
	if len(param) > 0 {
		copy(buf[size:], param)
		p := uint64(uintptr(unsafe.Pointer(&buf[size])))
		binary.LittleEndian.PutUint64(buf[paramOff:], p)
		binary.LittleEndian.PutUint32(buf[lenOff:], uint32(len(param)))
	}
	return buf
}

// Windows CK_RSA_PKCS_OAEP_PARAMS (LLP64). The three leading CK_ULONG-width
// fields (hashAlg@0, mgf@4, source@8) are identical in both ABIs; only the
// trailing pSourceData pointer moves (from @12 to @16, after 4 bytes of natural
// padding) and the total size grows (24 → 32). nvolt never supplies OAEP source
// (label) data, so pSourceData is always NULL and ulSourceDataLen 0 — but the
// total size still differs, which is what the enclosing CK_MECHANISM's
// ulParameterLen and the module's read of the struct depend on.
//
//	pack(1):  hashAlg@0, mgf@4, source@8, pSourceData@12 (ptr8, NULL), ulSourceDataLen@20  size 24
//	natural:  hashAlg@0, mgf@4, source@8, pSourceData@16 (ptr8, NULL), ulSourceDataLen@24  size 32
const (
	winOAEPSize      = 24
	winOAEPHashOff   = 0
	winOAEPMgfOff    = 4
	winOAEPSourceOff = 8

	natOAEPSize = 32
)

// oaepSize returns the CK_RSA_PKCS_OAEP_PARAMS size for the selected ABI.
func oaepSize(packed bool) int {
	if packed {
		return winOAEPSize
	}
	return natOAEPSize
}

// packOAEPWindows marshals a Windows-ABI CK_RSA_PKCS_OAEP_PARAMS with no source
// data (pSourceData=NULL, ulSourceDataLen=0). The pSourceData/ulSourceDataLen
// tail stays zero, so only the total size varies between ABIs.
func packOAEPWindows(hashAlg, mgf, source uintptr, packed bool) []byte {
	buf := make([]byte, oaepSize(packed))
	binary.LittleEndian.PutUint32(buf[winOAEPHashOff:], uint32(hashAlg))
	binary.LittleEndian.PutUint32(buf[winOAEPMgfOff:], uint32(mgf))
	binary.LittleEndian.PutUint32(buf[winOAEPSourceOff:], uint32(source))
	// pSourceData and ulSourceDataLen stay zero in both ABIs.
	return buf
}
