//go:build pkcs11 && !windows

package pkcs11

import (
	"bytes"
	"encoding/binary"
	"testing"
	"unsafe"
)

// These tests exercise the pure Windows (LLP64) marshaling functions directly.
// They run on any host (including this Linux CI) because the packing functions
// are not build-tagged, which is the only way to get by-construction coverage of
// the Windows byte layout without a Windows runtime. Every offset asserted here
// is the documented Windows Cryptoki layout; a human can check the packed
// offsets against pkcs11t.h compiled with #pragma pack(1) on a 64-bit target,
// and the natural offsets against the same headers compiled with no #pragma pack
// (as wolfPKCS11 ships them), where the 8-byte pointer aligns to offset 8.
//
// The two ABIs are selected by the packed argument (true = pack(1), false =
// natural), which nvolt derives per module from the detected CK_FUNCTION_LIST
// header offset via mechPacked.

// TestPackAttrsWindowsLayout asserts the 16-byte packed CK_ATTRIBUTE element:
// type(u32)@0, pValue(ptr8)@4, ulValueLen(u32)@12, no inter-element padding,
// with attribute values copied into the same buffer after the array.
func TestPackAttrsWindowsLayout(t *testing.T) {
	// CKO_PRIVATE_KEY rendered as a 4-byte Windows CK_ULONG value.
	classVal := []byte{0x03, 0x00, 0x00, 0x00}
	id := []byte{0xAA, 0xBB}
	attrs := []attr{
		{typ: CKA_CLASS, val: classVal},
		{typ: CKA_ID, val: id},
		{typ: CKA_MODULUS, val: nil}, // query form (C_GetAttributeValue call 1)
	}
	buf := packAttrsWindows(attrs, true)

	const elem = 16
	header := elem * len(attrs) // 48
	wantLen := header + len(classVal) + len(id)
	if len(buf) != wantLen {
		t.Fatalf("buffer length = %d, want %d (48 header + 6 values)", len(buf), wantLen)
	}

	// Element 0: CKA_CLASS.
	if got := binary.LittleEndian.Uint32(buf[0:]); got != uint32(CKA_CLASS) {
		t.Errorf("elem0 type @0 = 0x%x, want 0x%x", got, CKA_CLASS)
	}
	if got := binary.LittleEndian.Uint32(buf[12:]); got != 4 {
		t.Errorf("elem0 ulValueLen @12 = %d, want 4", got)
	}
	p0 := binary.LittleEndian.Uint64(buf[4:])
	if p0 != uint64(uintptr(unsafe.Pointer(&buf[header]))) {
		t.Errorf("elem0 pValue @4 = 0x%x, want &buf[%d]=0x%x", p0, header, uintptr(unsafe.Pointer(&buf[header])))
	}
	if !bytes.Equal(buf[header:header+4], classVal) {
		t.Errorf("elem0 value bytes = % x, want % x", buf[header:header+4], classVal)
	}

	// Element 1: CKA_ID at offset 16, its value stored right after class value.
	base1 := elem
	if got := binary.LittleEndian.Uint32(buf[base1:]); got != uint32(CKA_ID) {
		t.Errorf("elem1 type @16 = 0x%x, want 0x%x", got, CKA_ID)
	}
	if got := binary.LittleEndian.Uint32(buf[base1+12:]); got != 2 {
		t.Errorf("elem1 ulValueLen @28 = %d, want 2", got)
	}
	p1 := binary.LittleEndian.Uint64(buf[base1+4:])
	if p1 != uint64(uintptr(unsafe.Pointer(&buf[header+4]))) {
		t.Errorf("elem1 pValue = 0x%x, want &buf[%d]", p1, header+4)
	}
	if !bytes.Equal(buf[header+4:header+6], id) {
		t.Errorf("elem1 value bytes = % x, want % x", buf[header+4:header+6], id)
	}

	// Element 2: query form — type set, pValue NULL, ulValueLen 0.
	base2 := 2 * elem
	if got := binary.LittleEndian.Uint32(buf[base2:]); got != uint32(CKA_MODULUS) {
		t.Errorf("elem2 type @32 = 0x%x, want 0x%x", got, CKA_MODULUS)
	}
	if got := binary.LittleEndian.Uint64(buf[base2+4:]); got != 0 {
		t.Errorf("elem2 pValue = 0x%x, want 0 (NULL query)", got)
	}
	if got := binary.LittleEndian.Uint32(buf[base2+12:]); got != 0 {
		t.Errorf("elem2 ulValueLen = %d, want 0", got)
	}
}

// TestPackOAEPWindowsLayout asserts the 24-byte packed CK_RSA_PKCS_OAEP_PARAMS:
// hashAlg@0, mgf@4, source@8 (all u32), pSourceData(ptr8)@12=NULL,
// ulSourceDataLen(u32)@20=0.
func TestPackOAEPWindowsLayout(t *testing.T) {
	buf := packOAEPWindows(CKM_SHA256, CKG_MGF1_SHA256, CKZ_DATA_SPECIFIED, true)
	if len(buf) != 24 {
		t.Fatalf("OAEP params length = %d, want 24", len(buf))
	}
	if got := binary.LittleEndian.Uint32(buf[0:]); got != uint32(CKM_SHA256) {
		t.Errorf("hashAlg @0 = 0x%x, want 0x%x", got, CKM_SHA256)
	}
	if got := binary.LittleEndian.Uint32(buf[4:]); got != uint32(CKG_MGF1_SHA256) {
		t.Errorf("mgf @4 = 0x%x, want 0x%x", got, CKG_MGF1_SHA256)
	}
	if got := binary.LittleEndian.Uint32(buf[8:]); got != uint32(CKZ_DATA_SPECIFIED) {
		t.Errorf("source @8 = 0x%x, want 0x%x", got, CKZ_DATA_SPECIFIED)
	}
	if got := binary.LittleEndian.Uint64(buf[12:]); got != 0 {
		t.Errorf("pSourceData @12 = 0x%x, want 0 (NULL)", got)
	}
	if got := binary.LittleEndian.Uint32(buf[20:]); got != 0 {
		t.Errorf("ulSourceDataLen @20 = %d, want 0", got)
	}
}

// TestPackMechWindowsLayout asserts the 16-byte packed CK_MECHANISM:
// mechanism(u32)@0, pParameter(ptr8)@4, ulParameterLen(u32)@12, with any
// parameter copied into the same buffer.
func TestPackMechWindowsLayout(t *testing.T) {
	// With parameter (OAEP).
	param := packOAEPWindows(CKM_SHA256, CKG_MGF1_SHA256, CKZ_DATA_SPECIFIED, true)
	buf := packMechWindows(CKM_RSA_PKCS_OAEP, param, true)
	if len(buf) != 16+len(param) {
		t.Fatalf("mech length = %d, want %d", len(buf), 16+len(param))
	}
	if got := binary.LittleEndian.Uint32(buf[0:]); got != uint32(CKM_RSA_PKCS_OAEP) {
		t.Errorf("mechanism @0 = 0x%x, want 0x%x", got, CKM_RSA_PKCS_OAEP)
	}
	if got := binary.LittleEndian.Uint32(buf[12:]); got != uint32(len(param)) {
		t.Errorf("ulParameterLen @12 = %d, want %d", got, len(param))
	}
	pParam := binary.LittleEndian.Uint64(buf[4:])
	if pParam != uint64(uintptr(unsafe.Pointer(&buf[16]))) {
		t.Errorf("pParameter @4 = 0x%x, want &buf[16]", pParam)
	}
	if !bytes.Equal(buf[16:16+len(param)], param) {
		t.Errorf("copied parameter bytes mismatch")
	}

	// Without parameter (raw RSA / key-pair gen): NULL pParameter, len 0.
	buf2 := packMechWindows(CKM_RSA_X_509, nil, true)
	if len(buf2) != 16 {
		t.Fatalf("no-param mech length = %d, want 16", len(buf2))
	}
	if got := binary.LittleEndian.Uint32(buf2[0:]); got != uint32(CKM_RSA_X_509) {
		t.Errorf("mechanism @0 = 0x%x, want 0x%x", got, CKM_RSA_X_509)
	}
	if got := binary.LittleEndian.Uint64(buf2[4:]); got != 0 {
		t.Errorf("pParameter @4 = 0x%x, want 0 (NULL)", got)
	}
	if got := binary.LittleEndian.Uint32(buf2[12:]); got != 0 {
		t.Errorf("ulParameterLen @12 = %d, want 0", got)
	}
}

// TestMechPacked asserts the header-offset → packing mapping: offset 2 is
// #pragma pack(1) (packed), offset 8 is natural alignment.
func TestMechPacked(t *testing.T) {
	if !mechPacked(2) {
		t.Errorf("mechPacked(2) = false, want true (pack(1))")
	}
	if mechPacked(8) {
		t.Errorf("mechPacked(8) = true, want false (natural)")
	}
}

// TestPackAttrsWindowsNaturalLayout asserts the 24-byte naturally-aligned
// CK_ATTRIBUTE element: type(u32)@0, 4 pad bytes, pValue(ptr8)@8,
// ulValueLen(u32)@16, no inter-element padding beyond the struct's own tail,
// with attribute values copied into the same buffer after the array. This is
// the layout wolfPKCS11 (no #pragma pack) expects on 64-bit Windows.
func TestPackAttrsWindowsNaturalLayout(t *testing.T) {
	classVal := []byte{0x03, 0x00, 0x00, 0x00} // CKO_PRIVATE_KEY as 4-byte CK_ULONG
	id := []byte{0xAA, 0xBB}
	attrs := []attr{
		{typ: CKA_CLASS, val: classVal},
		{typ: CKA_ID, val: id},
		{typ: CKA_MODULUS, val: nil}, // query form
	}
	buf := packAttrsWindows(attrs, false)

	const elem = 24
	header := elem * len(attrs) // 72
	wantLen := header + len(classVal) + len(id)
	if len(buf) != wantLen {
		t.Fatalf("buffer length = %d, want %d (72 header + 6 values)", len(buf), wantLen)
	}

	// Element 0: CKA_CLASS — type@0, pValue@8, ulValueLen@16.
	if got := binary.LittleEndian.Uint32(buf[0:]); got != uint32(CKA_CLASS) {
		t.Errorf("elem0 type @0 = 0x%x, want 0x%x", got, CKA_CLASS)
	}
	// The 4 bytes of padding after type (offset 4..8) must be zero.
	if got := binary.LittleEndian.Uint32(buf[4:]); got != 0 {
		t.Errorf("elem0 pad @4 = 0x%x, want 0", got)
	}
	if got := binary.LittleEndian.Uint32(buf[16:]); got != 4 {
		t.Errorf("elem0 ulValueLen @16 = %d, want 4", got)
	}
	p0 := binary.LittleEndian.Uint64(buf[8:])
	if p0 != uint64(uintptr(unsafe.Pointer(&buf[header]))) {
		t.Errorf("elem0 pValue @8 = 0x%x, want &buf[%d]=0x%x", p0, header, uintptr(unsafe.Pointer(&buf[header])))
	}
	if !bytes.Equal(buf[header:header+4], classVal) {
		t.Errorf("elem0 value bytes = % x, want % x", buf[header:header+4], classVal)
	}

	// Element 1: CKA_ID at offset 24, its value stored right after class value.
	base1 := elem
	if got := binary.LittleEndian.Uint32(buf[base1:]); got != uint32(CKA_ID) {
		t.Errorf("elem1 type @24 = 0x%x, want 0x%x", got, CKA_ID)
	}
	if got := binary.LittleEndian.Uint32(buf[base1+16:]); got != 2 {
		t.Errorf("elem1 ulValueLen @40 = %d, want 2", got)
	}
	p1 := binary.LittleEndian.Uint64(buf[base1+8:])
	if p1 != uint64(uintptr(unsafe.Pointer(&buf[header+4]))) {
		t.Errorf("elem1 pValue @32 = 0x%x, want &buf[%d]", p1, header+4)
	}
	if !bytes.Equal(buf[header+4:header+6], id) {
		t.Errorf("elem1 value bytes = % x, want % x", buf[header+4:header+6], id)
	}

	// Element 2: query form — type set, pValue NULL @8, ulValueLen 0 @16.
	base2 := 2 * elem
	if got := binary.LittleEndian.Uint32(buf[base2:]); got != uint32(CKA_MODULUS) {
		t.Errorf("elem2 type @48 = 0x%x, want 0x%x", got, CKA_MODULUS)
	}
	if got := binary.LittleEndian.Uint64(buf[base2+8:]); got != 0 {
		t.Errorf("elem2 pValue @56 = 0x%x, want 0 (NULL query)", got)
	}
	if got := binary.LittleEndian.Uint32(buf[base2+16:]); got != 0 {
		t.Errorf("elem2 ulValueLen @64 = %d, want 0", got)
	}
}

// TestPackOAEPWindowsNaturalLayout asserts the 32-byte naturally-aligned
// CK_RSA_PKCS_OAEP_PARAMS: hashAlg@0, mgf@4, source@8 (all u32), 4 pad bytes,
// pSourceData(ptr8)@16=NULL, ulSourceDataLen(u32)@24=0.
func TestPackOAEPWindowsNaturalLayout(t *testing.T) {
	buf := packOAEPWindows(CKM_SHA256, CKG_MGF1_SHA256, CKZ_DATA_SPECIFIED, false)
	if len(buf) != 32 {
		t.Fatalf("OAEP params length = %d, want 32", len(buf))
	}
	if got := binary.LittleEndian.Uint32(buf[0:]); got != uint32(CKM_SHA256) {
		t.Errorf("hashAlg @0 = 0x%x, want 0x%x", got, CKM_SHA256)
	}
	if got := binary.LittleEndian.Uint32(buf[4:]); got != uint32(CKG_MGF1_SHA256) {
		t.Errorf("mgf @4 = 0x%x, want 0x%x", got, CKG_MGF1_SHA256)
	}
	if got := binary.LittleEndian.Uint32(buf[8:]); got != uint32(CKZ_DATA_SPECIFIED) {
		t.Errorf("source @8 = 0x%x, want 0x%x", got, CKZ_DATA_SPECIFIED)
	}
	// pad @12, pSourceData @16 (NULL), ulSourceDataLen @24 (0).
	if got := binary.LittleEndian.Uint32(buf[12:]); got != 0 {
		t.Errorf("pad @12 = 0x%x, want 0", got)
	}
	if got := binary.LittleEndian.Uint64(buf[16:]); got != 0 {
		t.Errorf("pSourceData @16 = 0x%x, want 0 (NULL)", got)
	}
	if got := binary.LittleEndian.Uint32(buf[24:]); got != 0 {
		t.Errorf("ulSourceDataLen @24 = %d, want 0", got)
	}
}

// TestPackMechWindowsNaturalLayout asserts the 24-byte naturally-aligned
// CK_MECHANISM: mechanism(u32)@0, 4 pad bytes, pParameter(ptr8)@8,
// ulParameterLen(u32)@16, with any parameter copied into the same buffer after
// the 24-byte header (and, for OAEP, the parameter itself in natural layout).
func TestPackMechWindowsNaturalLayout(t *testing.T) {
	// With parameter (OAEP), also naturally aligned → 32-byte param.
	param := packOAEPWindows(CKM_SHA256, CKG_MGF1_SHA256, CKZ_DATA_SPECIFIED, false)
	if len(param) != 32 {
		t.Fatalf("natural OAEP param length = %d, want 32", len(param))
	}
	buf := packMechWindows(CKM_RSA_PKCS_OAEP, param, false)
	if len(buf) != 24+len(param) {
		t.Fatalf("mech length = %d, want %d", len(buf), 24+len(param))
	}
	if got := binary.LittleEndian.Uint32(buf[0:]); got != uint32(CKM_RSA_PKCS_OAEP) {
		t.Errorf("mechanism @0 = 0x%x, want 0x%x", got, CKM_RSA_PKCS_OAEP)
	}
	if got := binary.LittleEndian.Uint32(buf[4:]); got != 0 {
		t.Errorf("pad @4 = 0x%x, want 0", got)
	}
	if got := binary.LittleEndian.Uint32(buf[16:]); got != uint32(len(param)) {
		t.Errorf("ulParameterLen @16 = %d, want %d", got, len(param))
	}
	pParam := binary.LittleEndian.Uint64(buf[8:])
	if pParam != uint64(uintptr(unsafe.Pointer(&buf[24]))) {
		t.Errorf("pParameter @8 = 0x%x, want &buf[24]", pParam)
	}
	if !bytes.Equal(buf[24:24+len(param)], param) {
		t.Errorf("copied parameter bytes mismatch")
	}

	// Without parameter (raw RSA / key-pair gen): NULL pParameter, len 0.
	buf2 := packMechWindows(CKM_RSA_X_509, nil, false)
	if len(buf2) != 24 {
		t.Fatalf("no-param mech length = %d, want 24", len(buf2))
	}
	if got := binary.LittleEndian.Uint32(buf2[0:]); got != uint32(CKM_RSA_X_509) {
		t.Errorf("mechanism @0 = 0x%x, want 0x%x", got, CKM_RSA_X_509)
	}
	if got := binary.LittleEndian.Uint64(buf2[8:]); got != 0 {
		t.Errorf("pParameter @8 = 0x%x, want 0 (NULL)", got)
	}
	if got := binary.LittleEndian.Uint32(buf2[16:]); got != 0 {
		t.Errorf("ulParameterLen @16 = %d, want 0", got)
	}
}

// TestCKULongRoundTrip checks the platform-width CK_ULONG encode/decode helpers
// on the current (LP64) host: 8 bytes, little-endian, value preserved.
func TestCKULongRoundTrip(t *testing.T) {
	if ckULongSize != 8 {
		t.Fatalf("ckULongSize = %d on this LP64 host, want 8", ckULongSize)
	}
	for _, v := range []uintptr{0, 1, 0x1234, 0xDEADBEEF, 0x0102030405060708} {
		b := encodeCKULong(v)
		if len(b) != 8 {
			t.Fatalf("encodeCKULong(%#x) len = %d, want 8", v, len(b))
		}
		if got := getCKULong(b); got != v {
			t.Errorf("getCKULong(encodeCKULong(%#x)) = %#x", v, got)
		}
	}
	// rvOf is the identity on unix (no high-bit masking).
	if got := rvOf(uintptr(CKR_OK)); got != CKR_OK {
		t.Errorf("rvOf(CKR_OK) = %v, want CKR_OK", got)
	}
}
