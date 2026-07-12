//go:build pkcs11

package pkcs11

import (
	"testing"
	"unsafe"
)

// fakeFnList8 lays out a CK_FUNCTION_LIST at natural alignment: a 2-byte
// CK_VERSION plus 6 bytes padding puts the function-pointer array at offset 8,
// matching how ordinary Linux/macOS modules are compiled.
type fakeFnList8 struct {
	header [8]byte
	fns    [80]uintptr
}

// canonical stand-in "function addresses" (non-nil, below 2^48).
const (
	fakeInit = 0x0000000000401000
	fakeFin  = 0x0000000000402000
	fakeGFL  = 0x0000000000404000
)

func newFakeFnList8() *fakeFnList8 {
	l := &fakeFnList8{}
	l.fns[idxInitialize] = fakeInit
	l.fns[idxFinalize] = fakeFin
	l.fns[idxGetFunctionList] = fakeGFL
	return l
}

// TestDetectHeaderOffsetExactMatch asserts the fast path: when the list's own
// C_GetFunctionList entry equals the exported symbol (an ordinary module), the
// offset resolves directly.
func TestDetectHeaderOffsetExactMatch(t *testing.T) {
	l := newFakeFnList8()
	off, err := detectHeaderOffset(unsafe.Pointer(l), uintptr(fakeGFL))
	if err != nil || off != 8 {
		t.Fatalf("exact match: got off=%d err=%v, want 8, nil", off, err)
	}
}

// TestDetectHeaderOffsetProxyFallback asserts the proxy path: a wrapping proxy
// (p11-kit) puts its INTERNAL C_GetFunctionList in the list, so it never equals
// the exported symbol. The offset must still resolve via the sane-table check
// rather than erroring.
func TestDetectHeaderOffsetProxyFallback(t *testing.T) {
	l := newFakeFnList8()                           // in-list C_GetFunctionList = fakeGFL
	proxyExportedSym := uintptr(0x00000000004F0000) // != fakeGFL, but canonical
	off, err := detectHeaderOffset(unsafe.Pointer(l), proxyExportedSym)
	if err != nil || off != 8 {
		t.Fatalf("proxy fallback: got off=%d err=%v, want 8, nil", off, err)
	}
}

// TestDetectHeaderOffsetRejectsGarbage asserts a list with no sane offset (no
// canonical mandatory pointers at either candidate) is rejected rather than
// silently accepted.
func TestDetectHeaderOffsetRejectsGarbage(t *testing.T) {
	var l fakeFnList8 // all-zero: no canonical function pointers anywhere
	if _, err := detectHeaderOffset(unsafe.Pointer(&l), uintptr(fakeGFL)); err == nil {
		t.Fatal("expected an error for a function list with no sane offset")
	}
}
