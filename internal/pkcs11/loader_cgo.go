//go:build wolfpkcs11_static

package pkcs11

// #include <wolfpkcs11/pkcs11.h>
import "C"

import (
	"fmt"
	"unsafe"
)

// Module is an opened PKCS#11 provider in the statically-linked build. Unlike
// the purego loader there is no dlopen handle: wolfPKCS11 is linked into the
// binary, so the only state is the function list resolved from the linked-in
// C_GetFunctionList and whether C_Initialize has been called.
type Module struct {
	// fnList is the raw CK_FUNCTION_LIST_PTR returned by C_GetFunctionList,
	// kept as unsafe.Pointer for parity with the purego loader's Module.
	fnList unsafe.Pointer

	// initialized records whether C_Initialize succeeded, so Close only calls
	// C_Finalize when there is something to finalize.
	initialized bool
}

// Open ignores the path (the module is linked in) and resolves the function
// list from the statically-linked C_GetFunctionList. No dlopen, so this works
// in a fully-static binary. C_Initialize is intentionally NOT called here: that
// (and the TPM it needs) is a later concern; Open only proves the module is
// reachable and hands back a usable function list.
func Open(_ string) (*Module, error) {
	var list C.CK_FUNCTION_LIST_PTR
	if rv := C.C_GetFunctionList(&list); rv != C.CKR_OK {
		return nil, fmt.Errorf("C_GetFunctionList: 0x%X", uint(rv))
	}
	if list == nil {
		return nil, fmt.Errorf("C_GetFunctionList returned a nil function list")
	}
	return &Module{fnList: unsafe.Pointer(list)}, nil
}

// Close finalizes the library if it was initialized. In this loader there is no
// dlopen handle to release; the archive stays mapped for the process lifetime.
func (m *Module) Close() error {
	if m == nil {
		return nil
	}
	if m.initialized {
		// Best-effort C_Finalize; its return is ignored.
		C.C_Finalize(nil)
		m.initialized = false
	}
	m.fnList = nil
	return nil
}
