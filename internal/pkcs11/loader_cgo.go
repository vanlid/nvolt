//go:build wolfpkcs11_static

package pkcs11

// #include <wolfpkcs11/pkcs11.h>
import "C"

import (
	"fmt"
	"sync"
	"unsafe"
)

// wolfPKCS11 is linked in as a single process-global library, so C_Initialize /
// C_Finalize act process-wide — not per-Module. Reference-count live Modules so
// the library is initialized on the first Module and finalized only when the
// last one closes. This keeps two concurrently-live Modules of the built-in
// provider correct (e.g. a migrate flow decrypting with the old key while
// encrypting with the new one): closing one no longer tears the library out
// from under the other. The mutex also makes initialize/Close race-free.
var (
	initMu    sync.Mutex
	initCount int
)

// Module is an opened PKCS#11 provider in the statically-linked build. Unlike
// the purego loader there is no dlopen handle: wolfPKCS11 is linked into the
// binary, so the only state is the function list resolved from the linked-in
// C_GetFunctionList and whether C_Initialize has been called.
type Module struct {
	// fnList is the raw CK_FUNCTION_LIST_PTR returned by C_GetFunctionList,
	// kept as unsafe.Pointer for parity with the purego loader's Module.
	fnList unsafe.Pointer

	// initialized records whether this Module contributed to the global
	// init refcount, so Close decrements exactly once.
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

// initialize calls the process-global C_Initialize once, when the first live
// Module needs it, and joins the init refcount. A NULL pInitArgs is passed for
// parity with the purego loader (no OS-locking args). CKR_CRYPTOKI_ALREADY_
// INITIALIZED is treated as success in case the library was initialized outside
// this refcount.
func (m *Module) initialize() error {
	initMu.Lock()
	defer initMu.Unlock()
	if m.initialized {
		return nil
	}
	if initCount == 0 {
		rv := C.C_Initialize(nil)
		if rv != C.CKR_OK && rv != C.CKR_CRYPTOKI_ALREADY_INITIALIZED {
			return fmt.Errorf("C_Initialize: 0x%X", uint(rv))
		}
	}
	initCount++
	m.initialized = true
	return nil
}

// Close drops this Module's hold on the global library. There is no dlopen
// handle to release (the archive stays mapped for the process lifetime); the
// only teardown is the process-global C_Finalize, which runs only when the LAST
// initialized Module closes — so closing one Module never finalizes the library
// out from under another that is still live.
func (m *Module) Close() error {
	if m == nil {
		return nil
	}
	if m.initialized {
		initMu.Lock()
		initCount--
		if initCount == 0 {
			// Best-effort C_Finalize; its return is ignored.
			C.C_Finalize(nil)
		}
		initMu.Unlock()
		m.initialized = false
	}
	m.fnList = nil
	return nil
}
