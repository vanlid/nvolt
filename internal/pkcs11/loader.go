// Package pkcs11 is a minimal, cgo-free PKCS#11 (Cryptoki 2.40) client built on
// purego. It implements only the calls nvolt needs.
package pkcs11

import (
	"fmt"
	"sync"

	"github.com/ebitengine/purego"
)

// Module is an opened PKCS#11 provider.
type Module struct {
	handle uintptr // dlopen handle
	fnList uintptr // CK_FUNCTION_LIST_PTR

	initOnce    sync.Once
	initErr     error
	initialized bool
}

// initialize calls C_Initialize exactly once per module. Cryptoki forbids a
// second C_Initialize without an intervening C_Finalize, so all session setup
// funnels through here.
func (m *Module) initialize() error {
	m.initOnce.Do(func() {
		rv, _, _ := purego.SyscallN(m.fn(idxInitialize), 0)
		if CKRV(rv) != CKR_OK {
			m.initErr = fmt.Errorf("C_Initialize: %s", CKRV(rv))
			return
		}
		m.initialized = true
	})
	return m.initErr
}

// Open dlopens the module and resolves its function list via C_GetFunctionList.
func Open(path string) (*Module, error) {
	handle, err := purego.Dlopen(path, purego.RTLD_NOW|purego.RTLD_GLOBAL)
	if err != nil {
		return nil, fmt.Errorf("dlopen %q: %w", path, err)
	}
	sym, err := purego.Dlsym(handle, "C_GetFunctionList")
	if err != nil {
		_ = purego.Dlclose(handle)
		return nil, fmt.Errorf("not a PKCS#11 module (no C_GetFunctionList): %q: %w", path, err)
	}
	var fnList uintptr
	// CK_RV C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR)
	rv, _, _ := purego.SyscallN(sym, uintptr(unsafePtr(&fnList)))
	if CKRV(rv) != CKR_OK {
		_ = purego.Dlclose(handle)
		return nil, fmt.Errorf("C_GetFunctionList: %s", CKRV(rv))
	}
	return &Module{handle: handle, fnList: fnList}, nil
}

// Close finalizes the library (if initialized) and releases the module handle.
func (m *Module) Close() error {
	if m.handle == 0 {
		return nil
	}
	if m.initialized {
		// Best-effort C_Finalize; ignore its return so Dlclose always runs.
		_, _, _ = purego.SyscallN(m.fn(idxFinalize), 0)
	}
	err := purego.Dlclose(m.handle)
	m.handle, m.fnList = 0, 0
	return err
}
