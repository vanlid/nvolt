// Package pkcs11 is a minimal, cgo-free PKCS#11 (Cryptoki 2.40) client built on
// purego. It implements only the calls nvolt needs.
package pkcs11

import (
	"fmt"

	"github.com/ebitengine/purego"
)

// Module is an opened PKCS#11 provider.
type Module struct {
	handle uintptr // dlopen handle
	fnList uintptr // CK_FUNCTION_LIST_PTR
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

// Close releases the module handle.
func (m *Module) Close() error {
	if m.handle == 0 {
		return nil
	}
	err := purego.Dlclose(m.handle)
	m.handle, m.fnList = 0, 0
	return err
}
