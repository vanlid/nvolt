// Package pkcs11 is a minimal, cgo-free PKCS#11 (Cryptoki 2.40) client built on
// purego. It implements only the calls nvolt needs.
package pkcs11

import (
	"fmt"
	"sync"
	"unsafe"

	"github.com/ebitengine/purego"
)

// Module is an opened PKCS#11 provider.
type Module struct {
	handle uintptr // dlopen handle

	// fnList is the raw CK_FUNCTION_LIST_PTR returned by C_GetFunctionList. It
	// is kept as unsafe.Pointer (not uintptr) so cryptoki.go's fn() can read it
	// back with plain Pointer arithmetic (unsafe.Add) instead of converting a
	// stored uintptr back to unsafe.Pointer, which `go vet`'s unsafeptr check
	// (rightly) flags as a possible misuse since it can't verify the uintptr
	// still denotes a live pointer.
	fnList unsafe.Pointer

	// headerOffset is the byte offset of the first function pointer within
	// CK_FUNCTION_LIST, detected at Open (see detectHeaderOffset) rather than
	// assumed per platform.
	headerOffset int

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
		if rvOf(rv) != CKR_OK {
			m.initErr = fmt.Errorf("C_Initialize: %s", rvOf(rv))
			return
		}
		m.initialized = true
	})
	return m.initErr
}

// Open dlopens the module and resolves its function list via C_GetFunctionList.
func Open(path string) (*Module, error) {
	handle, err := dlopen(path)
	if err != nil {
		return nil, fmt.Errorf("dlopen %q: %w", path, err)
	}
	sym, err := dlsym(handle, "C_GetFunctionList")
	if err != nil {
		_ = dlclose(handle)
		return nil, fmt.Errorf("not a PKCS#11 module (no C_GetFunctionList): %q: %w", path, err)
	}
	var fnList unsafe.Pointer
	// CK_RV C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR)
	rv, _, _ := purego.SyscallN(sym, uintptr(unsafe.Pointer(&fnList)))
	if rvOf(rv) != CKR_OK {
		_ = dlclose(handle)
		return nil, fmt.Errorf("C_GetFunctionList: %s", rvOf(rv))
	}
	offset, err := detectHeaderOffset(fnList, sym)
	if err != nil {
		_ = dlclose(handle)
		return nil, fmt.Errorf("%q: %w", path, err)
	}
	return &Module{handle: handle, fnList: fnList, headerOffset: offset}, nil
}

// detectHeaderOffset finds the byte offset of the function-pointer array inside
// CK_FUNCTION_LIST. The struct begins with a 2-byte CK_VERSION; how much
// padding follows depends on how the module's Cryptoki headers were compiled —
// naturally aligned (offset 8) or #pragma pack(1), as on Windows (offset 2).
//
// The fast path uses the fact that an ordinary module's list holds a pointer to
// C_GetFunctionList equal to the address we just called (sym); the matching
// offset is the one whose C_GetFunctionList entry equals sym. That equality does
// NOT hold for wrapping proxies (e.g. p11-kit-proxy), which expose their own
// internal C_GetFunctionList in the list — so we fall back to the offset whose
// mandatory entry points are all sane addresses. A wrong offset slides the array
// across the version/padding bytes and reads back nil or non-canonical values,
// so this disambiguates 8 vs 2 without assuming a per-platform constant. Both
// candidate reads stay well within the (far larger) list, so probing never
// dereferences out of bounds.
func detectHeaderOffset(fnList unsafe.Pointer, sym uintptr) (int, error) {
	for _, off := range []int{8, 2} {
		arr := (*[80]uintptr)(unsafe.Add(fnList, off))
		if arr[idxGetFunctionList] == sym {
			return off, nil
		}
	}
	for _, off := range []int{8, 2} {
		if looksLikeFunctionTable((*[80]uintptr)(unsafe.Add(fnList, off))) {
			return off, nil
		}
	}
	return 0, fmt.Errorf("could not resolve CK_FUNCTION_LIST layout: no offset yields a valid function table")
}

// looksLikeFunctionTable reports whether the mandatory (never-optional) Cryptoki
// entry points at this offset are all plausible code addresses: non-nil and
// canonical (below 2^48 on the LP64/LLP64 targets nvolt supports). At a wrong
// offset the pointer array slides across the 2-byte version and its padding,
// shifting real pointer bytes into the high bits, so at least one mandatory
// entry reads back as nil or non-canonical — which is how a proxy's true offset
// is told apart from the wrong one.
func looksLikeFunctionTable(arr *[80]uintptr) bool {
	const canonicalMax = uintptr(1) << 48
	for _, i := range []int{idxInitialize, idxFinalize, idxGetFunctionList} {
		if p := arr[i]; p == 0 || p >= canonicalMax {
			return false
		}
	}
	return true
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
	err := dlclose(m.handle)
	m.handle, m.fnList = 0, nil
	return err
}
