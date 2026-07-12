//go:build pkcs11 && !windows

package pkcs11

import "github.com/ebitengine/purego"

// dlopen loads a shared library and returns its handle.
//
// RTLD_LOCAL (not RTLD_GLOBAL) is deliberate and required: every PKCS#11 module
// exports the same symbol names (C_GetFunctionList, C_Initialize, ...), so
// loading more than one RTLD_GLOBAL into a process — as `pkcs11 list` does when
// it probes several providers — lets the first module's symbols interpose on the
// others. A later module's own reference to C_GetFunctionList then binds to the
// first module's copy, so its function-list entry no longer matches the dlsym'd
// symbol and detectHeaderOffset rejects it. dlclose between probes does not help
// (it is advisory; glibc keeps the RTLD_GLOBAL object mapped), so keeping each
// module's symbols local — as p11-kit, NSS and libp11 do — is the fix.
func dlopen(path string) (uintptr, error) {
	return purego.Dlopen(path, purego.RTLD_NOW|purego.RTLD_LOCAL)
}

// dlsym resolves a symbol in a library opened with dlopen.
func dlsym(handle uintptr, name string) (uintptr, error) {
	return purego.Dlsym(handle, name)
}

// dlclose releases a library handle opened with dlopen.
func dlclose(handle uintptr) error {
	return purego.Dlclose(handle)
}
