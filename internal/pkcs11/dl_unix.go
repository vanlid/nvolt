//go:build !windows

package pkcs11

import "github.com/ebitengine/purego"

// dlopen loads a shared library and returns its handle.
func dlopen(path string) (uintptr, error) {
	return purego.Dlopen(path, purego.RTLD_NOW|purego.RTLD_GLOBAL)
}

// dlsym resolves a symbol in a library opened with dlopen.
func dlsym(handle uintptr, name string) (uintptr, error) {
	return purego.Dlsym(handle, name)
}

// dlclose releases a library handle opened with dlopen.
func dlclose(handle uintptr) error {
	return purego.Dlclose(handle)
}
