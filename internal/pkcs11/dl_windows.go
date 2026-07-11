//go:build windows

// Package pkcs11 loads PKCS#11 modules via the Win32 dynamic loader on
// Windows. This lets nvolt run directly on a Windows machine that has a
// YubiKey plugged in locally, dlopen-ing a module such as OpenSC's
// opensc-pkcs11.dll or Yubico's ykcs11.dll — no WSL/p11-kit/usbip forwarding
// required for that topology.
package pkcs11

import (
	"fmt"

	"golang.org/x/sys/windows"
)

// dlopen loads a shared library and returns its handle. It uses
// LOAD_WITH_ALTERED_SEARCH_PATH so the module's own directory is searched
// for its dependent DLLs (important for modules like OpenSC that ship
// sibling dependencies alongside the main DLL).
func dlopen(path string) (uintptr, error) {
	h, err := windows.LoadLibraryEx(path, 0, windows.LOAD_WITH_ALTERED_SEARCH_PATH)
	if err != nil {
		return 0, fmt.Errorf("LoadLibraryEx %q: %w", path, err)
	}
	return uintptr(h), nil
}

// dlsym resolves a symbol in a library opened with dlopen.
func dlsym(handle uintptr, name string) (uintptr, error) {
	addr, err := windows.GetProcAddress(windows.Handle(handle), name)
	if err != nil {
		return 0, fmt.Errorf("GetProcAddress %q: %w", name, err)
	}
	return addr, nil
}

// dlclose releases a library handle opened with dlopen.
func dlclose(handle uintptr) error {
	return windows.FreeLibrary(windows.Handle(handle))
}
