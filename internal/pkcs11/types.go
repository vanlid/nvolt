package pkcs11

import (
	"fmt"
	"unsafe"
)

// CKRV is a PKCS#11 CK_RV return code.
type CKRV uintptr

const (
	CKR_OK CKRV = 0x00000000
)

func (r CKRV) String() string { return ckrvName(r) } // filled out in Task 2

// ckrvName renders a CKRV as a human-readable string. Only CKR_OK is named
// for now; Task 2 will fill out the full Cryptoki error table.
func ckrvName(r CKRV) string {
	switch r {
	case CKR_OK:
		return "CKR_OK"
	default:
		return fmt.Sprintf("CKR_0x%08X", uintptr(r))
	}
}

func unsafePtr[T any](p *T) unsafe.Pointer { return unsafe.Pointer(p) }
