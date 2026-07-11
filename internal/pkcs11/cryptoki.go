package pkcs11

import "unsafe"

// Index of each function pointer in CK_FUNCTION_LIST (after the 8-byte
// version+padding header). Order is fixed by the Cryptoki 2.40 spec: the
// members appear in the exact order they are declared in pkcs11f.h, so the
// zero-based index of each call is its position in that declaration list.
//
// NOTE: these were corrected during the Task 2 spike. The task brief's draft
// values (e.g. GetSlotList=3, OpenSession=24, GetAttributeValue=39,
// FindObjects*=43..45) did not match the canonical layout and caused a SIGSEGV
// on the first non-Initialize call (calling C_GetFunctionList as if it were
// C_GetSlotList, dereferencing the CK_BBOOL tokenPresent=1 as a pointer).
const (
	idxInitialize        = 0  // C_Initialize
	idxFinalize          = 1  // C_Finalize
	idxGetSlotList       = 4  // C_GetSlotList  (index 3 is C_GetFunctionList)
	idxGetTokenInfo      = 6  // C_GetTokenInfo
	idxOpenSession       = 12 // C_OpenSession
	idxCloseSession      = 13 // C_CloseSession
	idxLogin             = 18 // C_Login
	idxLogout            = 19 // C_Logout
	idxGetAttributeValue = 24 // C_GetAttributeValue
	idxFindObjectsInit   = 26 // C_FindObjectsInit
	idxFindObjects       = 27 // C_FindObjects
	idxFindObjectsFinal  = 28 // C_FindObjectsFinal
	idxDecryptInit       = 33 // C_DecryptInit
	idxDecrypt           = 34 // C_Decrypt
	idxGenerateKeyPair   = 59 // C_GenerateKeyPair
)

// fn returns the idx-th function pointer of the module's CK_FUNCTION_LIST.
// The struct begins with a CK_VERSION (2 bytes) padded to pointer alignment
// (8 bytes on linux/amd64); function pointers follow as a packed array.
func (m *Module) fn(idx int) uintptr {
	base := unsafe.Pointer(m.fnList)
	arr := (*[80]uintptr)(unsafe.Add(base, 8)) // skip CK_VERSION + pad
	return arr[idx]
}
