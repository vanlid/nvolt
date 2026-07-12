//go:build pkcs11

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
	idxGetFunctionList   = 3  // C_GetFunctionList
	idxGetSlotList       = 4  // C_GetSlotList
	idxGetTokenInfo      = 6  // C_GetTokenInfo
	idxInitToken         = 9  // C_InitToken
	idxInitPIN           = 10 // C_InitPIN
	idxOpenSession       = 12 // C_OpenSession
	idxCloseSession      = 13 // C_CloseSession
	idxLogin             = 18 // C_Login
	idxLogout            = 19 // C_Logout
	idxCreateObject      = 20 // C_CreateObject
	idxDestroyObject     = 22 // C_DestroyObject
	idxGetAttributeValue = 24 // C_GetAttributeValue
	idxSetAttributeValue = 25 // C_SetAttributeValue
	idxFindObjectsInit   = 26 // C_FindObjectsInit
	idxFindObjects       = 27 // C_FindObjects
	idxFindObjectsFinal  = 28 // C_FindObjectsFinal
	idxDecryptInit       = 33 // C_DecryptInit
	idxDecrypt           = 34 // C_Decrypt
	idxGenerateKeyPair   = 59 // C_GenerateKeyPair
)

// fn returns the idx-th function pointer of the module's CK_FUNCTION_LIST.
// m.headerOffset (the byte offset of the pointer array within the struct) is
// detected at Open (see detectHeaderOffset) rather than assumed, so it is
// correct regardless of how the module's Cryptoki headers were packed.
func (m *Module) fn(idx int) uintptr {
	arr := (*[80]uintptr)(unsafe.Add(m.fnList, m.headerOffset))
	return arr[idx]
}
