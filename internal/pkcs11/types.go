package pkcs11

import (
	"fmt"
	"unsafe"
)

// CKRV is a PKCS#11 CK_RV return code.
type CKRV uintptr

const (
	CKR_OK                     CKRV = 0x00000000
	CKR_ARGUMENTS_BAD          CKRV = 0x00000007
	CKR_FUNCTION_NOT_SUPPORTED CKRV = 0x00000054
	CKR_MECHANISM_INVALID      CKRV = 0x00000070
)

// Object classes, key types, session/user flags, mechanisms.
const (
	CKO_PUBLIC_KEY     uintptr = 2
	CKO_PRIVATE_KEY    uintptr = 3
	CKK_RSA            uintptr = 0
	CKF_RW_SESSION     uintptr = 2
	CKF_SERIAL_SESSION uintptr = 4
	CKU_USER           uintptr = 1
	CKM_RSA_PKCS_OAEP  uintptr = 0x00000009
	CKM_RSA_X_509      uintptr = 0x00000003
	CKG_MGF1_SHA256    uintptr = 0x00000002
	CKZ_DATA_SPECIFIED uintptr = 1
	CKM_SHA256         uintptr = 0x00000250

	CKM_RSA_PKCS_KEY_PAIR_GEN uintptr = 0x00000000
)

// CK_TOKEN_INFO.flags bits (Cryptoki 2.40 SS9.5.1) that drive PIN-handling
// auto-detection: CKF_LOGIN_REQUIRED tells us whether C_Login is needed at
// all, and CKF_PROTECTED_AUTHENTICATION_PATH tells us the reader/pinpad
// collects the PIN out-of-band, so the application must call C_Login with a
// NULL PIN rather than supplying one.
const (
	CKF_LOGIN_REQUIRED                uintptr = 0x00000004
	CKF_PROTECTED_AUTHENTICATION_PATH uintptr = 0x00000100
)

// Attribute types.
const (
	CKA_CLASS           uintptr = 0x00000000
	CKA_KEY_TYPE        uintptr = 0x00000100
	CKA_ID              uintptr = 0x00000102
	CKA_LABEL           uintptr = 0x00000003
	CKA_TOKEN           uintptr = 0x00000001
	CKA_PRIVATE         uintptr = 0x00000002
	CKA_SENSITIVE       uintptr = 0x00000103
	CKA_ENCRYPT         uintptr = 0x00000104
	CKA_DECRYPT         uintptr = 0x00000105
	CKA_WRAP            uintptr = 0x00000106
	CKA_UNWRAP          uintptr = 0x00000107
	CKA_SIGN            uintptr = 0x00000108
	CKA_VERIFY          uintptr = 0x0000010A
	CKA_MODULUS         uintptr = 0x00000120
	CKA_MODULUS_BITS    uintptr = 0x00000121
	CKA_PUBLIC_EXPONENT uintptr = 0x00000122
)

// CK_ATTRIBUTE mirrors the Cryptoki attribute template entry.
type CK_ATTRIBUTE struct {
	Type  uintptr
	Value unsafe.Pointer
	Len   uintptr
}

// CK_MECHANISM mirrors the Cryptoki mechanism struct.
type CK_MECHANISM struct {
	Mechanism uintptr
	Param     unsafe.Pointer
	ParamLen  uintptr
}

// ckOAEPParams is CK_RSA_PKCS_OAEP_PARAMS for CKM_RSA_PKCS_OAEP.
type ckOAEPParams struct {
	HashAlg    uintptr
	Mgf        uintptr
	SourceType uintptr
	SourceData unsafe.Pointer
	SourceLen  uintptr
}

func (r CKRV) String() string { return ckrvName(r) }

// ckrvName renders a CKRV as a human-readable string, naming the codes nvolt
// distinguishes and hex-formatting the rest.
func ckrvName(r CKRV) string {
	switch r {
	case CKR_OK:
		return "CKR_OK"
	case CKR_ARGUMENTS_BAD:
		return "CKR_ARGUMENTS_BAD"
	case CKR_FUNCTION_NOT_SUPPORTED:
		return "CKR_FUNCTION_NOT_SUPPORTED"
	case CKR_MECHANISM_INVALID:
		return "CKR_MECHANISM_INVALID"
	default:
		return fmt.Sprintf("CKR_0x%08X", uintptr(r))
	}
}
