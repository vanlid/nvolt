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

	CKA_PRIVATE_EXPONENT uintptr = 0x00000123
	CKA_PRIME_1          uintptr = 0x00000124
	CKA_PRIME_2          uintptr = 0x00000125
	CKA_EXPONENT_1       uintptr = 0x00000126
	CKA_EXPONENT_2       uintptr = 0x00000127
	CKA_COEFFICIENT      uintptr = 0x00000128
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
// ckrvNames maps common Cryptoki return values to their names, so errors read
// as e.g. "CKR_PIN_INCORRECT" instead of a raw hex code.
var ckrvNames = map[CKRV]string{
	0x00:  "CKR_OK",
	0x01:  "CKR_CANCEL",
	0x05:  "CKR_GENERAL_ERROR",
	0x06:  "CKR_FUNCTION_FAILED",
	0x07:  "CKR_ARGUMENTS_BAD",
	0x30:  "CKR_DEVICE_ERROR",
	0x54:  "CKR_FUNCTION_NOT_SUPPORTED",
	0x60:  "CKR_KEY_HANDLE_INVALID",
	0x70:  "CKR_MECHANISM_INVALID",
	0x71:  "CKR_MECHANISM_PARAM_INVALID",
	0x82:  "CKR_OBJECT_HANDLE_INVALID",
	0xA0:  "CKR_PIN_INCORRECT",
	0xA1:  "CKR_PIN_INVALID",
	0xA2:  "CKR_PIN_LEN_RANGE",
	0xA3:  "CKR_PIN_EXPIRED",
	0xA4:  "CKR_PIN_LOCKED",
	0xB3:  "CKR_SESSION_HANDLE_INVALID",
	0xB5:  "CKR_SESSION_READ_ONLY",
	0xD0:  "CKR_TEMPLATE_INCOMPLETE",
	0xD1:  "CKR_TEMPLATE_INCONSISTENT",
	0xE0:  "CKR_TOKEN_NOT_PRESENT",
	0xE2:  "CKR_TOKEN_WRITE_PROTECTED",
	0x100: "CKR_USER_ALREADY_LOGGED_IN",
	0x101: "CKR_USER_NOT_LOGGED_IN",
	0x102: "CKR_USER_PIN_NOT_INITIALIZED",
	0x103: "CKR_USER_TYPE_INVALID",
}

func ckrvName(r CKRV) string {
	if name, ok := ckrvNames[r]; ok {
		return name
	}
	return fmt.Sprintf("CKR_0x%08X", uintptr(r))
}
