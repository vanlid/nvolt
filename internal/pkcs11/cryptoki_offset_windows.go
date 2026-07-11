//go:build windows

package pkcs11

// ckFuncListHeaderOffset is the byte offset of the first function pointer in
// CK_FUNCTION_LIST. Windows Cryptoki headers use #pragma pack(1), so the
// struct is byte-packed with no padding after the 2-byte CK_VERSION — the
// function pointers start at offset 2, not 8.
const ckFuncListHeaderOffset = 2
