//go:build !windows

package pkcs11

// ckFuncListHeaderOffset is the byte offset of the first function pointer in
// CK_FUNCTION_LIST. On Unix the struct is naturally aligned, so the 2-byte
// CK_VERSION is padded to pointer alignment and the pointers start at offset 8.
const ckFuncListHeaderOffset = 8
