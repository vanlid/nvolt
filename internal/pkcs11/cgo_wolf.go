//go:build tpm_static && !pkcs11

package pkcs11

/*
#cgo CFLAGS: -I${SRCDIR}/dist/static/include
#cgo LDFLAGS: ${SRCDIR}/dist/static/lib/libwolfpkcs11.a ${SRCDIR}/dist/static/lib/libwolftpm.a ${SRCDIR}/dist/static/lib/libwolfssl.a -lm
#include <wolfpkcs11/pkcs11.h>
*/
import "C"
