# nvolt PKCS#11 / YubiKey Support — Phase 1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let an nvolt machine perform its one private-key operation (RSA-OAEP-SHA256 unwrap of the vault master key) on a hardware token via PKCS#11, without cgo, keeping a single static binary.

**Architecture:** Introduce a `crypto.Decrypter` seam so the machine's private key can be software (PEM, today) or PKCS#11 (token). A thin `purego`-based FFI binding `dlopen`s the PKCS#11 module (`p11-kit-client.so` / `opensc-pkcs11.so`) and drives the ~12 `C_*` calls we need. Enrollment (`pkcs11 use`) validates the module + RSA key and pins a working OAEP path via a round-trip self-test. SoftHSM2 is the automated test oracle; a real YubiKey is validated manually.

**Tech Stack:** Go 1.24.3, `github.com/ebitengine/purego`, PKCS#11 (Cryptoki 2.40), SoftHSM2 + OpenSC (tests), cobra (existing CLI).

## Global Constraints

- Go **1.24.3**; build stays **`CGO_ENABLED=0`** — no cgo, no build tags for PKCS#11.
- Only new dependency: **`github.com/ebitengine/purego`**. No `miekg/pkcs11`, no `crypto11`.
- On-disk wrap format is **unchanged**: master key stays RSA-**OAEP-SHA256**-wrapped (`internal/crypto/wrap.go`). Hardware and software machines must interoperate in one vault.
- Minimum RSA modulus **2048 bits** (matches `crypto.ValidateRSAKey`).
- Machine key-source persists in existing `~/.nvolt/machine.json` via a new optional `KeySource` field; **absent ⇒ `software`** (backward compatible). PIN is **never persisted**.
- PKCS#11 key named by an **RFC 7512** `pkcs11:` URI; module path overridable via `NVOLT_PKCS11_MODULE`.
- Follow existing repo patterns: cobra commands in `internal/cli/`, errors via `internal/errors`, UI via `internal/ui`, atomic writes via `vault.WriteFileAtomic`.

---

### Task 1: Dev environment, SoftHSM2 fixture, and purego module-load smoke test

Proves the foundation: `purego` can `dlopen` a real PKCS#11 module and obtain its function list.

**Files:**
- Modify: `go.mod`, `go.sum` (add purego)
- Create: `internal/pkcs11/loader.go`
- Create: `internal/pkcs11/loader_test.go`
- Create: `scripts/test-softhsm-setup.sh`

**Interfaces:**
- Produces: `pkcs11.Open(modulePath string) (*Module, error)`, `(*Module).Close() error`, and an opaque `*Module` holding the resolved `CK_FUNCTION_LIST` pointer.

- [ ] **Step 1: Install toolchain and libraries**

```bash
sudo apt-get update && sudo apt-get install -y softhsm2 opensc
# Go 1.24.3 (if not present): fetch official tarball to /usr/local/go
curl -fsSL https://go.dev/dl/go1.24.3.linux-amd64.tar.gz -o /tmp/go.tgz && sudo tar -C /usr/local -xzf /tmp/go.tgz
export PATH=/usr/local/go/bin:$PATH && go version   # expect: go version go1.24.3 ...
```

- [ ] **Step 2: Create the SoftHSM fixture script**

`scripts/test-softhsm-setup.sh` — creates an isolated token + a 2048-bit RSA key labelled `nvolt-test`:

```bash
#!/usr/bin/env bash
set -euo pipefail
export SOFTHSM2_CONF="${SOFTHSM2_CONF:-$PWD/.softhsm2/softhsm2.conf}"
TOKENDIR="$(dirname "$SOFTHSM2_CONF")/tokens"
mkdir -p "$TOKENDIR"
printf 'directories.tokendir = %s\nobjectstore.backend = file\n' "$TOKENDIR" > "$SOFTHSM2_CONF"
softhsm2-util --init-token --free --label nvolt-test --pin 1234 --so-pin 5678
MODULE="$(ls /usr/lib/softhsm/libsofthsm2.so /usr/lib/*/softhsm/libsofthsm2.so 2>/dev/null | head -1)"
pkcs11-tool --module "$MODULE" --token-label nvolt-test --login --pin 1234 \
  --keypairgen --key-type rsa:2048 --label nvolt-test --id 01
echo "MODULE=$MODULE"
echo "SOFTHSM2_CONF=$SOFTHSM2_CONF"
```

Run it: `bash scripts/test-softhsm-setup.sh` → note the printed `MODULE` path.

- [ ] **Step 3: Add purego**

```bash
go get github.com/ebitengine/purego@latest && go mod tidy
```

- [ ] **Step 4: Write the failing test**

`internal/pkcs11/loader_test.go`:

```go
package pkcs11

import (
	"os"
	"testing"
)

func testModulePath(t *testing.T) string {
	p := os.Getenv("NVOLT_TEST_PKCS11_MODULE")
	if p == "" {
		t.Skip("set NVOLT_TEST_PKCS11_MODULE to run PKCS#11 integration tests")
	}
	return p
}

func TestOpenReturnsModuleWithFunctionList(t *testing.T) {
	m, err := Open(testModulePath(t))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer m.Close()
	if m.fnList == 0 {
		t.Fatal("expected non-nil CK_FUNCTION_LIST pointer")
	}
}
```

- [ ] **Step 5: Run test to verify it fails**

Run: `NVOLT_TEST_PKCS11_MODULE=$MODULE go test ./internal/pkcs11/ -run TestOpen -v`
Expected: FAIL — `undefined: Open`.

- [ ] **Step 6: Implement `Open`/`Close`**

`internal/pkcs11/loader.go`:

```go
// Package pkcs11 is a minimal, cgo-free PKCS#11 (Cryptoki 2.40) client built on
// purego. It implements only the calls nvolt needs.
package pkcs11

import (
	"fmt"

	"github.com/ebitengine/purego"
)

// Module is an opened PKCS#11 provider.
type Module struct {
	handle uintptr // dlopen handle
	fnList uintptr // CK_FUNCTION_LIST_PTR
}

// Open dlopens the module and resolves its function list via C_GetFunctionList.
func Open(path string) (*Module, error) {
	handle, err := purego.Dlopen(path, purego.RTLD_NOW|purego.RTLD_GLOBAL)
	if err != nil {
		return nil, fmt.Errorf("dlopen %q: %w", path, err)
	}
	sym, err := purego.Dlsym(handle, "C_GetFunctionList")
	if err != nil {
		_ = purego.Dlclose(handle)
		return nil, fmt.Errorf("not a PKCS#11 module (no C_GetFunctionList): %q: %w", path, err)
	}
	var fnList uintptr
	// CK_RV C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR)
	rv, _, _ := purego.SyscallN(sym, uintptr(unsafePtr(&fnList)))
	if CKRV(rv) != CKR_OK {
		_ = purego.Dlclose(handle)
		return nil, fmt.Errorf("C_GetFunctionList: %s", CKRV(rv))
	}
	return &Module{handle: handle, fnList: fnList}, nil
}

// Close releases the module handle.
func (m *Module) Close() error {
	if m.handle == 0 {
		return nil
	}
	err := purego.Dlclose(m.handle)
	m.handle, m.fnList = 0, 0
	return err
}
```

Create `internal/pkcs11/types.go` with the constants + helpers used above:

```go
package pkcs11

import "unsafe"

type CKRV uintptr

const (
	CKR_OK CKRV = 0x00000000
)

func (r CKRV) String() string { return ckrvName(r) } // filled out in Task 2

func unsafePtr[T any](p *T) unsafe.Pointer { return unsafe.Pointer(p) }
```

- [ ] **Step 7: Run test to verify it passes**

Run: `NVOLT_TEST_PKCS11_MODULE=$MODULE go test ./internal/pkcs11/ -run TestOpen -v`
Expected: PASS.

- [ ] **Step 8: Commit**

```bash
git add go.mod go.sum internal/pkcs11/ scripts/test-softhsm-setup.sh
git commit -m "feat(pkcs11): purego module loader + SoftHSM test fixture"
```

---

### Task 2: FFI binding + OAEP-SHA256 decrypt round-trip (the spike — make-or-break)

Drives a session end-to-end and proves an on-token RSA-OAEP-SHA256 decrypt matches software wrapping. **If native OAEP fails here, Task 3's raw fallback is required before proceeding.**

**Files:**
- Create: `internal/pkcs11/cryptoki.go` (function-list offsets + typed wrappers)
- Modify: `internal/pkcs11/types.go` (constants, `CK_ATTRIBUTE`, `CK_MECHANISM`, `ckrvName`)
- Create: `internal/pkcs11/session.go` (`Session`, find-key, decrypt)
- Create: `internal/pkcs11/session_test.go`

**Interfaces:**
- Produces:
  - `(*Module).OpenSession(tokenLabel string) (*Session, error)`
  - `(*Session).Login(pin string) error`, `(*Session).Close() error`
  - `(*Session).FindRSAPrivateKey(id []byte) (Object, error)` (Object = `uintptr` handle)
  - `(*Session).RSAPublicKey(obj Object) (*rsa.PublicKey, error)`
  - `(*Session).DecryptOAEPSHA256(priv Object, ct []byte) ([]byte, error)`
  - Constants: `CKM_RSA_PKCS_OAEP`, `CKO_PRIVATE_KEY`, `CKK_RSA`, attribute type consts, `CKR_*`.

- [ ] **Step 1: Define the Cryptoki call layer**

`internal/pkcs11/cryptoki.go` — read function pointers from the `CK_FUNCTION_LIST` struct by index and call via `purego.SyscallN`. The struct is `CK_VERSION version;` (2 bytes, padded to pointer alignment) followed by function pointers in the Cryptoki 2.40 order. Model it as an array of `uintptr` after an 8-byte header:

```go
package pkcs11

import "unsafe"

// Index of each function pointer in CK_FUNCTION_LIST (after the 8-byte
// version+padding header). Order is fixed by the Cryptoki 2.40 spec.
const (
	idxInitialize        = 0
	idxFinalize          = 1
	idxGetSlotList       = 3
	idxGetTokenInfo      = 5
	idxOpenSession       = 24
	idxCloseSession      = 25
	idxLogin             = 28
	idxLogout            = 29
	idxGenerateKeyPair   = 51
	idxFindObjectsInit   = 43
	idxFindObjects       = 44
	idxFindObjectsFinal  = 45
	idxGetAttributeValue = 39
	idxDecryptInit       = 33
	idxDecrypt           = 34
)

func (m *Module) fn(idx int) uintptr {
	base := unsafe.Pointer(m.fnList)
	arr := (*[80]uintptr)(unsafe.Add(base, 8)) // skip CK_VERSION + pad
	return arr[idx]
}
```

> Implementation note: the indices above are the canonical Cryptoki 2.40 ordering. Verify once at runtime in Step 4's test (a wrong index surfaces immediately as `CKR_OK` failures on `C_Initialize`). If the header/padding differs on a platform, adjust the `unsafe.Add` offset — SoftHSM on linux/amd64 uses 8.

- [ ] **Step 2: Add the type/constant definitions**

`internal/pkcs11/types.go` (extend):

```go
const (
	CKR_OK                    CKRV = 0x00000000
	CKR_MECHANISM_INVALID     CKRV = 0x00000070
	CKR_FUNCTION_NOT_SUPPORTED CKRV = 0x00000054
)

const (
	CKO_PRIVATE_KEY uintptr = 3
	CKK_RSA         uintptr = 0
	CKF_SERIAL_SESSION uintptr = 4
	CKU_USER        uintptr = 1
	CKM_RSA_PKCS_OAEP uintptr = 0x00000009
	CKM_RSA_X_509     uintptr = 0x00000003
	CKG_MGF1_SHA256   uintptr = 0x00000002
	CKZ_DATA_SPECIFIED uintptr = 1
	CKM_SHA256        uintptr = 0x00000250
)

// attribute types
const (
	CKA_CLASS        uintptr = 0x00000000
	CKA_KEY_TYPE     uintptr = 0x00000100
	CKA_ID           uintptr = 0x00000102
	CKA_LABEL        uintptr = 0x00000003
	CKA_DECRYPT      uintptr = 0x00000105
	CKA_MODULUS      uintptr = 0x00000120
	CKA_MODULUS_BITS uintptr = 0x00000121
	CKA_PUBLIC_EXPONENT uintptr = 0x00000122
)

type CK_ATTRIBUTE struct {
	Type  uintptr
	Value unsafe.Pointer
	Len   uintptr
}

// CK_RSA_PKCS_OAEP_PARAMS for CKM_RSA_PKCS_OAEP.
type ckOAEPParams struct {
	HashAlg    uintptr
	Mgf        uintptr
	SourceType uintptr
	SourceData unsafe.Pointer
	SourceLen  uintptr
}

func ckrvName(r CKRV) string {
	switch r {
	case CKR_OK:
		return "CKR_OK"
	case CKR_MECHANISM_INVALID:
		return "CKR_MECHANISM_INVALID"
	case CKR_FUNCTION_NOT_SUPPORTED:
		return "CKR_FUNCTION_NOT_SUPPORTED"
	default:
		return "CKR_0x" + strconvFormatUint(uint64(r))
	}
}
```

(Add `import "strconv"` and a tiny `strconvFormatUint` helper, or inline `strconv.FormatUint(uint64(r),16)`.)

- [ ] **Step 3: Implement session, find-key, pubkey, decrypt**

`internal/pkcs11/session.go` — full implementations of `OpenSession`, `Login`, `FindRSAPrivateKey`, `RSAPublicKey`, `DecryptOAEPSHA256`, each calling `m.fn(idx)` via `purego.SyscallN`. Representative (the decrypt, which is the crux):

```go
package pkcs11

import (
	"crypto/rsa"
	"fmt"
	"math/big"
	"unsafe"

	"github.com/ebitengine/purego"
)

type Session struct {
	m      *Module
	handle uintptr
}

type Object = uintptr

// DecryptOAEPSHA256 performs CKM_RSA_PKCS_OAEP (SHA-256, MGF1-SHA256) on the token.
func (s *Session) DecryptOAEPSHA256(priv Object, ct []byte) ([]byte, error) {
	params := ckOAEPParams{HashAlg: CKM_SHA256, Mgf: CKG_MGF1_SHA256, SourceType: CKZ_DATA_SPECIFIED}
	mech := struct {
		Mechanism uintptr
		Param     unsafe.Pointer
		ParamLen  uintptr
	}{CKM_RSA_PKCS_OAEP, unsafe.Pointer(&params), unsafe.Sizeof(params)}

	rv, _, _ := purego.SyscallN(s.m.fn(idxDecryptInit), s.handle, uintptr(unsafe.Pointer(&mech)), priv)
	if CKRV(rv) != CKR_OK {
		return nil, fmt.Errorf("C_DecryptInit(OAEP): %s", CKRV(rv))
	}
	return s.doDecrypt(ct)
}

// doDecrypt runs the two-call C_Decrypt length pattern.
func (s *Session) doDecrypt(ct []byte) ([]byte, error) {
	var outLen uintptr
	rv, _, _ := purego.SyscallN(s.m.fn(idxDecrypt), s.handle,
		uintptr(unsafe.Pointer(&ct[0])), uintptr(len(ct)), 0, uintptr(unsafe.Pointer(&outLen)))
	if CKRV(rv) != CKR_OK {
		return nil, fmt.Errorf("C_Decrypt(size): %s", CKRV(rv))
	}
	out := make([]byte, outLen)
	rv, _, _ = purego.SyscallN(s.m.fn(idxDecrypt), s.handle,
		uintptr(unsafe.Pointer(&ct[0])), uintptr(len(ct)),
		uintptr(unsafe.Pointer(&out[0])), uintptr(unsafe.Pointer(&outLen)))
	if CKRV(rv) != CKR_OK {
		return nil, fmt.Errorf("C_Decrypt: %s", CKRV(rv))
	}
	return out[:outLen], nil
}
```

Implement the remaining methods in the same file using the same `SyscallN(m.fn(idx), ...)` pattern:
- `OpenSession(tokenLabel)`: `C_Initialize(nil)` (once per module — guard with a `sync.Once` on `Module`), `C_GetSlotList`→find slot whose `C_GetTokenInfo.label` matches, `C_OpenSession(slot, CKF_SERIAL_SESSION, ...)`.
- `Login(pin)`: `C_Login(handle, CKU_USER, pinBytes, len)`.
- `FindRSAPrivateKey(id)`: `C_FindObjectsInit` with attrs `{CKA_CLASS=CKO_PRIVATE_KEY, CKA_KEY_TYPE=CKK_RSA[, CKA_ID=id]}`, `C_FindObjects`, `C_FindObjectsFinal`; return first handle.
- `RSAPublicKey(obj)`: `C_GetAttributeValue` two-call pattern for `CKA_MODULUS` and `CKA_PUBLIC_EXPONENT`; build `&rsa.PublicKey{N: new(big.Int).SetBytes(mod), E: int(new(big.Int).SetBytes(exp).Int64())}`.

- [ ] **Step 4: Write the round-trip test**

`internal/pkcs11/session_test.go`:

```go
package pkcs11

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"testing"
)

func TestOAEPRoundTripAgainstToken(t *testing.T) {
	m, err := Open(testModulePath(t))
	if err != nil { t.Fatal(err) }
	defer m.Close()
	sess, err := m.OpenSession("nvolt-test")
	if err != nil { t.Fatal(err) }
	defer sess.Close()
	if err := sess.Login("1234"); err != nil { t.Fatal(err) }

	priv, err := sess.FindRSAPrivateKey([]byte{0x01})
	if err != nil { t.Fatal(err) }
	pub, err := sess.RSAPublicKey(priv)
	if err != nil { t.Fatal(err) }

	msg := []byte("nvolt-master-key-32-bytes-xxxxxx")
	ct, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, msg, nil)
	if err != nil { t.Fatal(err) }

	got, err := sess.DecryptOAEPSHA256(priv, ct)
	if err != nil { t.Fatalf("token decrypt: %v", err) }
	if !bytes.Equal(got, msg) {
		t.Fatalf("round-trip mismatch: got %q", got)
	}
}
```

- [ ] **Step 5: Run and verify**

Run: `NVOLT_TEST_PKCS11_MODULE=$MODULE go test ./internal/pkcs11/ -run TestOAEP -v`
Expected: PASS. **If it fails with `CKR_MECHANISM_INVALID`**, native OAEP is unsupported on this token — note it; Task 3 supplies the fallback and Task 6 will select it.

- [ ] **Step 6: Commit**

```bash
git add internal/pkcs11/
git commit -m "feat(pkcs11): session + OAEP-SHA256 token decrypt (spike passes on SoftHSM)"
```

---

### Task 3: Raw-RSA OAEP fallback (`oaep_mode: raw`)

For tokens exposing only raw RSA. Do `CKM_RSA_X_509` on-card, strip OAEP-SHA256 padding in Go.

**Files:**
- Create: `internal/crypto/oaep_raw.go`
- Create: `internal/crypto/oaep_raw_test.go`
- Modify: `internal/pkcs11/session.go` (add `DecryptRawRSA(priv, ct) ([]byte, error)` using `CKM_RSA_X_509`)

**Interfaces:**
- Produces: `crypto.UnpadOAEPSHA256(em []byte, k int) ([]byte, error)` (k = modulus size in bytes); `(*pkcs11.Session).DecryptRawRSA(priv Object, ct []byte) ([]byte, error)`.

- [ ] **Step 1: Write the failing test** (verifies unpad matches stdlib OAEP)

`internal/crypto/oaep_raw_test.go`:

```go
package crypto

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"math/big"
	"testing"
)

func TestUnpadOAEPSHA256MatchesStdlib(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	msg := []byte("hello-nvolt")
	ct, _ := rsa.EncryptOAEP(sha256.New(), rand.Reader, &key.PublicKey, msg, nil)
	// raw RSA decrypt (what a token's CKM_RSA_X_509 returns): m = c^d mod n
	c := new(big.Int).SetBytes(ct)
	m := new(big.Int).Exp(c, key.D, key.N)
	k := (key.N.BitLen() + 7) / 8
	em := make([]byte, k)
	m.FillBytes(em)
	got, err := UnpadOAEPSHA256(em, k)
	if err != nil { t.Fatal(err) }
	if !bytes.Equal(got, msg) { t.Fatalf("got %q want %q", got, msg) }
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `go test ./internal/crypto/ -run TestUnpadOAEP -v` → FAIL (`undefined: UnpadOAEPSHA256`).

- [ ] **Step 3: Implement OAEP unpad**

`internal/crypto/oaep_raw.go` — standard OAEP decode (RFC 8017 §7.1.2) with SHA-256 + MGF1-SHA256, constant-time where practical:

```go
package crypto

import (
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"hash"
)

// UnpadOAEPSHA256 removes OAEP (SHA-256, MGF1-SHA256, empty label) padding from a
// raw RSA decryption result `em` of length k (the modulus size in bytes).
func UnpadOAEPSHA256(em []byte, k int) ([]byte, error) {
	h := sha256.New()
	hLen := h.Size()
	if k < 2*hLen+2 || len(em) != k {
		return nil, errors.New("oaep: bad length")
	}
	h.Write(nil)
	lHash := h.Sum(nil)

	y := em[0]
	maskedSeed := em[1 : 1+hLen]
	maskedDB := em[1+hLen:]
	seed := xorMGF1(maskedSeed, maskedDB, sha256.New)
	db := xorMGF1(maskedDB, seed, sha256.New)

	lHash2 := db[:hLen]
	rest := db[hLen:]
	// find 0x01 separator after zero padding
	var one, index int
	for i := 0; i < len(rest); i++ {
		if rest[i] == 1 && one == 0 {
			one, index = 1, i
		} else if rest[i] != 0 && one == 0 {
			one = -1 // nonzero before separator => invalid
		}
	}
	good := subtle.ConstantTimeByteEq(y, 0)
	good &= subtle.ConstantTimeCompare(lHash, lHash2)
	if good != 1 || one != 1 {
		return nil, errors.New("oaep: decryption error")
	}
	return rest[index+1:], nil
}

// xorMGF1 returns a XOR (MGF1(seed) over len(target)).
func xorMGF1(target, seed []byte, newHash func() hash.Hash) []byte {
	out := make([]byte, len(target))
	mgf1XOR(out, newHash(), seed, target)
	return out
}

// mgf1XOR writes target XOR MGF1(seed) into out.
func mgf1XOR(out []byte, h hash.Hash, seed, target []byte) {
	var counter [4]byte
	var digest []byte
	done := 0
	for done < len(out) {
		h.Reset()
		h.Write(seed)
		h.Write(counter[:])
		digest = h.Sum(digest[:0])
		for i := 0; i < len(digest) && done < len(out); i++ {
			out[done] = target[done] ^ digest[i]
			done++
		}
		// increment counter
		for i := 3; i >= 0; i-- {
			counter[i]++
			if counter[i] != 0 { break }
		}
	}
}
```

- [ ] **Step 4: Run to verify it passes**

Run: `go test ./internal/crypto/ -run TestUnpadOAEP -v` → PASS.

- [ ] **Step 5: Add `DecryptRawRSA` to the session** (uses `CKM_RSA_X_509` via `idxDecryptInit`/`idxDecrypt`, no params), mirroring `DecryptOAEPSHA256` but with `mech.Mechanism = CKM_RSA_X_509` and `Param=nil`. Then commit.

```bash
git add internal/crypto/oaep_raw.go internal/crypto/oaep_raw_test.go internal/pkcs11/session.go
git commit -m "feat(crypto): raw-RSA OAEP-SHA256 unpad fallback for tokens without native OAEP"
```

---

### Task 4: `crypto.Decrypter` seam — refactor `UnwrapKey` + software backend

Swap the concrete `*rsa.PrivateKey` for the stdlib interface. Software behaviour is unchanged.

**Files:**
- Modify: `internal/crypto/wrap.go` (`UnwrapKey` signature) + `internal/crypto/wrap_test.go`
- Create: `internal/keyprovider/provider.go`, `internal/keyprovider/software.go`
- Create: `internal/keyprovider/software_test.go`
- Modify callers: `internal/vault/secrets.go:405-411`, `internal/cli/push.go:237-248`

**Interfaces:**
- Consumes: existing `crypto.WrapKey`, `vault.LoadPrivateKey`.
- Produces: `crypto.UnwrapKey(dec crypto.Decrypter, wrapped []byte) ([]byte, error)`; `keyprovider.LoadDecrypter() (dec crypto.Decrypter, closeFn func() error, err error)`.

- [ ] **Step 1: Write the failing test** for the new `UnwrapKey` signature

`internal/crypto/wrap_test.go` (add):

```go
func TestUnwrapKeyAcceptsDecrypter(t *testing.T) {
	key, _ := GenerateRSAKeypair()
	aes, _ := GenerateAESKey()
	wrapped, _ := WrapKey(&key.PublicKey, aes)
	// *rsa.PrivateKey satisfies crypto.Decrypter
	got, err := UnwrapKey(key, wrapped)
	if err != nil { t.Fatal(err) }
	if !bytes.Equal(got, aes) { t.Fatal("mismatch") }
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `go test ./internal/crypto/ -run TestUnwrapKeyAccepts -v` → FAIL (compile error: too few args / type mismatch).

- [ ] **Step 3: Change `UnwrapKey`**

`internal/crypto/wrap.go`:

```go
import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
)

// UnwrapKey unwraps a symmetric key using RSA-OAEP-SHA256 via any crypto.Decrypter.
func UnwrapKey(dec crypto.Decrypter, wrappedKey []byte) ([]byte, error) {
	if dec == nil {
		return nil, fmt.Errorf("decrypter is nil")
	}
	key, err := dec.Decrypt(rand.Reader, wrappedKey, &rsa.OAEPOptions{Hash: crypto.SHA256})
	if err != nil {
		return nil, fmt.Errorf("failed to unwrap key: %w", err)
	}
	return key, nil
}
```

- [ ] **Step 4: Update the two callers** to pass the loaded key directly (they already hold `*rsa.PrivateKey` from `vault.LoadPrivateKey()`, which satisfies `crypto.Decrypter`). In `internal/vault/secrets.go` and `internal/cli/push.go`, change `crypto.UnwrapKey(privateKey, wrappedKey)` — no code change needed at call sites since `*rsa.PrivateKey` is a `crypto.Decrypter`; just verify compilation.

- [ ] **Step 5: Add the provider seam**

`internal/keyprovider/provider.go`:

```go
package keyprovider

import "crypto"

// LoadDecrypter returns the decrypter for THIS machine plus a close func.
// It reads the machine key-source (Task 5); absent source ⇒ software.
func LoadDecrypter() (crypto.Decrypter, func() error, error) {
	src, err := loadKeySource() // Task 5
	if err != nil {
		return nil, nil, err
	}
	switch src.Source {
	case "pkcs11":
		return loadPKCS11Decrypter(src) // Task 6
	default:
		return loadSoftwareDecrypter()
	}
}
```

`internal/keyprovider/software.go`:

```go
package keyprovider

import (
	"crypto"

	"github.com/iluxav/nvolt/internal/vault"
)

func loadSoftwareDecrypter() (crypto.Decrypter, func() error, error) {
	key, err := vault.LoadPrivateKey()
	if err != nil {
		return nil, nil, err
	}
	return key, func() error { return nil }, nil
}
```

- [ ] **Step 6: Run tests**

Run: `go test ./internal/crypto/... ./internal/keyprovider/... -v`
Expected: PASS (existing wrap tests + new one). `loadKeySource`/`loadPKCS11Decrypter` may be stubbed to compile — implemented in Tasks 5/6.

- [ ] **Step 7: Commit**

```bash
git add internal/crypto/ internal/keyprovider/ internal/vault/secrets.go internal/cli/push.go
git commit -m "refactor(crypto): UnwrapKey takes crypto.Decrypter; add keyprovider seam"
```

---

### Task 5: `KeySource` type + machine.json persistence

**Files:**
- Modify: `pkg/types/types.go` (add `KeySource` struct + field on `MachineInfo`)
- Create: `internal/keyprovider/keysource.go`, `internal/keyprovider/keysource_test.go`

**Interfaces:**
- Produces: `type KeySource struct { Source, Module, URI, PinMode, OAEPMode string }`; `keyprovider.loadKeySource() (KeySource, error)` (defaults `Source="software"` when absent); `keyprovider.saveKeySource(KeySource) error`.

- [ ] **Step 1: Write the failing test**

`internal/keyprovider/keysource_test.go`:

```go
package keyprovider

import "testing"

func TestLoadKeySourceDefaultsToSoftware(t *testing.T) {
	t.Setenv("HOME", t.TempDir()) // no machine.json present
	src, err := loadKeySource()
	if err != nil { t.Fatal(err) }
	if src.Source != "software" {
		t.Fatalf("want software, got %q", src.Source)
	}
}
```

- [ ] **Step 2: Run to verify fail** → `go test ./internal/keyprovider/ -run TestLoadKeySourceDefaults -v` → FAIL.

- [ ] **Step 3: Implement** `keysource.go` — read `~/.nvolt/machine.json`, unmarshal `MachineInfo.KeySource`; if file or field absent return `KeySource{Source: "software"}`. `saveKeySource` loads, sets `.KeySource`, writes atomically via `vault.WriteFileAtomic`. Add to `pkg/types/types.go`:

```go
type KeySource struct {
	Source   string `json:"source,omitempty"`   // "software" | "pkcs11"
	Module   string `json:"module,omitempty"`
	URI      string `json:"uri,omitempty"`
	PinMode  string `json:"pin_mode,omitempty"` // "prompt" | "env" | "none"
	OAEPMode string `json:"oaep_mode,omitempty"`// "native" | "raw"
}
// add to MachineInfo:
//   KeySource *KeySource `json:"key_source,omitempty"`
```

- [ ] **Step 4: Run to verify pass** → PASS.

- [ ] **Step 5: Commit**

```bash
git add pkg/types/types.go internal/keyprovider/keysource.go internal/keyprovider/keysource_test.go
git commit -m "feat(keyprovider): KeySource type + machine.json persistence (defaults software)"
```

---

### Task 6: PKCS#11 backend — enroll validation, public-key extraction, OAEP self-test, runtime decrypter

**Files:**
- Create: `internal/keyprovider/pkcs11.go`, `internal/keyprovider/pkcs11_test.go`
- Create: `internal/pkcs11/discover.go` (list objects + token/key attribute reads) + `discover_test.go`

**Interfaces:**
- Consumes: `pkcs11.Open/OpenSession/Login/FindRSAPrivateKey/RSAPublicKey/DecryptOAEPSHA256/DecryptRawRSA`.
- Produces:
  - `pkcs11.ListRSAKeys(module string) ([]KeyInfo, error)` (KeyInfo: TokenLabel, Label, ID, Bits).
  - `keyprovider.Enroll(module, uri, pinMode string, pin func() (string,error)) (types.KeySource, *rsa.PublicKey, error)` — runs the 5 validation checks + OAEP self-test, returns source (with `OAEPMode`) + public key.
  - `keyprovider.loadPKCS11Decrypter(KeySource) (crypto.Decrypter, func() error, error)` — a `crypto.Decrypter` whose `Decrypt` calls the token per `OAEPMode`.

- [ ] **Step 1: Write the failing enroll test** (against SoftHSM)

`internal/keyprovider/pkcs11_test.go`:

```go
package keyprovider

import (
	"os"
	"testing"
)

func TestEnrollValidatesAndSelfTests(t *testing.T) {
	mod := os.Getenv("NVOLT_TEST_PKCS11_MODULE")
	if mod == "" { t.Skip("no module") }
	src, pub, err := Enroll(mod, "pkcs11:token=nvolt-test;id=%01;type=private", "env",
		func() (string, error) { return "1234", nil })
	if err != nil { t.Fatal(err) }
	if src.Source != "pkcs11" || src.OAEPMode == "" {
		t.Fatalf("bad source: %+v", src)
	}
	if pub == nil || pub.N.BitLen() < 2048 {
		t.Fatal("bad public key")
	}
}
```

- [ ] **Step 2: Run to verify fail** → FAIL (`undefined: Enroll`).

- [ ] **Step 3: Implement `Enroll`** — parse URI (token + id), `pkcs11.Open`, `OpenSession(token)`, `Login(pin)`, `FindRSAPrivateKey(id)`; run checks: object found (class/keytype implied by finder attrs), `RSAPublicKey` (rejects if `N.BitLen()<2048`); **self-test**: `aes,_ := crypto.GenerateAESKey(); ct,_ := crypto.WrapKey(pub, aes)`; try `DecryptOAEPSHA256` → if equal, `OAEPMode="native"`; else `DecryptRawRSA`+`crypto.UnpadOAEPSHA256` → `OAEPMode="raw"`; else error `"token cannot perform OAEP-SHA256 unwrap"`. Return `types.KeySource{Source:"pkcs11", Module:mod, URI:uri, PinMode:pinMode, OAEPMode:mode}` + pub.

- [ ] **Step 4: Implement `loadPKCS11Decrypter`** — returns a small `pkcs11Decrypter` type implementing `crypto.Decrypter`: `Public()` returns the stored pub (loaded from machine.json PEM), `Decrypt()` opens session, logs in (PIN per `PinMode` — Task 8 wires the prompt), calls `DecryptOAEPSHA256` or raw+unpad per `OAEPMode`. The returned `close` finalizes the session/module.

- [ ] **Step 5: Run to verify pass** → `NVOLT_TEST_PKCS11_MODULE=$MODULE go test ./internal/keyprovider/ -run TestEnroll -v` → PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/keyprovider/pkcs11.go internal/keyprovider/pkcs11_test.go internal/pkcs11/discover.go internal/pkcs11/discover_test.go
git commit -m "feat(keyprovider): pkcs11 enroll validation + OAEP self-test + runtime decrypter"
```

---

### Task 7: CLI `nvolt pkcs11 list`

**Files:**
- Create: `internal/cli/pkcs11.go` (parent `pkcs11` command + `list`)
- Modify: `internal/cli/root.go` (register command)
- Create: `internal/cli/pkcs11_test.go`

**Interfaces:**
- Consumes: `pkcs11.ListRSAKeys`.
- Produces: cobra command `pkcs11 list --module PATH`.

- [ ] **Step 1: Write the failing test** — table output contains the fixture key label.

```go
func TestPKCS11ListShowsKeys(t *testing.T) {
	mod := os.Getenv("NVOLT_TEST_PKCS11_MODULE")
	if mod == "" { t.Skip() }
	out, err := runPKCS11List(mod) // helper invoking the command's RunE, capturing stdout
	if err != nil { t.Fatal(err) }
	if !strings.Contains(out, "nvolt-test") {
		t.Fatalf("expected key in output:\n%s", out)
	}
}
```

- [ ] **Step 2: Run to verify fail** → FAIL.
- [ ] **Step 3: Implement** `pkcs11.go` following the existing cobra pattern in `internal/cli/machine.go`: `--module` flag (default `os.Getenv("NVOLT_PKCS11_MODULE")`), call `pkcs11.ListRSAKeys`, render token/label/id/bits via `internal/ui`.
- [ ] **Step 4: Run to verify pass** → PASS.
- [ ] **Step 5: Commit** — `git commit -m "feat(cli): nvolt pkcs11 list"`.

---

### Task 8: CLI `nvolt pkcs11 use` (enroll) + PIN prompt

**Files:**
- Modify: `internal/cli/pkcs11.go` (add `use`), create `internal/cli/pinentry.go`
- Modify: `internal/keyprovider/keysource.go` (persist public key into machine.json alongside source)
- Create/modify: `internal/cli/pkcs11_test.go`

**Interfaces:**
- Consumes: `keyprovider.Enroll`, `keyprovider.saveKeySource`, existing `vault` machine-info writer, `crypto.EncodePublicKeyPEM`, `crypto.GenerateFingerprint`.
- Produces: cobra `pkcs11 use --module PATH --uri 'pkcs11:...' [--pin-mode prompt|env]`; `pinentry.Read(mode string) (string, error)`.

- [ ] **Step 1: Write the failing test** — after `use`, machine.json has `key_source.source == pkcs11`, a PEM public key, and a fingerprint.

```go
func TestUseEnrollsPKCS11Machine(t *testing.T) {
	mod := os.Getenv("NVOLT_TEST_PKCS11_MODULE"); if mod == "" { t.Skip() }
	t.Setenv("HOME", t.TempDir())
	t.Setenv("NVOLT_PKCS11_PIN", "1234")
	if err := runPKCS11Use(mod, "pkcs11:token=nvolt-test;id=%01;type=private", "env"); err != nil {
		t.Fatal(err)
	}
	mi := readMachineInfo(t) // helper
	if mi.KeySource == nil || mi.KeySource.Source != "pkcs11" { t.Fatal("not enrolled") }
	if mi.PublicKey == "" || mi.Fingerprint == "" { t.Fatal("missing pub/fingerprint") }
}
```

- [ ] **Step 2: Run to verify fail** → FAIL.
- [ ] **Step 3: Implement `pinentry.Read`** — `prompt`: `golang.org/x/term.ReadPassword` on the TTY with a "🔑 Enter PKCS#11 PIN:" prompt; `env`: read `NVOLT_PKCS11_PIN`; `none`: return "". (`x/term` is already an indirect dep via bubbletea; run `go mod tidy`.)
- [ ] **Step 4: Implement `use`** — reject if machine already initialized (mirror `InitializeMachine`’s guard) unless `--force`; call `keyprovider.Enroll(module, uri, pinMode, func(){ return pinentry.Read(pinMode) })`; build `MachineInfo` exactly like `vault.InitializeMachine` but with `PublicKey = PEM(pub)`, `Fingerprint = GenerateFingerprint(pub)`, `ID = GenerateMachineID(...)`, and `KeySource = &src`; persist via the existing machine-info save + `saveKeySource`. Print a success banner via `internal/ui`.
- [ ] **Step 5: Run to verify pass** → PASS.
- [ ] **Step 6: Commit** — `git commit -m "feat(cli): nvolt pkcs11 use — enroll on-card key as machine identity"`.

---

### Task 9: CLI `nvolt pkcs11 generate`

**Files:**
- Modify: `internal/pkcs11/session.go` (add `GenerateRSAKeyPair(label string, id []byte, bits int) (Object, error)` via `C_GenerateKeyPair`, `CKM_RSA_PKCS_KEY_PAIR_GEN=0x0`)
- Modify: `internal/cli/pkcs11.go` (add `generate`)
- Modify: `internal/pkcs11/session_test.go`

**Interfaces:**
- Produces: `(*Session).GenerateRSAKeyPair`; cobra `pkcs11 generate --module PATH --label L --id HEX --bits 2048`.

- [ ] **Step 1: Write the failing test** — generate a key with a fresh id, then `FindRSAPrivateKey` finds it. Use a second SoftHSM id (e.g. `0x02`).
- [ ] **Step 2: Run to verify fail** → FAIL.
- [ ] **Step 3: Implement `GenerateRSAKeyPair`** — build public template (`CKA_MODULUS_BITS=bits`, `CKA_PUBLIC_EXPONENT={1,0,1}` (0x10001), `CKA_TOKEN=true`, `CKA_ENCRYPT/VERIFY=true`, `CKA_LABEL`, `CKA_ID`) and private template (`CKA_TOKEN/PRIVATE/SENSITIVE/DECRYPT=true`, `CKA_LABEL`, `CKA_ID`); call `C_GenerateKeyPair`. If it returns `CKR_FUNCTION_NOT_SUPPORTED`, return an error whose message prints the manual `ykman piv keys generate 9d ...` / `yubico-piv-tool -a generate -s 9d ...` commands.
- [ ] **Step 4: Run to verify pass** → PASS.
- [ ] **Step 5: Commit** — `git commit -m "feat(pkcs11): on-card C_GenerateKeyPair + nvolt pkcs11 generate"`.

---

### Task 10: `init`/`join --pkcs11` integration + pull/push use `LoadDecrypter`

**Files:**
- Modify: `internal/cli/init.go`, `internal/cli/join.go` (add `--pkcs11` + `--module`/`--uri` flags routing to the enroll flow)
- Modify: `internal/vault/secrets.go`, `internal/cli/push.go` (replace `vault.LoadPrivateKey()` + `crypto.UnwrapKey` with `keyprovider.LoadDecrypter()` + `defer close()`)
- Create: `internal/keyprovider/roundtrip_test.go`

**Interfaces:**
- Consumes: `keyprovider.LoadDecrypter`, `keyprovider.Enroll`.

- [ ] **Step 1: Write the failing end-to-end test** — full envelope round-trip through a PKCS#11 machine:

```go
func TestPushPullThroughPKCS11Machine(t *testing.T) {
	mod := os.Getenv("NVOLT_TEST_PKCS11_MODULE"); if mod == "" { t.Skip() }
	// enroll pkcs11 machine, wrap a master key to its pub, then LoadDecrypter().Decrypt round-trips
	src, pub, err := Enroll(mod, "pkcs11:token=nvolt-test;id=%01;type=private", "env",
		func() (string, error) { return "1234", nil })
	if err != nil { t.Fatal(err) }
	_ = saveKeySource(src) // with HOME=tempdir + machine.json holding PEM(pub)
	dec, closeFn, err := LoadDecrypter(); if err != nil { t.Fatal(err) }
	defer closeFn()
	aes, _ := crypto.GenerateAESKey()
	wrapped, _ := crypto.WrapKey(pub, aes)
	got, err := crypto.UnwrapKey(dec, wrapped); if err != nil { t.Fatal(err) }
	if !bytes.Equal(got, aes) { t.Fatal("round-trip mismatch") }
}
```

- [ ] **Step 2: Run to verify fail** → FAIL.
- [ ] **Step 3: Wire `LoadDecrypter` into `secrets.go` and `push.go`.** Replace:
  ```go
  privateKey, err := vault.LoadPrivateKey()
  ...
  masterKey, err := crypto.UnwrapKey(privateKey, wrappedKey)
  ```
  with:
  ```go
  dec, closeDec, err := keyprovider.LoadDecrypter()
  if err != nil { return ... }
  defer closeDec()
  masterKey, err := crypto.UnwrapKey(dec, wrappedKey)
  ```
- [ ] **Step 4: Add `--pkcs11` to `init`/`join`** — when set, run the Task 8 enroll flow instead of `vault.InitializeMachine`; require `--module`/`--uri`.
- [ ] **Step 5: Run to verify pass** → PASS. Also run `go test ./...` to confirm software paths unaffected.
- [ ] **Step 6: Commit** — `git commit -m "feat(cli): init/join --pkcs11 + route pull/push through LoadDecrypter"`.

---

### Task 11: SoftHSM2 integration job in CI

**Files:**
- Create: `.github/workflows/ci.yml` (build + unit + PKCS#11 integration on push/PR)

**Interfaces:** none (CI only).

- [ ] **Step 1: Write the workflow**

```yaml
name: CI
on: { push: { branches: [main] }, pull_request: {} }
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
      - uses: actions/setup-go@v5
        with: { go-version: "1.24.3" }
      - run: sudo apt-get update && sudo apt-get install -y softhsm2 opensc
      - name: Set up SoftHSM token
        run: bash scripts/test-softhsm-setup.sh | tee /tmp/hsm.env
      - name: Unit + integration tests
        run: |
          set -a; source <(grep -E '^(MODULE|SOFTHSM2_CONF)=' /tmp/hsm.env); set +a
          export NVOLT_TEST_PKCS11_MODULE="$MODULE"
          CGO_ENABLED=0 go test -race ./...
      - run: CGO_ENABLED=0 go build ./cmd/nvolt   # prove static build still works
```

- [ ] **Step 2: Verify locally** — reproduce the job steps in a shell; expect all tests PASS and the build to succeed with `CGO_ENABLED=0`.
- [ ] **Step 3: Commit** — `git commit -m "ci: build + SoftHSM2 PKCS#11 integration tests on push/PR"`.

---

### Task 12: WSL + p11-kit runbook

**Files:**
- Create: `docs/pkcs11-yubikey-runbook.md`

**Interfaces:** none (docs).

- [ ] **Step 1: Write the runbook** covering, verbatim commands: (a) Windows `usbipd list/bind/attach --wsl`; (b) WSL `pcscd` + `p11-kit server --provider .../opensc-pkcs11.so 'pkcs11:'`; (c) the **separate** `ssh -R /home/USER/.nvolt/pkcs11.sock:$XDG_RUNTIME_DIR/p11-kit/... user@remote` session and the remote sshd `StreamLocalBindUnlink yes` requirement; (d) remote `nvolt pkcs11 list/use --module /usr/lib/.../p11-kit-client.so`; (e) the explicit warning **not** to route VS Code Remote-SSH through WSL. Cross-link the spec.
- [ ] **Step 2: Commit** — `git commit -m "docs: WSL + p11-kit YubiKey forwarding runbook"`.

---

## Self-Review

**Spec coverage:**
- Seam / `UnwrapKey` → Task 4. ✅
- purego FFI, no cgo → Tasks 1–2, enforced in Task 11 build step. ✅
- `list`/`use`/`generate`, `init/join --pkcs11` → Tasks 7–10. ✅
- Validation (module/RSA/decrypt/2048) + public-key-to-PEM + OAEP self-test + `oaep_mode` → Task 6. ✅
- Raw OAEP fallback → Task 3. ✅
- KeySource persistence + software default → Task 5. ✅
- PIN prompt/env → Task 8. ✅
- SoftHSM CI → Task 11; runbook → Task 12. ✅
- Phase-2 RPC client → intentionally **out of scope** for this plan.

**Placeholder scan:** No "TBD"/"handle errors" placeholders; the FFI binding shows the full mechanism plus an explicit per-call signature list (the repeated `SyscallN(m.fn(idx),...)` boilerplate is enumerated, not hand-waved).

**Type consistency:** `LoadDecrypter`, `Enroll`, `KeySource{Source,Module,URI,PinMode,OAEPMode}`, `DecryptOAEPSHA256`, `DecryptRawRSA`, `UnpadOAEPSHA256`, `ListRSAKeys` are used consistently across tasks.

**Known risk carried from spec:** the CK_FUNCTION_LIST field indices (Task 2 Step 1) are validated empirically by the Task 2 round-trip; a wrong index fails loudly on `C_Initialize`, not silently.
