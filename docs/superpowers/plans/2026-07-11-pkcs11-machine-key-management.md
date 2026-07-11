# PKCS#11 Machine-Key Management Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make a PKCS#11 hardware key a first-class citizen in nvolt's machine-key management: register machines from an existing public key, relocate an existing key between software/hardware backing, import a key onto a token, remove the redundant `pkcs11 use`, unify flag naming, and quiet default output.

**Architecture:** All work is in `internal/cli` and `internal/pkcs11`, building on the existing `crypto.Decrypter` seam (`keyprovider.LoadDecrypter` switches on `key_source.source`). New CLI commands reuse `keyprovider.Enroll` (self-test + KeySource), the `resolveEnrollTarget` wizard, the packed-`CK_ATTRIBUTE` marshaling (`attr`/`packTemplate`, ABI-correct on Windows), and `internal/crypto` PEM helpers. No new dependencies.

**Tech Stack:** Go 1.22 (module `github.com/iluxav/nvolt`), cobra, `github.com/ebitengine/purego` (cgo-free PKCS#11), SoftHSM2 for integration tests.

## Global Constraints

- Target branch: **`windows-abi-integrated`**. Build `go` via `/usr/local/go/bin`.
- **`CGO_ENABLED=0` static build must be preserved**; all six targets cross-compile (`linux/amd64`, `linux/arm64`, `darwin/amd64`, `darwin/arm64`, `windows/amd64`, `windows/arm64`).
- Tests run with **`-vet=off`** (pre-existing non-constant-format-string vet warnings in unrelated files). SoftHSM integration tests are gated on `NVOLT_TEST_PKCS11_MODULE=/usr/lib/softhsm/libsofthsm2.so` and self-provision via `internal/hsmtest.Provision(t)`.
- **RSA keys must be ≥ 2048 bits** (mirror `keyprovider/pkcs11.go:89`: `if pub.N.BitLen() < 2048 { error }`).
- **Never delete or overwrite a user's key file.** Where nvolt would orphan a software `private_key.pem`, it prints an at-Info notice instead.
- **Flag naming rule:** a PKCS#11 flag that appears on a general command (`init`, `join`, `machine add`, `rebind`) uses the `--pkcs11-*` prefix on *every* command it appears on; flags confined to the `pkcs11` group (`--token`/`--label`/`--id`) and generic key-file inputs (`--pubkey`/`--privkey`) stay bare.
- Reuse the packed-attribute marshaling: build `[]attr{{typ, val}}` (CK_ULONG values via `encodeCKULong`, byte values as-is), `packTemplate(attrs)`, call through `purego.SyscallN(s.m.fn(idx...), ...)` with `runtime.KeepAlive`. Model on `Session.GenerateRSAKeyPair` (`internal/pkcs11/session.go:289`).

## File Structure

| File | Responsibility | Change |
|---|---|---|
| `internal/pkcs11/types.go` | Cryptoki constants | Add `CKA_PRIVATE_EXPONENT`, `CKA_PRIME_1/2`, `CKA_EXPONENT_1/2`, `CKA_COEFFICIENT` |
| `internal/pkcs11/cryptoki.go` | Function-pointer indices | Add `idxCreateObject = 20` |
| `internal/pkcs11/session.go` | Session ops | Add `ImportRSAPrivateKey(label, id, priv)` |
| `internal/cli/pkcs11.go` | `pkcs11` command group | Rename shared flags; add `import`; remove `use`; add `ReadTokenPublicKey`; verbosity |
| `internal/cli/init.go` | init/join shared enroll flags | Rename to `--pkcs11-*` |
| `internal/cli/machine.go` | `machine add` | Add `--pubkey`/`--pkcs11` sources; verbosity |
| `internal/cli/rebind.go` (new) | `nvolt rebind` command | Non-destructive backing swap |
| `internal/cli/machine_setup.go` | enroll orchestration | Orphan-key cleanup → inform-not-delete |
| `internal/cli/root.go` | command registration | Register `rebind` |
| `README.md` | docs | Flag renames; `rebind`/`import` usage; rotation flow |

---

### Task 1: Rename shared PKCS#11 flags to `--pkcs11-*`

**Files:**
- Modify: `internal/cli/init.go` (`addPKCS11EnrollFlags`, `pkcs11OptsFromFlags`)
- Modify: `internal/cli/pkcs11.go` (list/use/generate flag registrations)
- Test: `internal/cli/flagname_test.go` (create)

**Interfaces:**
- Produces: init/join carry `--pkcs11-module`, `--pkcs11-uri`, `--pkcs11-pin-mode` (toggle stays `--pkcs11`); `pkcs11 list/use/generate` carry `--pkcs11-module`/`--pkcs11-pin-mode`, with `generate`'s `--token/--label/--id/--bits` unchanged.

- [ ] **Step 1: Write the failing test** — `internal/cli/flagname_test.go`:

```go
package cli

import (
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func flagNames(c *cobra.Command) map[string]bool {
	m := map[string]bool{}
	c.Flags().VisitAll(func(f *pflagFlag) { m[f.Name] = true })
	return m
}

func TestSharedPKCS11FlagsArePrefixed(t *testing.T) {
	// init & join expose the prefixed shared flags, not the bare ones.
	for _, c := range []*cobra.Command{initCmd, joinCmd} {
		names := map[string]bool{}
		c.Flags().VisitAll(func(f *pflag.Flag) { names[f.Name] = true })
		for _, want := range []string{"pkcs11", "pkcs11-module", "pkcs11-uri", "pkcs11-pin-mode"} {
			if !names[want] {
				t.Errorf("%s missing --%s", c.Name(), want)
			}
		}
		for _, bare := range []string{"module", "uri", "pin-mode"} {
			if names[bare] {
				t.Errorf("%s still has bare --%s", c.Name(), bare)
			}
		}
	}
}
```

Replace the `flagNames` helper stub above with the real import — use `pflag`:
delete the `flagNames`/`pflagFlag` lines and add `import "github.com/spf13/pflag"` so the `pflag.Flag` reference in the loop compiles. Final imports: `strings` may be dropped if unused.

- [ ] **Step 2: Run test to verify it fails**

Run: `PATH=$PATH:/usr/local/go/bin go test -vet=off ./internal/cli/ -run TestSharedPKCS11FlagsArePrefixed -v`
Expected: FAIL — `init missing --pkcs11-module` (flags are still bare).

- [ ] **Step 3: Rename in `init.go`** — in `addPKCS11EnrollFlags` change the three `String(...)` flag names, and in `pkcs11OptsFromFlags` change the three `GetString(...)` keys:

```go
// addPKCS11EnrollFlags
cmd.Flags().String("pkcs11-module", "", "Path to PKCS#11 module (.so) (with --pkcs11); autodetected if omitted")
cmd.Flags().String("pkcs11-uri", "", "PKCS#11 URI of the RSA key to enroll (with --pkcs11)")
cmd.Flags().String("pkcs11-pin-mode", "prompt", "How to obtain the PIN: prompt, env, or none (with --pkcs11)")
// pkcs11OptsFromFlags
flagModule, _ := cmd.Flags().GetString("pkcs11-module")
flagURI, _ := cmd.Flags().GetString("pkcs11-uri")
pinMode, _ := cmd.Flags().GetString("pkcs11-pin-mode")
```

- [ ] **Step 4: Rename in `pkcs11.go`** — in the `init()` flag registrations, rename `--module`→`--pkcs11-module` and `--pin-mode`→`--pkcs11-pin-mode` on `pkcs11ListCmd`, `pkcs11UseCmd`, `pkcs11GenerateCmd` (leave `--token`/`--label`/`--id`/`--bits` bare). Also rename `--uri`→`--pkcs11-uri` on `pkcs11UseCmd`. Update the matching `pkcs11.ResolveModulePath` call sites only if they read a renamed var (they read the Go var, not the flag string, so no change).

- [ ] **Step 5: Run test to verify it passes**

Run: `PATH=$PATH:/usr/local/go/bin go test -vet=off ./internal/cli/ -run TestSharedPKCS11FlagsArePrefixed -v`
Expected: PASS.

- [ ] **Step 6: Update README + cross-compile check**

Update `README.md` PKCS#11 examples to the `--pkcs11-*` names. Then:
Run: `PATH=$PATH:/usr/local/go/bin bash -c 'for t in linux/amd64 windows/amd64; do GOOS=${t%/*} GOARCH=${t#*/} CGO_ENABLED=0 go build -o /dev/null ./cmd/nvolt && echo ok $t; done'`
Expected: `ok linux/amd64` / `ok windows/amd64`.

- [ ] **Step 7: Commit**

```bash
git add internal/cli/init.go internal/cli/pkcs11.go internal/cli/flagname_test.go README.md
git commit -m "feat(pkcs11): prefix shared flags --pkcs11-module/-uri/-pin-mode on general + pkcs11 commands"
```

---

### Task 2: `pkcs11 import` via `C_CreateObject`

**Files:**
- Modify: `internal/pkcs11/types.go` (attribute constants)
- Modify: `internal/pkcs11/cryptoki.go` (`idxCreateObject = 20`)
- Modify: `internal/pkcs11/session.go` (`ImportRSAPrivateKey`)
- Modify: `internal/cli/pkcs11.go` (`pkcs11 import` command + `runPKCS11Import`)
- Test: `internal/pkcs11/session_test.go`, `internal/cli/pkcs11_test.go`

**Interfaces:**
- Consumes: `attr`, `packTemplate`, `encodeCKULong`, `newCKULongOut`, `rvOf`, `s.m.fn`, `s.handle` (all in `internal/pkcs11`); `crypto.DecodePrivateKeyPEM`.
- Produces: `func (s *Session) ImportRSAPrivateKey(label string, id []byte, priv *rsa.PrivateKey) (Object, error)`.

- [ ] **Step 1: Add attribute constants** — in `internal/pkcs11/types.go` after `CKA_PUBLIC_EXPONENT`:

```go
CKA_PRIVATE_EXPONENT uintptr = 0x00000123
CKA_PRIME_1          uintptr = 0x00000124
CKA_PRIME_2          uintptr = 0x00000125
CKA_EXPONENT_1       uintptr = 0x00000126
CKA_EXPONENT_2       uintptr = 0x00000127
CKA_COEFFICIENT      uintptr = 0x00000128
```

And in `internal/pkcs11/cryptoki.go` add to the index block:

```go
idxCreateObject = 20 // C_CreateObject
```

- [ ] **Step 2: Write the failing test** — append to `internal/pkcs11/session_test.go` (uses the same SoftHSM harness other session tests use; find how they open a session and copy that setup — look for an existing `func Test...` that calls `Provision`/opens a `*Session`):

```go
func TestImportRSAPrivateKeyRoundTrip(t *testing.T) {
	sess := openTestSession(t) // reuse the helper the other session tests use
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sess.ImportRSAPrivateKey("imported", []byte{0x09}, priv); err != nil {
		t.Fatalf("import: %v", err)
	}
	// The imported private key is findable and decrypts an OAEP round-trip.
	obj, err := sess.FindPrivateKeyByID([]byte{0x09}) // use the finder the tests already use
	if err != nil {
		t.Fatalf("find imported key: %v", err)
	}
	ct, _ := rsa.EncryptOAEP(sha256.New(), rand.Reader, &priv.PublicKey, []byte("hi"), nil)
	pt, err := sess.DecryptOAEPSHA256(obj, ct)
	if err != nil {
		t.Fatalf("decrypt with imported key: %v", err)
	}
	if string(pt) != "hi" {
		t.Fatalf("got %q", pt)
	}
}
```

Add imports `crypto/rand`, `crypto/rsa`, `crypto/sha256`. Match the finder/session helper names to whatever `session_test.go` already defines (read the file first); if no `openTestSession` helper exists, inline the same setup the neighboring test uses.

- [ ] **Step 3: Run test to verify it fails**

Run: `NVOLT_TEST_PKCS11_MODULE=/usr/lib/softhsm/libsofthsm2.so PATH=$PATH:/usr/local/go/bin go test -vet=off ./internal/pkcs11/ -run TestImportRSAPrivateKeyRoundTrip -v`
Expected: FAIL — `sess.ImportRSAPrivateKey undefined`.

- [ ] **Step 4: Implement `ImportRSAPrivateKey`** — in `internal/pkcs11/session.go`, mirroring `GenerateRSAKeyPair` (session.go:289) for the marshaling pattern:

```go
// ImportRSAPrivateKey creates a token (persistent) RSA private key object from
// priv via C_CreateObject. The key is marked CKA_DECRYPT so nvolt can unwrap
// with it. Returns the created object handle. Tokens that forbid PKCS#11 key
// import (e.g. YubiKey via OpenSC) return the token's error unchanged.
func (s *Session) ImportRSAPrivateKey(label string, id []byte, priv *rsa.PrivateKey) (Object, error) {
	priv.Precompute()
	bytesOf := func(i *big.Int) []byte { return i.Bytes() }
	eBytes := big.NewInt(int64(priv.E)).Bytes()

	boolAttr := func(t uintptr) attr { return attr{typ: t, val: []byte{0x01}} }
	attrs := []attr{
		{typ: CKA_CLASS, val: encodeCKULong(CKO_PRIVATE_KEY)},
		{typ: CKA_KEY_TYPE, val: encodeCKULong(CKK_RSA)},
		boolAttr(CKA_TOKEN),
		boolAttr(CKA_PRIVATE),
		boolAttr(CKA_DECRYPT),
		{typ: CKA_LABEL, val: []byte(label)},
		{typ: CKA_MODULUS, val: bytesOf(priv.N)},
		{typ: CKA_PUBLIC_EXPONENT, val: eBytes},
		{typ: CKA_PRIVATE_EXPONENT, val: bytesOf(priv.D)},
		{typ: CKA_PRIME_1, val: bytesOf(priv.Primes[0])},
		{typ: CKA_PRIME_2, val: bytesOf(priv.Primes[1])},
		{typ: CKA_EXPONENT_1, val: bytesOf(priv.Precomputed.Dp)},
		{typ: CKA_EXPONENT_2, val: bytesOf(priv.Precomputed.Dq)},
		{typ: CKA_COEFFICIENT, val: bytesOf(priv.Precomputed.Qinv)},
	}
	if len(id) > 0 {
		attrs = append(attrs, attr{typ: CKA_ID, val: id})
	}
	tmpl := packTemplate(attrs)
	objHandle := newCKULongOut()
	rv, _, _ := purego.SyscallN(s.m.fn(idxCreateObject), s.handle,
		uintptr(tmpl.ptr()), tmpl.count(), uintptr(objHandle.ptr()))
	runtime.KeepAlive(tmpl)
	runtime.KeepAlive(objHandle)
	if code := rvOf(rv); code != CKR_OK {
		if code == CKR_FUNCTION_NOT_SUPPORTED {
			return 0, fmt.Errorf("C_CreateObject: %s: this token does not support PKCS#11 "+
				"key import; import the key with the device's own tool instead, e.g.:\n"+
				"  ykman piv keys import 9d key.pem", code)
		}
		return 0, fmt.Errorf("C_CreateObject: %s", code)
	}
	return objHandle.get(), nil
}
```

Add imports `math/big` to session.go if absent. Confirm `packTemplate` exposes `.ptr()`/`.count()` (GenerateRSAKeyPair uses them) — it does.

- [ ] **Step 5: Run test to verify it passes**

Run: `NVOLT_TEST_PKCS11_MODULE=/usr/lib/softhsm/libsofthsm2.so PATH=$PATH:/usr/local/go/bin go test -vet=off ./internal/pkcs11/ -run TestImportRSAPrivateKeyRoundTrip -v`
Expected: PASS.

- [ ] **Step 6: Add the `pkcs11 import` CLI command** — in `internal/cli/pkcs11.go`, add vars + command mirroring `pkcs11GenerateCmd`/`runPKCS11Generate` (pkcs11.go:495-515):

```go
var pkcs11ImportModule, pkcs11ImportToken, pkcs11ImportLabel, pkcs11ImportID, pkcs11ImportFile, pkcs11ImportPinMode string

var pkcs11ImportCmd = &cobra.Command{
	Use:   "import",
	Short: "Import an RSA private key onto a token (PKCS#11 C_CreateObject)",
	RunE: func(cmd *cobra.Command, args []string) error {
		module, err := pkcs11.ResolveModulePath(pkcs11ImportModule)
		if err != nil {
			return err
		}
		return runPKCS11Import(module, pkcs11ImportToken, pkcs11ImportLabel, pkcs11ImportID, pkcs11ImportFile, pkcs11ImportPinMode)
	},
}

func runPKCS11Import(module, token, label, idHex, keyFile, pinMode string) error {
	if token == "" || keyFile == "" {
		return fmt.Errorf("--token and --privkey are required")
	}
	pemData, err := os.ReadFile(keyFile)
	if err != nil {
		return fmt.Errorf("read %s: %w", keyFile, err)
	}
	priv, err := nvcrypto.DecodePrivateKeyPEM(pemData)
	if err != nil {
		return fmt.Errorf("parse private key: %w", err)
	}
	if priv.N.BitLen() < 2048 {
		return fmt.Errorf("RSA key is %d bits; minimum 2048 required", priv.N.BitLen())
	}
	id, err := hex.DecodeString(idHex)
	if err != nil {
		return fmt.Errorf("invalid --id hex %q: %w", idHex, err)
	}
	// Open a session on the token, log in, import. Reuse the session-open +
	// login helper that runPKCS11Generate uses (copy its module.Open/find-slot/
	// OpenSession/Login sequence verbatim, substituting ImportRSAPrivateKey for
	// GenerateRSAKeyPair).
	// ... (same open/login as runPKCS11Generate) ...
	if _, err := sess.ImportRSAPrivateKey(label, id, priv); err != nil {
		return err
	}
	ui.Success("Imported RSA key onto token %s", token)          // Info
	ui.Verbose("  Label: %s", label)                              // Verbose
	ui.Verbose("  ID: %x", id)
	return nil
}
```

Register it in `init()`: `pkcs11Cmd.AddCommand(pkcs11ImportCmd)` and flags `--pkcs11-module`, `--token`, `--label`, `--id`, `--privkey`, `--pkcs11-pin-mode`. Read `runPKCS11Generate` fully first and copy its session-open/login block verbatim into `runPKCS11Import`.

- [ ] **Step 7: Integration test the command** — append to `internal/cli/pkcs11_test.go`:

```go
func TestPKCS11ImportCreatesUsableKey(t *testing.T) {
	mod := hsmtest.Provision(t)
	t.Setenv("NVOLT_PKCS11_PIN", "1234")
	dir := t.TempDir()
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	pemBytes, _ := nvcrypto.EncodePrivateKeyPEM(priv)
	keyPath := filepath.Join(dir, "k.pem")
	os.WriteFile(keyPath, pemBytes, 0o600)

	if err := runPKCS11Import(mod, "nvolt-test", "imported", "09", keyPath, "env"); err != nil {
		t.Fatalf("import: %v", err)
	}
	// It now appears as an RSA key on the token.
	listing, err := pkcs11.ListTokensAndKeys(mod)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, tl := range listing {
		if tl.Label == "nvolt-test" && len(tl.Keys) > 0 {
			found = true
		}
	}
	if !found {
		t.Fatal("imported key not found on token")
	}
}
```

Run: `NVOLT_TEST_PKCS11_MODULE=/usr/lib/softhsm/libsofthsm2.so PATH=$PATH:/usr/local/go/bin go test -vet=off ./internal/cli/ -run TestPKCS11Import -v`
Expected: PASS.

- [ ] **Step 8: Windows cross-compile + commit**

Run: `PATH=$PATH:/usr/local/go/bin bash -c 'GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -o /dev/null ./cmd/nvolt && echo ok'`
Expected: `ok`.

```bash
git add internal/pkcs11/ internal/cli/pkcs11.go internal/cli/pkcs11_test.go
git commit -m "feat(pkcs11): add 'pkcs11 import' via C_CreateObject (RSA key import onto a token)"
```

---

### Task 3: `machine add` from an existing public key

**Files:**
- Modify: `internal/cli/pkcs11.go` (`ReadTokenPublicKey`)
- Modify: `internal/cli/machine.go` (`runMachineAdd` + source switch + `machineAddPublicKey`)
- Test: `internal/cli/machine_test.go`

**Interfaces:**
- Consumes: `resolveEnrollTarget`, `keyprovider.Enroll` (for the token pubkey — but reading a pubkey needs no PIN; see below), `nvcrypto.DecodePublicKeyPEM`, `isInteractive`.
- Produces: `func ReadTokenPublicKey(module, uri string) (*rsa.PublicKey, error)` in `internal/cli/pkcs11.go`; `machine add` accepts `--pubkey`/`--pkcs11 --pkcs11-module/--pkcs11-uri`.

- [ ] **Step 1: Extract `ReadTokenPublicKey`** — `keyprovider.Enroll` already reads the token's public key (it returns `*rsa.PublicKey`) but also runs a decrypt self-test needing a PIN. For `machine add` we only need the pubkey. Read `internal/keyprovider/pkcs11.go`'s `Enroll` to find the pubkey-read (it builds `*rsa.PublicKey` from `CKA_MODULUS`/`CKA_PUBLIC_EXPONENT` via `internal/pkcs11` discovery). Extract that read into an exported `keyprovider.ReadTokenPublicKey(module, uri string) (*rsa.PublicKey, error)` that opens a session (no login), finds the object by the URI's `id`, and reads its public components — reusing `internal/pkcs11`'s existing `findRSAObjects`/attribute reads. Then in `internal/cli/pkcs11.go` add a thin wrapper `func ReadTokenPublicKey(module, uri string) (*rsa.PublicKey, error) { return keyprovider.ReadTokenPublicKey(module, uri) }`.

- [ ] **Step 2: Write the failing test** — append to `internal/cli/machine_test.go`:

```go
func TestMachineAddFromPubkeyFile(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	// A local vault to register into.
	vaultDir := t.TempDir()
	mustInitLocalVault(t, vaultDir) // reuse the test helper that sets up a vault, or InitializeVaultDirectory + chdir
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	pubPEM, _ := nvcrypto.EncodePublicKeyPEM(&priv.PublicKey)
	pubPath := filepath.Join(t.TempDir(), "pub.pem")
	os.WriteFile(pubPath, pubPEM, 0o644)

	pub, err := machineAddPublicKey(machineAddSource{pubkeyFile: pubPath})
	if err != nil {
		t.Fatalf("machineAddPublicKey: %v", err)
	}
	if pub.N.Cmp(priv.N) != 0 {
		t.Fatal("wrong pubkey")
	}
}

func TestMachineAddPublicKeyRejectsSub2048(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 1024)
	pubPEM, _ := nvcrypto.EncodePublicKeyPEM(&priv.PublicKey)
	p := filepath.Join(t.TempDir(), "small.pem")
	os.WriteFile(p, pubPEM, 0o644)
	if _, err := machineAddPublicKey(machineAddSource{pubkeyFile: p}); err == nil {
		t.Fatal("expected sub-2048 rejection")
	}
}

func TestMachineAddSourceMutualExclusion(t *testing.T) {
	if _, err := machineAddPublicKey(machineAddSource{pubkeyFile: "a", pkcs11: true}); err == nil {
		t.Fatal("expected error when both --pubkey and --pkcs11 given")
	}
}
```

- [ ] **Step 3: Run test to verify it fails**

Run: `PATH=$PATH:/usr/local/go/bin go test -vet=off ./internal/cli/ -run TestMachineAdd -v`
Expected: FAIL — `machineAddPublicKey undefined`.

- [ ] **Step 4: Implement `machineAddSource` + `machineAddPublicKey`** — in `internal/cli/machine.go`:

```go
type machineAddSource struct {
	pubkeyFile string // --pubkey
	pkcs11     bool   // --pkcs11
	module     string // --pkcs11-module
	uri        string // --pkcs11-uri
}

// machineAddPublicKey returns the RSA public key to register, from the chosen
// source. Empty source => nil pubkey (caller generates a software key instead).
func machineAddPublicKey(s machineAddSource) (*rsa.PublicKey, error) {
	if s.pubkeyFile != "" && s.pkcs11 {
		return nil, fmt.Errorf("choose one of --pubkey or --pkcs11, not both")
	}
	var pub *rsa.PublicKey
	switch {
	case s.pubkeyFile != "":
		data, err := os.ReadFile(s.pubkeyFile)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", s.pubkeyFile, err)
		}
		if pub, err = nvcrypto.DecodePublicKeyPEM(data); err != nil {
			return nil, fmt.Errorf("parse public key: %w", err)
		}
	case s.pkcs11:
		module, uri, err := resolveEnrollTarget(s.module, s.uri)
		if err != nil {
			return nil, err
		}
		if pub, err = ReadTokenPublicKey(module, uri); err != nil {
			return nil, err
		}
	default:
		return nil, nil
	}
	if pub.N.BitLen() < 2048 {
		return nil, fmt.Errorf("RSA key is %d bits; minimum 2048 required", pub.N.BitLen())
	}
	return pub, nil
}
```

- [ ] **Step 5: Wire it into `runMachineAdd`** — read `runMachineAdd` (machine.go). Replace the unconditional `crypto.GenerateRSAKeypair()` block with:

```go
externalPub, err := machineAddPublicKey(addSource) // addSource built from the flags
if err != nil {
	return err
}
var publicKey *rsa.PublicKey
var privateKeyPEM []byte // stays nil for external sources
if externalPub != nil {
	publicKey = externalPub
} else {
	privateKey, err := crypto.GenerateRSAKeypair()
	if err != nil {
		return fmt.Errorf("failed to generate keypair: %w", err)
	}
	publicKey = &privateKey.PublicKey
	if privateKeyPEM, err = crypto.EncodePrivateKeyPEM(privateKey); err != nil {
		return fmt.Errorf("failed to encode private key: %w", err)
	}
}
```

Then guard the private-key printout so it only runs when `privateKeyPEM != nil` (external sources print `ui.Success("Registered %s", machineID)` + the grant hint instead, with no "save this private key" block). Add the flags in `machine.go`'s `init()`: `--pubkey`, `--pkcs11` (Bool), `--pkcs11-module`, `--pkcs11-uri`; build `addSource` from them in the `RunE`.

- [ ] **Step 6: Run test to verify it passes**

Run: `PATH=$PATH:/usr/local/go/bin go test -vet=off ./internal/cli/ -run TestMachineAdd -v`
Expected: PASS (all three).

- [ ] **Step 7: SoftHSM integration + commit** — append `TestMachineAddFromPKCS11` mirroring Task 2's list check (provision, `machineAddPublicKey(machineAddSource{pkcs11:true, module:mod, uri:"pkcs11:token=nvolt-test;id=%01;type=private"})`, assert the returned pubkey is non-nil and ≥2048). Run the cli package tests with the SoftHSM module set, then:

```bash
git add internal/cli/machine.go internal/cli/machine_test.go internal/cli/pkcs11.go internal/keyprovider/pkcs11.go
git commit -m "feat(machine): 'machine add --pubkey/--pkcs11' registers a machine from an existing public key"
```

---

### Task 4: `nvolt rebind` — non-destructive backing swap

**Files:**
- Create: `internal/cli/rebind.go`
- Modify: `internal/cli/root.go` (register command)
- Test: `internal/cli/rebind_test.go`

**Interfaces:**
- Consumes: `vault.LoadMachineInfo`, `vault.SaveMachineInfo`, `vault.GetHomePaths`, `nvcrypto.DecodePublicKeyPEM`, `nvcrypto.DecodePrivateKeyPEM`, `keyprovider.Enroll`, `resolveEnrollTarget`, `vault.WriteFileAtomic`, `vault.PrivateKeyPerm`.
- Produces: top-level `rebind` command.

- [ ] **Step 1: Write the failing test (pure gate logic)** — `internal/cli/rebind_test.go`. Factor the pubkey comparison into a pure helper so it is testable without hardware:

```go
package cli

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"
)

func TestSamePublicKey(t *testing.T) {
	a, _ := rsa.GenerateKey(rand.Reader, 2048)
	b, _ := rsa.GenerateKey(rand.Reader, 2048)
	if !samePublicKey(&a.PublicKey, &a.PublicKey) {
		t.Fatal("same key should match")
	}
	if samePublicKey(&a.PublicKey, &b.PublicKey) {
		t.Fatal("different keys should not match")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `PATH=$PATH:/usr/local/go/bin go test -vet=off ./internal/cli/ -run TestSamePublicKey -v`
Expected: FAIL — `samePublicKey undefined`.

- [ ] **Step 3: Implement `rebind.go`**:

```go
package cli

import (
	"crypto/rsa"
	"fmt"
	"os"

	nvcrypto "github.com/iluxav/nvolt/internal/crypto"
	"github.com/iluxav/nvolt/internal/keyprovider"
	"github.com/iluxav/nvolt/internal/pinentry"
	"github.com/iluxav/nvolt/internal/ui"
	"github.com/iluxav/nvolt/internal/vault"
	"github.com/spf13/cobra"
)

var rebindPKCS11, rebindSoftware bool
var rebindModule, rebindURI, rebindPinMode, rebindPrivkey string

var rebindCmd = &cobra.Command{
	Use:   "rebind",
	Short: "Re-point this machine's identity between software and hardware backing (same key)",
	RunE: func(cmd *cobra.Command, args []string) error {
		return runRebind()
	},
}

func samePublicKey(a, b *rsa.PublicKey) bool {
	return a != nil && b != nil && a.N.Cmp(b.N) == 0 && a.E == b.E
}

func runRebind() error {
	if rebindPKCS11 == rebindSoftware { // both or neither
		return fmt.Errorf("specify exactly one of --pkcs11 or --software")
	}
	if rebindPrivkey != "" && !rebindSoftware {
		return fmt.Errorf("--privkey is only valid with --software")
	}
	mi, err := vault.LoadMachineInfo()
	if err != nil {
		return fmt.Errorf("no machine identity yet; use 'nvolt init --pkcs11' or 'nvolt join --pkcs11': %w", err)
	}
	identityPub, err := nvcrypto.DecodePublicKeyPEM([]byte(mi.PublicKey))
	if err != nil {
		return fmt.Errorf("parse current identity public key: %w", err)
	}
	homePaths, err := vault.GetHomePaths()
	if err != nil {
		return err
	}

	if rebindPKCS11 {
		return rebindToHardware(mi, identityPub, homePaths)
	}
	return rebindToSoftware(mi, identityPub, homePaths)
}

func rebindToHardware(mi *types.MachineInfo, identityPub *rsa.PublicKey, homePaths *vault.HomePaths) error {
	module, uri, err := resolveEnrollTarget(rebindModule, rebindURI)
	if err != nil {
		return err
	}
	// Enroll runs the on-card self-test (proves the card can decrypt) and returns
	// the card's public key + KeySource.
	src, cardPub, err := keyprovider.Enroll(module, uri, rebindPinMode, func() (string, error) {
		return pinentry.Read(rebindPinMode)
	})
	if err != nil {
		return err
	}
	if !samePublicKey(cardPub, identityPub) {
		return fmt.Errorf("the token's public key doesn't match this machine's identity; " +
			"rebind only relocates the same key. To change to a different key, register it " +
			"with 'nvolt machine add' and re-grant")
	}
	mi.KeySource = &src
	if err := vault.SaveMachineInfo(homePaths.MachineInfo, mi); err != nil {
		return err
	}
	ui.Success("%s now backed by hardware (PKCS#11)", mi.ID)
	if vault.FileExists(homePaths.PrivateKey) {
		ui.Info("Your software private key is still at %s and can still decrypt your secrets.", homePaths.PrivateKey)
		ui.Info("Remove it once you've confirmed the card works: rm %s", homePaths.PrivateKey)
	}
	return nil
}

func rebindToSoftware(mi *types.MachineInfo, identityPub *rsa.PublicKey, homePaths *vault.HomePaths) error {
	// Ensure a matching software key is at the forced location.
	if rebindPrivkey != "" {
		data, err := os.ReadFile(rebindPrivkey)
		if err != nil {
			return fmt.Errorf("read %s: %w", rebindPrivkey, err)
		}
		priv, err := nvcrypto.DecodePrivateKeyPEM(data)
		if err != nil {
			return fmt.Errorf("parse private key: %w", err)
		}
		if !samePublicKey(&priv.PublicKey, identityPub) {
			return fmt.Errorf("that key's public key doesn't match this machine's identity")
		}
		if vault.FileExists(homePaths.PrivateKey) {
			existing, _ := os.ReadFile(homePaths.PrivateKey)
			ep, err := nvcrypto.DecodePrivateKeyPEM(existing)
			if err != nil || !samePublicKey(&ep.PublicKey, identityPub) {
				return fmt.Errorf("a different private key already exists at %s — remove or relocate it first", homePaths.PrivateKey)
			}
			// existing already matches: nothing to write.
		} else {
			pemBytes, _ := nvcrypto.EncodePrivateKeyPEM(priv)
			if err := vault.WriteFileAtomic(homePaths.PrivateKey, pemBytes, vault.PrivateKeyPerm); err != nil {
				return err
			}
		}
	} else {
		if !vault.FileExists(homePaths.PrivateKey) {
			return fmt.Errorf("no software key at %s; supply --privkey <path>", homePaths.PrivateKey)
		}
		existing, _ := os.ReadFile(homePaths.PrivateKey)
		ep, err := nvcrypto.DecodePrivateKeyPEM(existing)
		if err != nil || !samePublicKey(&ep.PublicKey, identityPub) {
			return fmt.Errorf("the key at %s doesn't match this machine's identity", homePaths.PrivateKey)
		}
	}
	mi.KeySource = &types.KeySource{Source: "software"}
	if err := vault.SaveMachineInfo(homePaths.MachineInfo, mi); err != nil {
		return err
	}
	ui.Success("%s now backed by software", mi.ID)
	return nil
}

func init() {
	rebindCmd.Flags().BoolVar(&rebindPKCS11, "pkcs11", false, "Re-point to a PKCS#11 token (sw->hw)")
	rebindCmd.Flags().BoolVar(&rebindSoftware, "software", false, "Re-point to a software key file (hw->sw)")
	rebindCmd.Flags().StringVar(&rebindModule, "pkcs11-module", "", "Path to PKCS#11 module (.so) (with --pkcs11)")
	rebindCmd.Flags().StringVar(&rebindURI, "pkcs11-uri", "", "PKCS#11 URI of the key (with --pkcs11)")
	rebindCmd.Flags().StringVar(&rebindPinMode, "pkcs11-pin-mode", "prompt", "How to obtain the PIN (with --pkcs11)")
	rebindCmd.Flags().StringVar(&rebindPrivkey, "privkey", "", "Private-key PEM to install (with --software)")
	rootCmd.AddCommand(rebindCmd)
}
```

Confirm the exact type names as you write: `types.MachineInfo`/`types.KeySource` (import `github.com/iluxav/nvolt/pkg/types`), and the real name of the home-paths struct returned by `vault.GetHomePaths()` (grep it — it is `*vault.HomePaths` or similar; use the real one). `vault.SaveMachineInfo(path, *MachineInfo)` and `vault.LoadMachineInfo() (*MachineInfo, error)` already exist.

- [ ] **Step 4: Run test to verify it passes**

Run: `PATH=$PATH:/usr/local/go/bin go test -vet=off ./internal/cli/ -run TestSamePublicKey -v`
Expected: PASS. Then `go build ./...` clean.

- [ ] **Step 5: Add a no-hardware behavior test** — append to `rebind_test.go` a test that sets `HOME` to a temp dir, writes a software identity via `vault.InitializeMachine("")`, sets `rebindSoftware=true` with no `--privkey`, and asserts `runRebind()` flips `key_source` to software using the existing on-disk key **without deleting it** (assert `vault.FileExists(homePaths.PrivateKey)` after). Reset the package-level `rebind*` vars at the top of the test. Run it; expect PASS.

- [ ] **Step 6: Cross-compile + commit**

Run: `PATH=$PATH:/usr/local/go/bin bash -c 'for t in linux/amd64 windows/amd64 darwin/arm64; do GOOS=${t%/*} GOARCH=${t#*/} CGO_ENABLED=0 go build -o /dev/null ./cmd/nvolt && echo ok $t; done'`
Expected: all ok.

```bash
git add internal/cli/rebind.go internal/cli/rebind_test.go internal/cli/root.go
git commit -m "feat: add 'nvolt rebind' — non-destructive sw<->hw backing swap (pubkey-gated)"
```

---

### Task 5: Remove `pkcs11 use`; enroll orphan-cleanup → inform

**Files:**
- Modify: `internal/cli/pkcs11.go` (delete `use` command, vars, `runPKCS11Use`; change orphan cleanup)
- Modify: `internal/cli/pkcs11_test.go` (remove/adjust `use` tests)
- Modify: `README.md` / `docs/pkcs11-yubikey-runbook.md` (replace `pkcs11 use` references)

**Interfaces:**
- Produces: `pkcs11` group has `list`, `generate`, `import` (no `use`).

- [ ] **Step 1: Delete the `use` command** — remove `pkcs11UseCmd`, `pkcs11UseModule/URI/PinMode` vars, `runPKCS11Use`, and the `pkcs11Cmd.AddCommand(pkcs11UseCmd)` + its flag registrations. `enrollPKCS11Machine` stays (used by init/join and `rebind` via `keyprovider.Enroll`).

- [ ] **Step 2: Change orphan cleanup to inform** — in `enrollPKCS11Machine` (pkcs11.go), replace the `SecureDeleteFile(homePaths.PrivateKey)` block with:

```go
if vault.FileExists(homePaths.PrivateKey) {
	ui.Info("A software private key remains at %s; it can still decrypt your secrets.", homePaths.PrivateKey)
	ui.Info("Remove it once you've confirmed the card works: rm %s", homePaths.PrivateKey)
}
```

- [ ] **Step 3: Fix the tests** — remove `TestUseEnrollsPKCS11Machine`, `TestUseRefusesToOverwriteExistingIdentity` (they drove `runPKCS11Use`). Keep `TestPercentEscapeSurvivesUIDoublePass` and `TestPKCS11URIRoundTrip`. If any helper (`readMachineInfo`, `captureStdout`) becomes unused, leave it if referenced elsewhere; otherwise delete.

- [ ] **Step 4: Run tests + build**

Run: `NVOLT_TEST_PKCS11_MODULE=/usr/lib/softhsm/libsofthsm2.so PATH=$PATH:/usr/local/go/bin go test -vet=off ./internal/cli/ 2>&1 | tail -3`
Expected: `ok`.
Run: `PATH=$PATH:/usr/local/go/bin go build ./...`
Expected: clean.

- [ ] **Step 5: Update docs + commit** — replace `pkcs11 use` in `README.md` and `docs/pkcs11-yubikey-runbook.md` with `init/join --pkcs11` (fresh enroll) and `nvolt rebind --pkcs11` (backing swap).

```bash
git add internal/cli/pkcs11.go internal/cli/pkcs11_test.go README.md docs/pkcs11-yubikey-runbook.md
git commit -m "refactor(pkcs11): remove 'pkcs11 use'; enroll informs about orphaned software key instead of deleting"
```

---

### Task 6: Output verbosity — technical detail behind `--verbose`/`--debug`

**Files:**
- Modify: `internal/cli/pkcs11.go` (list/generate/import/enroll output)
- Modify: `internal/cli/rebind.go` (verbose detail)
- Modify: `internal/cli/machine.go` (new-source output)
- Test: `internal/cli/verbosity_test.go`

**Interfaces:**
- Consumes: `ui.Info`, `ui.Verbose`, `ui.Success`, `ui.SetLevel`, `ui.LevelInfo`, `ui.LevelVerbose`.

- [ ] **Step 1: Write the failing test** — `internal/cli/verbosity_test.go`:

```go
package cli

import (
	"strings"
	"testing"

	"github.com/iluxav/nvolt/internal/ui"
)

func TestPkcs11ListDefaultOmitsTechnicalDetail(t *testing.T) {
	mod := hsmtestModuleOrSkip(t) // provision a token with a key via hsmtest
	ui.SetLevel(ui.LevelInfo)
	defer ui.SetLevel(ui.LevelInfo)
	out, err := captureStdout(func() error { return runPKCS11ListDiscovered(mod) })
	if err != nil {
		t.Fatal(err)
	}
	// At the default level, the module .so path and key ID are NOT shown.
	if strings.Contains(out, ".so") || strings.Contains(out, "ID") {
		t.Fatalf("default output leaked technical detail:\n%s", out)
	}
	ui.SetLevel(ui.LevelVerbose)
	vout, _ := captureStdout(func() error { return runPKCS11ListDiscovered(mod) })
	if !strings.Contains(vout, ".so") {
		t.Fatalf("verbose output should include the module path:\n%s", vout)
	}
}
```

Match `runPKCS11ListDiscovered` and `captureStdout` to their real names (read `pkcs11.go`/`pkcs11_test.go`). Provide `hsmtestModuleOrSkip` by reusing `hsmtest.Provision(t)`.

- [ ] **Step 2: Run test to verify it fails**

Run: `NVOLT_TEST_PKCS11_MODULE=/usr/lib/softhsm/libsofthsm2.so PATH=$PATH:/usr/local/go/bin go test -vet=off ./internal/cli/ -run TestPkcs11ListDefault -v`
Expected: FAIL — default output currently includes `.so` path and `ID` (they print via ungated `ui.PrintKeyValue`).

- [ ] **Step 3: Move detail to Verbose** — in `internal/cli/pkcs11.go` `printModuleListing`/`printTokenListing`, change the ungated detail lines to `ui.Verbose`, keeping only the concise summary at Info:
  - Module: `ui.Section(m.Label)` stays; `Path`/`Source` → `ui.Verbose("  Path: %s ...")`.
  - Token: keep the token label at Info; per key print `ui.Info("    RSA-%d", k.Bits)` at Info and `ui.Verbose("      ID: %x  Label: %s", k.ID, k.Label)` at Verbose.
  - Enroll (`enrollPKCS11Machine` output block): keep `ui.Success("Machine %s is now backed by the on-card key", mi.ID)` at Info + the software-key notice at Info; move `Fingerprint`/`Module`/`URI`/`OAEP mode` to `ui.Verbose`.
  - `pkcs11 generate`/`import`: keep the one-line `ui.Success` at Info; move `Label`/`ID`/`Bits` to `ui.Verbose`.
  - `machine add` external-source path: `ui.Success("Registered %s", id)` + grant hint at Info; `Fingerprint`/source at `ui.Verbose`.
  - `rebind`: already Info summary + at-Info software-key notice; move fingerprint/module/uri to `ui.Verbose`.

- [ ] **Step 4: Run test to verify it passes**

Run: `NVOLT_TEST_PKCS11_MODULE=/usr/lib/softhsm/libsofthsm2.so PATH=$PATH:/usr/local/go/bin go test -vet=off ./internal/cli/ -run TestPkcs11ListDefault -v`
Expected: PASS.

- [ ] **Step 5: Full suite + all-targets cross-compile + commit**

Run: `NVOLT_TEST_PKCS11_MODULE=/usr/lib/softhsm/libsofthsm2.so PATH=$PATH:/usr/local/go/bin go test -vet=off ./... 2>&1 | tail -8`
Expected: all `ok` except the known pre-existing `internal/vault` `TestGenerateMachineID` failure.
Run: `PATH=$PATH:/usr/local/go/bin bash -c 'for t in linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64; do GOOS=${t%/*} GOARCH=${t#*/} CGO_ENABLED=0 go build -o /dev/null ./cmd/nvolt && echo ok $t; done'`
Expected: all six `ok`.

```bash
git add internal/cli/
git commit -m "feat(pkcs11): gate technical output behind --verbose; default output stays concise"
```

---

## Self-Review

**Spec coverage:** Feature 1 → Task 3; Feature 2 → Task 4; Feature 3 → Task 2; Feature 4 → Task 5; Feature 5 → Task 1; Feature 6 → Task 6. All six covered.

**Ordering note:** Task 1 (flag rename) runs first so Tasks 2–4 add new commands with the final `--pkcs11-*` names. Task 5 (remove `use`) runs after Task 4 (`rebind`) so the replacement exists before removal.

**Known pre-existing failure:** `internal/vault` `TestGenerateMachineID` fails on the baseline (fix lives on `fork-extras`); it is not in scope and must be ignored in test runs.

**Open transcription points (resolve by reading the named file before implementing, not by guessing):** the exact session-open/login block in `runPKCS11Generate` (Task 2 Step 6); the pubkey-read to extract into `keyprovider.ReadTokenPublicKey` (Task 3 Step 1); the real `vault.GetHomePaths()` return type and `runMachineAdd` body (Tasks 3–4); the real names of `runPKCS11ListDiscovered`/`captureStdout`/`readMachineInfo` test helpers (Tasks 2, 6).
