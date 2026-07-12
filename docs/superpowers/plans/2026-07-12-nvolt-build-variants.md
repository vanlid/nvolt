# nvolt Build Variants (static / dynamic / TPM-static) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give nvolt three build variants selected by build tag — a fully-static default with no PKCS#11 (restoring the `v1.0.25` static binary), an opt-in dynamic `pkcs11` build (purego `dlopen`, external tokens + embedded wolfPKCS11), and a fully-static Linux/musl `wolfpkcs11_static` build that links wolfPKCS11 in via cgo for TPM-only use.

**Architecture:** PKCS#11 support is gated behind build tags because purego forces a dynamic ELF (it imports `dlopen` from libdl), which broke the historical fully-static binary. purego lives only in `internal/pkcs11`, imported by exactly two files (`internal/cli/pkcs11.go`, `internal/keyprovider/pkcs11.go`), so tagging those two importers (with stubs for the tag-off build) removes purego from the default build. A third, cgo-based loader (no purego, no `dlopen`) links wolfPKCS11's static archive directly for a fully-static TPM binary on musl. External tokens (OpenSC/YubiKey) and Windows/macOS stay on the dynamic `pkcs11` build, where `dlopen`/`LoadLibrary` always work.

**Tech Stack:** Go 1.24 (build tags, `//go:embed`, cgo), purego v0.10.1 (dynamic loader), wolfSSL/wolfTPM/wolfPKCS11 (C, static archives), musl-gcc (fully-static cgo on Linux), GitHub Actions + cross toolchains.

## Global Constraints

- Default `go build` (no tags), `CGO_ENABLED=0`, MUST produce a fully-static binary on Linux (`ldd` → "not a dynamic executable"). Verify with `file`/`ldd`, never assume.
- `internal/pkcs11` MUST be imported only under `//go:build pkcs11 || wolfpkcs11_static`. No default-build code path may import it (that would pull in purego → dynamic ELF).
- `pkcs11` and `wolfpkcs11_static` are mutually exclusive loaders; a build with both tags is unsupported (guard with a compile-time assertion file).
- The public API of `internal/pkcs11` is identical across the purego and cgo loaders: `Open(path string) (*Module, error)`, `DetectModules() []DiscoveredModule`, `ListTokensAndKeys(module string) ([]TokenListing, error)`, `ListRSAKeys(module string) ([]KeyInfo, error)`, `ResolveModulePath(flagValue string) (string, error)`, `DefaultModulePath() (string, error)`, plus `(*Module)` methods used by keyprovider (`Close`, login/decrypt path). Types `DiscoveredModule`, `TokenListing`, `KeyInfo`, `Module` are shared (untagged files).
- The `embedded` sentinel and `wolfpkcs11_embed` embed tag apply ONLY to the `pkcs11` (purego) loader. The `wolfpkcs11_static` loader links the module directly — no embed, no extraction.
- Darwin has no TPM (Secure Enclave ≠ TPM 2.0); never build a wolf module or `wolfpkcs11_static` binary for darwin. macOS cannot produce fully-static binaries (no static libSystem) — the dynamic `pkcs11` build is the only hardware path there.
- Windows has no fully-static concept and `LoadLibrary` always works; ship a single dynamic `pkcs11` Windows build. No static variant on Windows.
- Pinned upstream: wolfSSL `v5.9.2-stable`, wolfTPM `v4.1.0`, wolfPKCS11 `v2.1.0-stable` (already in `build/pkcs11/build-module.sh`).
- Follow existing conventions: table-driven tests, `//go:build` tags on line 1, cgo-free default, commit messages end with `Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>`.

---

## Branch & Distribution Strategy

Two tracks, so the upstream PR stays clean and non-regressive:

**Upstream — `pkcs11-feature` (→ PR to upstream `main`; distributed via `install.nvolt.io`):**
- PKCS#11 is **opt-in behind `-tags pkcs11`**; the default `go build` stays **fully static** (no glibc regression vs `v1.0.25`).
- Hardware support is obtained via `go install -tags pkcs11` / `make build-pkcs11` — cross-platform and **cgo-free (purego)**, so **no prebuilt pkcs11 binary is shipped and `install.sh` is unchanged**. One README paragraph documents the opt-in.
- Includes the two general loader fixes (`RTLD_LOCAL` interposition, `CK_FUNCTION_LIST` proxy offset).
- **Tasks 1–4 + the upstream README note land here.**

**Fork — `fork-extras` (rename candidate: `downstream`; distributed via GitHub Releases):**
- Merges upstream, adds the wolf bundling: recipe, embed (`wolfpkcs11_embed`), and the cgo static loader (`wolfpkcs11_static`). **Tasks 5–7.**
- Publishes prebuilt `nvolt-<os>-<arch>-pkcs11` (embedded wolf) and `nvolt-tpm-linux-<arch>` (static) to **GitHub Releases**. **Task 8 (fork portion).**
- **Dual release tracking (Task 10):** scheduled/`repository_dispatch` CI that rebuilds + republishes when EITHER upstream nvolt OR wolfSSL/wolfTPM/wolfPKCS11 cut a release.
- The wolf feature branch `pkcs11-wolf-module` merges into this branch.

Rule: nothing wolf-specific (bundling a particular TPM stack, the autobuild) goes upstream; only the provider-agnostic tag split + fixes do.

---

## File Structure

**Phase A — `pkcs11` build tag (pure-static default):**
- Modify: `internal/cli/pkcs11.go` — add `//go:build pkcs11 || wolfpkcs11_static` (only compiled when PKCS#11 is included).
- Modify: `internal/keyprovider/pkcs11.go` — same tag.
- Create: `internal/cli/pkcs11_stub.go` (`//go:build !pkcs11 && !wolfpkcs11_static`) — stub implementations of every symbol the rest of `internal/cli` references from `pkcs11.go` (`addPKCS11EnrollFlags`, `pkcs11OptsFromFlags`, `registerPKCS11Commands`, etc.), returning "not supported in this build" where invoked.
- Create: `internal/keyprovider/pkcs11_stub.go` (`//go:build !pkcs11 && !wolfpkcs11_static`) — stub `LoadDecrypter` branch for `key_source.source == "pkcs11"` returning a clear error.
- Modify: `internal/cli/init.go`, `join`/`rebind`/`machine` call sites only if they reference `pkcs11.go` symbols directly (they call same-package helpers, so the stub file covers them).

**Phase B — `wolfpkcs11_static` cgo loader (`nvolt-tpm`):**
- Create: `internal/pkcs11/loader_purego.go` — move the current purego `Open`/`dlopen` glue here under `//go:build pkcs11` (rename from `loader.go`/`dl_unix.go` bodies). Shared types/logic stay in untagged files.
- Create: `internal/pkcs11/loader_cgo.go` (`//go:build wolfpkcs11_static`) — cgo loader: `Open` calls the linked-in `C_GetFunctionList`; operations call `C.C_*` directly using real `pkcs11.h` structs.
- Create: `internal/pkcs11/cgo_wolf.go` (`//go:build wolfpkcs11_static`) — cgo preamble only: `#cgo LDFLAGS` for the static archives + `#include <wolfpkcs11/pkcs11.h>`.
- Create: `internal/pkcs11/detect_cgo.go` (`//go:build wolfpkcs11_static`) — `DetectModules` returns exactly the built-in module (`Path: "builtin"`, `Label: "wolfPKCS11 (static, TPM)"`); no filesystem probing, no `embedded` sentinel.
- Create: `internal/pkcs11/tags_guard.go` (`//go:build pkcs11 && wolfpkcs11_static`) — `#error`-equivalent: a `const _ = "pkcs11 and wolfpkcs11_static are mutually exclusive" ` that fails to compile, so both-tags builds are rejected.
- Modify: `build/pkcs11/build-module.sh` — add a `--archives-only` / `STATIC_ARCHIVES=1` mode that installs `libwolfpkcs11.a` + deps to a prefix for cgo linking (currently only produces the shared module).

**Phase C — CI / release / docs:**
- Modify: `.github/workflows/release.yml` — produce the variants: default static (Linux), `nvolt` `-tags pkcs11` (all platforms, with embed on TPM targets), `nvolt-tpm` musl-static (Linux amd64/arm64).
- Modify: `build/pkcs11/README.md` — document the three variants and which build reaches which provider per platform.
- Modify: `README.md` — user-facing note on choosing a build.

---

## Task 1: Gate `internal/cli/pkcs11.go` behind the `pkcs11` tag

**Files:**
- Modify: `internal/cli/pkcs11.go:1` (add build tag)
- Create: `internal/cli/pkcs11_stub.go`
- Test: `internal/cli/pkcs11_stub_test.go`

**Interfaces:**
- Consumes: nothing new.
- Produces: for the tag-off build, stubs of every exported-to-package symbol `pkcs11.go` defines that other `internal/cli` files call. Enumerate them first (Step 1).

- [ ] **Step 1: Enumerate the symbols other cli files use from pkcs11.go**

Run: `cd internal/cli && grep -rn "pkcs11OptsFromFlags\|addPKCS11EnrollFlags\|registerPKCS11\|resolveEnroll\|enrollPKCS11Machine\|ensurePKCS11" --include=*.go . | grep -v pkcs11.go | grep -v _test.go`
Expected: a list of call sites in `init.go`, `rebind.go`, `machine.go`, `machine_setup.go`, `root.go`. Record every distinct symbol name + signature — these are exactly what the stub must define.

- [ ] **Step 2: Write the failing test (default build has no pkcs11 command, clear error on --pkcs11)**

```go
//go:build !pkcs11 && !wolfpkcs11_static

package cli

import (
	"strings"
	"testing"
)

// TestPKCS11UnsupportedInDefaultBuild asserts the default (static) build reports
// an actionable error when a user asks for --pkcs11, instead of silently doing
// nothing or panicking.
func TestPKCS11UnsupportedInDefaultBuild(t *testing.T) {
	_, err := pkcs11OptsFromFlags(nil)
	if err == nil || !strings.Contains(err.Error(), "not built with PKCS#11") {
		t.Fatalf("want 'not built with PKCS#11' error, got %v", err)
	}
}
```

- [ ] **Step 3: Run test to verify it fails**

Run: `go test ./internal/cli/ -run TestPKCS11UnsupportedInDefaultBuild`
Expected: FAIL to compile — `pkcs11OptsFromFlags` is defined in `pkcs11.go` which still compiles in the default build (duplicate) or the stub doesn't exist yet.

- [ ] **Step 4: Add the build tag to pkcs11.go and create the stub**

Add to `internal/cli/pkcs11.go` line 1 (before `package cli`):
```go
//go:build pkcs11 || wolfpkcs11_static
```

Create `internal/cli/pkcs11_stub.go` (fill in EVERY symbol from Step 1; representative subset shown — include all):
```go
//go:build !pkcs11 && !wolfpkcs11_static

package cli

import (
	"errors"

	"github.com/spf13/cobra"
)

// errNoPKCS11 is returned by every PKCS#11 entry point in a build compiled
// without a PKCS#11 loader (the default fully-static binary). Use the dynamic
// `-tags pkcs11` build (or the static `nvolt-tpm` build) for hardware keys.
var errNoPKCS11 = errors.New("this nvolt was not built with PKCS#11 support; use the pkcs11-enabled build for hardware/TPM keys")

// pkcs11EnrollOpts mirrors the real type's shape so init/join compile; a nil
// value means --pkcs11 was not requested (unchanged semantics).
type pkcs11EnrollOpts struct{ module, uri, pinMode string }

func pkcs11OptsFromFlags(_ *cobra.Command) (*pkcs11EnrollOpts, error) { return nil, errNoPKCS11 }

func addPKCS11EnrollFlags(_ *cobra.Command) {} // no-op: flags absent in this build

func ensurePKCS11MachineInitialized(_ *pkcs11EnrollOpts) error { return errNoPKCS11 }

func registerPKCS11Commands(_ *cobra.Command) {} // no `nvolt pkcs11` subcommand
// ... define the remaining symbols from Step 1 identically (return errNoPKCS11
//     for funcs, no-op for registrars). Match each real signature exactly.
```

- [ ] **Step 5: Run test to verify it passes and the default build compiles**

Run: `go test ./internal/cli/ -run TestPKCS11UnsupportedInDefaultBuild && go build ./...`
Expected: PASS, and `go build ./...` (default, no tags) succeeds with no reference to `internal/pkcs11`.

- [ ] **Step 6: Verify the pkcs11 build still compiles and its tests pass**

Run: `go build -tags pkcs11 ./... && go test -tags pkcs11 ./internal/cli/`
Expected: builds and passes (real `pkcs11.go` now compiles under the tag).

- [ ] **Step 7: Commit**

```bash
git add internal/cli/pkcs11.go internal/cli/pkcs11_stub.go internal/cli/pkcs11_stub_test.go
git commit -m "refactor(cli): gate PKCS#11 command/flags behind the pkcs11 build tag

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 2: Gate `internal/keyprovider/pkcs11.go` behind the `pkcs11` tag

**Files:**
- Modify: `internal/keyprovider/pkcs11.go:1`
- Create: `internal/keyprovider/pkcs11_stub.go`
- Test: `internal/keyprovider/pkcs11_stub_test.go`

**Interfaces:**
- Consumes: `pkcs11EnrollOpts`-independent; the keyprovider dispatches on `key_source.source`.
- Produces: for the tag-off build, the `pkcs11` branch of `LoadDecrypter` (or equivalent) returns an error. Identify the exact function in Step 1.

- [ ] **Step 1: Find the pkcs11 dispatch point**

Run: `grep -rn "pkcs11\|LoadDecrypter\|key_source\|KeySource" internal/keyprovider/*.go | grep -v _test.go`
Expected: the `source == "pkcs11"` branch in `LoadDecrypter` (or a `newPKCS11Decrypter` constructor) in `pkcs11.go`. Record the function name/signature the non-pkcs11 keyprovider must still satisfy.

- [ ] **Step 2: Write the failing test**

```go
//go:build !pkcs11 && !wolfpkcs11_static

package keyprovider

import (
	"strings"
	"testing"

	"github.com/iluxav/nvolt/pkg/types"
)

// TestPKCS11KeySourceUnsupportedInDefaultBuild asserts a machine recorded with a
// pkcs11 key source fails clearly (not a panic) in the software-only build.
func TestPKCS11KeySourceUnsupportedInDefaultBuild(t *testing.T) {
	_, err := newPKCS11Decrypter(&types.KeySource{Source: "pkcs11"})
	if err == nil || !strings.Contains(err.Error(), "not built with PKCS#11") {
		t.Fatalf("want 'not built with PKCS#11' error, got %v", err)
	}
}
```
(Adjust `newPKCS11Decrypter` to the real constructor name from Step 1.)

- [ ] **Step 3: Run test to verify it fails**

Run: `go test ./internal/keyprovider/ -run TestPKCS11KeySourceUnsupportedInDefaultBuild`
Expected: FAIL to compile (real `pkcs11.go` still defines the symbol in the default build).

- [ ] **Step 4: Tag pkcs11.go and add the stub**

Add `//go:build pkcs11 || wolfpkcs11_static` to `internal/keyprovider/pkcs11.go:1`.

Create `internal/keyprovider/pkcs11_stub.go`:
```go
//go:build !pkcs11 && !wolfpkcs11_static

package keyprovider

import (
	"errors"

	"github.com/iluxav/nvolt/pkg/types"
)

// newPKCS11Decrypter is the software-only build's stub: a machine backed by a
// PKCS#11 key can't be used here. Match the real constructor's signature.
func newPKCS11Decrypter(_ *types.KeySource) (Decrypter, error) {
	return nil, errors.New("this nvolt was not built with PKCS#11 support; rebind to a software key or use the pkcs11-enabled build")
}
```

- [ ] **Step 5: Run test + verify default build**

Run: `go test ./internal/keyprovider/ -run TestPKCS11KeySourceUnsupportedInDefaultBuild && go build ./...`
Expected: PASS and default build succeeds.

- [ ] **Step 6: Confirm the whole default binary is now fully static**

Run:
```bash
CGO_ENABLED=0 go build -o /tmp/nvolt-static ./cmd/nvolt
file /tmp/nvolt-static   # want: statically linked / not a dynamic executable
ldd /tmp/nvolt-static    # want: "not a dynamic executable"
```
Expected: **statically linked** (no libdl/libc). This is the headline deliverable of Phase A.

- [ ] **Step 7: Commit**

```bash
git add internal/keyprovider/pkcs11.go internal/keyprovider/pkcs11_stub.go internal/keyprovider/pkcs11_stub_test.go
git commit -m "refactor(keyprovider): gate PKCS#11 key source behind the pkcs11 tag

Default build is now fully static (no purego, no dlopen).

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 3: Add the mutually-exclusive-tags compile guard

**Files:**
- Create: `internal/pkcs11/tags_guard.go`
- Test: none (compile-time behavior; verified by a build command)

**Interfaces:** none.

- [ ] **Step 1: Create the guard**

```go
//go:build pkcs11 && wolfpkcs11_static

package pkcs11

// Selecting both loaders is unsupported: they provide conflicting Open/DetectModules
// implementations (purego dlopen vs cgo static link). This line fails to compile so
// the mistake is caught at build time rather than producing a broken binary.
const _ = "build error: tags 'pkcs11' and 'wolfpkcs11_static' are mutually exclusive" - 0
```
(The `string - 0` is intentionally invalid Go, forcing a compile error only when both tags are set.)

- [ ] **Step 2: Verify it triggers only with both tags**

Run: `go build -tags "pkcs11 wolfpkcs11_static" ./internal/pkcs11/ 2>&1 | head -3`
Expected: compile error mentioning "mutually exclusive". Then `go build -tags pkcs11 ./internal/pkcs11/` and `go build ./internal/pkcs11/` both succeed.

- [ ] **Step 3: Commit**

```bash
git add internal/pkcs11/tags_guard.go
git commit -m "build(pkcs11): reject building both pkcs11 and wolfpkcs11_static tags

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 4: Split the purego loader glue under the `pkcs11` tag

**Files:**
- Modify: `internal/pkcs11/loader.go`, `internal/pkcs11/discover.go`, `internal/pkcs11/session.go`, `internal/pkcs11/dl_unix.go`, `internal/pkcs11/dl_windows.go` — add `//go:build pkcs11` (these are the purego-using files).
- Keep untagged (shared): `internal/pkcs11/cryptoki.go` (constants/types), `internal/pkcs11/autodetect.go` (path resolution helpers that don't import purego), `internal/pkcs11/abi*.go` if purego-free, the `DiscoveredModule`/`TokenListing`/`KeyInfo` type declarations, `embed*.go`.
- Test: existing `internal/pkcs11` tests, run under `-tags pkcs11`.

**Interfaces:**
- Produces: under `-tags pkcs11`, the current public API unchanged. Under no tag, `internal/pkcs11` still compiles as a types-only package (shared files), so untagged tests keep working.

- [ ] **Step 1: Identify which pkcs11 files import purego and which are pure**

Run: `for f in internal/pkcs11/*.go; do grep -q purego "$f" && echo "PUREGO: $f" || echo "pure  : $f"; done | grep -v _test`
Expected: PUREGO = loader.go, discover.go, session.go, dl_unix.go (dl_windows.go uses syscall not purego — check). Pure = cryptoki.go, autodetect.go, embed*.go, abi*.go, discover_modules_*.go, types.

- [ ] **Step 2: Move shared types out of purego-tagged files if needed**

If `DiscoveredModule`, `TokenListing`, `KeyInfo`, or `Module` are declared in a purego file, move those declarations to an untagged file `internal/pkcs11/types.go` so the shared API surface compiles without the tag. Run `go build ./internal/pkcs11/` (no tags) after — Expected: compiles (types-only).

- [ ] **Step 3: Add `//go:build pkcs11` to each purego-using file**

Prepend `//go:build pkcs11` (line 1, blank line, then existing content) to: `loader.go`, `discover.go`, `session.go`, `dl_unix.go`, and `dl_windows.go`. For the `!windows`/`windows` build-tagged dl files, combine: `//go:build pkcs11 && !windows` and `//go:build pkcs11 && windows`.

- [ ] **Step 4: Verify all three tag states compile**

Run:
```bash
go build ./internal/pkcs11/                       # no tag: types only
go build -tags pkcs11 ./internal/pkcs11/          # purego loader
go vet -tags pkcs11 ./internal/pkcs11/
go test -tags pkcs11 ./internal/pkcs11/           # existing tests
```
Expected: all succeed; `-tags pkcs11` tests pass (offset/embed/discovery tests from earlier commits).

- [ ] **Step 5: Commit**

```bash
git add internal/pkcs11/
git commit -m "refactor(pkcs11): move purego loader behind the pkcs11 tag; keep types shared

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 5: Static-archive output mode in the build recipe

**Files:**
- Modify: `build/pkcs11/build-module.sh`
- Test: manual build command (integration; no unit test)

**Interfaces:**
- Produces: with `STATIC_ARCHIVES=<dir>`, installs `libwolfpkcs11.a`, `libwolftpm.a`, `libwolfssl.a` and headers into `<dir>` for cgo linking, in addition to (or instead of) the shared module.

- [ ] **Step 1: Add the archive-install path**

In `build/pkcs11/build-module.sh`, after the wolfPKCS11 build, add:
```bash
if [ -n "${STATIC_ARCHIVES:-}" ]; then
  # wolfPKCS11 static archive is not installed by the shared-module build; add
  # --enable-static to its configure (see Global Constraints) and install.
  make -C "$WORK/wolfPKCS11" install >/dev/null   # installs libwolfpkcs11.a when --enable-static
  mkdir -p "$STATIC_ARCHIVES/lib" "$STATIC_ARCHIVES/include"
  cp "$PREFIX"/lib/libwolfpkcs11.a "$PREFIX"/lib/libwolftpm.a "$PREFIX"/lib/libwolfssl.a "$STATIC_ARCHIVES/lib/"
  cp -r "$PREFIX"/include/wolfpkcs11 "$PREFIX"/include/wolfssl "$PREFIX"/include/wolftpm "$STATIC_ARCHIVES/include/"
  echo "static archives installed to $STATIC_ARCHIVES" >&2
fi
```
Also add `--enable-static` to the wolfPKCS11 `./configure` line so `libwolfpkcs11.a` is produced.

- [ ] **Step 2: Verify archives are produced (native, glibc is fine for this check)**

Run: `STATIC_ARCHIVES=/tmp/wolfstatic TPM_INTERFACE=swtpm build/pkcs11/build-module.sh /tmp/mod.so`
Expected: `/tmp/wolfstatic/lib/libwolfpkcs11.a` (+ libwolftpm.a, libwolfssl.a) and `/tmp/wolfstatic/include/wolfpkcs11/pkcs11.h` exist.

- [ ] **Step 3: Commit**

```bash
git add build/pkcs11/build-module.sh
git commit -m "build(pkcs11): add STATIC_ARCHIVES mode for cgo static linking

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 6: cgo static loader — `Open` + `C_GetFunctionList`

**Files:**
- Create: `internal/pkcs11/cgo_wolf.go` (cgo preamble)
- Create: `internal/pkcs11/loader_cgo.go` (Open)
- Create: `internal/pkcs11/detect_cgo.go` (DetectModules → builtin)
- Test: `internal/pkcs11/loader_cgo_test.go` (integration, gated on archives present)

**Interfaces:**
- Consumes: shared types `Module`, `DiscoveredModule` (Task 4).
- Produces: `Open(path string) (*Module, error)` and `DetectModules() []DiscoveredModule` under `wolfpkcs11_static`, API-compatible with the purego versions. `Module` here wraps the `CK_FUNCTION_LIST*` from the linked-in `C_GetFunctionList`.

- [ ] **Step 1: cgo preamble**

Create `internal/pkcs11/cgo_wolf.go`:
```go
//go:build wolfpkcs11_static

package pkcs11

/*
#cgo CFLAGS: -I${SRCDIR}/dist/static/include
#cgo LDFLAGS: ${SRCDIR}/dist/static/lib/libwolfpkcs11.a ${SRCDIR}/dist/static/lib/libwolftpm.a ${SRCDIR}/dist/static/lib/libwolfssl.a -lm
#include <wolfpkcs11/pkcs11.h>
*/
import "C"
```
(The `dist/static/` prefix is populated by `STATIC_ARCHIVES=internal/pkcs11/dist/static build/pkcs11/build-module.sh` before building with the tag; git-ignore it like `dist/module.bin`.)

- [ ] **Step 2: Write the failing integration test**

```go
//go:build wolfpkcs11_static

package pkcs11

import "testing"

// TestCgoOpenBuiltin asserts the statically-linked module opens and exposes a
// function list without dlopen. C_Initialize failing for lack of a TPM is fine;
// what matters is that Open returns a usable Module.
func TestCgoOpenBuiltin(t *testing.T) {
	m, err := Open("builtin")
	if err != nil {
		t.Fatalf("Open(builtin): %v", err)
	}
	defer m.Close()
	if m.fnList == nil {
		t.Fatal("nil function list from statically-linked C_GetFunctionList")
	}
}
```

- [ ] **Step 3: Run to verify it fails (no impl yet)**

Run: `STATIC_ARCHIVES=internal/pkcs11/dist/static TPM_INTERFACE=devtpm build/pkcs11/build-module.sh /dev/null; CGO_ENABLED=1 go test -tags wolfpkcs11_static ./internal/pkcs11/ -run TestCgoOpenBuiltin`
Expected: FAIL — `Open`/`DetectModules` undefined under this tag.

- [ ] **Step 4: Implement Open + DetectModules**

Create `internal/pkcs11/loader_cgo.go`:
```go
//go:build wolfpkcs11_static

package pkcs11

// #include <wolfpkcs11/pkcs11.h>
import "C"
import (
	"fmt"
	"unsafe"
)

// Open ignores the path (the module is linked in) and resolves the function list
// from the statically-linked C_GetFunctionList. No dlopen, so this works in a
// fully-static binary.
func Open(_ string) (*Module, error) {
	var list C.CK_FUNCTION_LIST_PTR
	if rv := C.C_GetFunctionList(&list); rv != C.CKR_OK {
		return nil, fmt.Errorf("C_GetFunctionList: 0x%X", uint(rv))
	}
	return &Module{fnList: unsafe.Pointer(list)}, nil
}
```

Create `internal/pkcs11/detect_cgo.go`:
```go
//go:build wolfpkcs11_static

package pkcs11

// DetectModules returns just the statically-linked wolfPKCS11 module. There is
// no filesystem probing and no "embedded" sentinel in this build — the module
// is the binary.
func DetectModules() []DiscoveredModule {
	return []DiscoveredModule{{
		Path:   "builtin",
		Label:  "wolfPKCS11 (static, TPM)",
		Source: "builtin",
	}}
}
```
(Ensure `Module` has an exported-enough `fnList unsafe.Pointer` field in the shared `types.go`, and a `Close()` that calls `C.C_Finalize` under this tag — add a tagged `Close` in `loader_cgo.go`.)

- [ ] **Step 5: Run to verify it passes (needs a TPM or swtpm for a fuller run, but Open must succeed)**

Run: `CGO_ENABLED=1 go test -tags wolfpkcs11_static ./internal/pkcs11/ -run TestCgoOpenBuiltin`
Expected: PASS (Open returns a non-nil function list).

- [ ] **Step 6: Verify the resulting binary is fully static under musl (the real target)**

Run (on a musl toolchain, e.g. Alpine or `musl-gcc`):
```bash
STATIC_ARCHIVES=internal/pkcs11/dist/static build/pkcs11/build-module.sh /dev/null  # built with musl CC
CGO_ENABLED=1 CC=musl-gcc go build -tags "wolfpkcs11_static netgo osusergo" \
  -ldflags '-linkmode external -extldflags "-static"' -o nvolt-tpm ./cmd/nvolt
file nvolt-tpm   # want: statically linked
ldd nvolt-tpm    # want: not a dynamic executable
```
Expected: fully static `nvolt-tpm`. (Glibc-static also links but warns; musl is the shipping target.)

- [ ] **Step 7: Commit**

```bash
git add internal/pkcs11/cgo_wolf.go internal/pkcs11/loader_cgo.go internal/pkcs11/detect_cgo.go internal/pkcs11/loader_cgo_test.go .gitignore
git commit -m "feat(pkcs11): cgo static wolfPKCS11 loader (no dlopen, fully static)

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 7: cgo loader — token/key enumeration and decrypt path

**Files:**
- Modify: `internal/pkcs11/loader_cgo.go` (add operations)
- Create: `internal/pkcs11/session_cgo.go` (`//go:build wolfpkcs11_static`)
- Test: `internal/pkcs11/session_cgo_test.go` (integration, gated on swtpm/TPM via `NVOLT_TEST_TPM`)

**Interfaces:**
- Consumes: `Open` (Task 6), shared `TokenListing`/`KeyInfo` types.
- Produces: `ListTokensAndKeys(module string) ([]TokenListing, error)`, `ListRSAKeys(...)`, and the `(*Module)` login+decrypt methods the keyprovider calls — same names/signatures as the purego build.

- [ ] **Step 1: List the exact keyprovider entry points to replicate**

Run: `grep -rn "pkcs11\." internal/keyprovider/pkcs11.go` (under `-tags pkcs11` this is the real file)
Expected: the set of `pkcs11.Open`, session/login/decrypt calls the runtime path uses. Each must exist under `wolfpkcs11_static` with an identical signature. Record them.

- [ ] **Step 2: Write the failing integration test (gated on a TPM/swtpm being available)**

```go
//go:build wolfpkcs11_static

package pkcs11

import (
	"os"
	"testing"
)

// TestCgoListTokens exercises the static loader against a real/simulated TPM.
// Skipped unless NVOLT_TEST_TPM is set, so ordinary CI stays green.
func TestCgoListTokens(t *testing.T) {
	if os.Getenv("NVOLT_TEST_TPM") == "" {
		t.Skip("set NVOLT_TEST_TPM to run against a TPM/swtpm")
	}
	toks, err := ListTokensAndKeys("builtin")
	if err != nil {
		t.Fatalf("ListTokensAndKeys: %v", err)
	}
	if len(toks) == 0 {
		t.Fatal("expected at least one token from the TPM")
	}
}
```

- [ ] **Step 3: Run to verify it fails**

Run: `CGO_ENABLED=1 go build -tags wolfpkcs11_static ./internal/pkcs11/`
Expected: FAIL — `ListTokensAndKeys` undefined under this tag.

- [ ] **Step 4: Implement the operations via direct cgo calls**

In `session_cgo.go`, implement each operation calling the C API directly (real `pkcs11.h` structs — no manual ABI packing). Pattern for one operation (replicate for slots/find/attributes/login/decrypt):
```go
//go:build wolfpkcs11_static

package pkcs11

// #include <wolfpkcs11/pkcs11.h>
import "C"
import "fmt"

func ListTokensAndKeys(_ string) ([]TokenListing, error) {
	if rv := C.C_Initialize(nil); rv != C.CKR_OK && rv != C.CKR_CRYPTOKI_ALREADY_INITIALIZED {
		return nil, fmt.Errorf("C_Initialize: 0x%X", uint(rv))
	}
	var count C.CK_ULONG
	C.C_GetSlotList(C.CK_TRUE, nil, &count)
	slots := make([]C.CK_SLOT_ID, int(count))
	if count > 0 {
		C.C_GetSlotList(C.CK_TRUE, &slots[0], &count)
	}
	// ... for each slot: C_GetTokenInfo -> label; open session; find RSA
	//     public/private objects (C_FindObjectsInit/C_FindObjects/Final);
	//     read CKA_ID/CKA_LABEL/CKA_MODULUS (C_GetAttributeValue); build KeyInfo.
	//     Mirror discover.go's logic 1:1, using C structs instead of purego.
	return nil, nil // replace with the assembled []TokenListing
}
```
Implement `ListRSAKeys` in terms of `ListTokensAndKeys` (same as `discover.go`). Implement the keyprovider decrypt path (`C_OpenSession`, `C_Login`, `C_FindObjects` for the private key, `C_DecryptInit` with `CKM_RSA_PKCS_OAEP` + `CK_RSA_PKCS_OAEP_PARAMS`, `C_Decrypt`) with the exact method names Step 1 recorded.

- [ ] **Step 5: Run the gated integration test against swtpm**

Run:
```bash
# start a swtpm simulator, then:
NVOLT_TEST_TPM=1 CGO_ENABLED=1 go test -tags wolfpkcs11_static ./internal/pkcs11/ -run TestCgoListTokens
```
Expected: PASS (token enumerated). Without `NVOLT_TEST_TPM`, the test skips and the package still builds.

- [ ] **Step 6: End-to-end — static nvolt-tpm enrolls against swtpm**

Run: build `nvolt-tpm` (Task 6 Step 6), point it at a swtpm, `./nvolt-tpm pkcs11 list` (or `init --pkcs11`). Expected: reaches the TPM, lists/creates a key. Record the output.

- [ ] **Step 7: Commit**

```bash
git add internal/pkcs11/session_cgo.go internal/pkcs11/loader_cgo.go internal/pkcs11/session_cgo_test.go
git commit -m "feat(pkcs11): cgo static loader token/key enumeration + OAEP decrypt

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 8: CI — build the three variants

**Files:**
- Modify: `.github/workflows/release.yml`
- Test: workflow YAML validates; jobs run on tag.

**Interfaces:** none (CI).

- [ ] **Step 1: Add the default static Linux binaries to the matrix**

For `linux-amd64`/`linux-arm64`, add a build step that produces `nvolt-<os>-<arch>-static` with **no tags** and `CGO_ENABLED=0` (fully static, software-only), alongside the existing `-tags pkcs11` binary. Use `env:` for matrix values (no interpolation in `run:`).

- [ ] **Step 2: Rename the existing embed build to the `pkcs11` variant**

The current `Build binary` step (with `-tags wolfpkcs11_embed`) becomes the `pkcs11` dynamic variant; ensure its tag is `-tags "pkcs11 wolfpkcs11_embed"` on TPM targets and `-tags pkcs11` elsewhere (darwin: `-tags pkcs11`, no embed).

- [ ] **Step 3: Add the `nvolt-tpm` musl-static job (Linux only)**

New matrix entries `linux-amd64`/`linux-arm64` that:
- install musl cross toolchain (`musl-tools` / `musl-cross`),
- run `STATIC_ARCHIVES=internal/pkcs11/dist/static TPM_INTERFACE=devtpm build/pkcs11/build-module.sh /dev/null` with the musl `CC`,
- `CGO_ENABLED=1 CC=<musl-gcc> go build -tags "wolfpkcs11_static netgo osusergo" -ldflags '-linkmode external -extldflags "-static"' -o nvolt-tpm-<os>-<arch>`,
- assert `file` reports "statically linked".

- [ ] **Step 4: Validate the workflow**

Run: `python3 -c "import yaml; yaml.safe_load(open('.github/workflows/release.yml')); print('YAML OK')"`
Expected: `YAML OK`. Review the matrix lists the expected artifacts: `nvolt-*` (pkcs11), `nvolt-*-static` (Linux), `nvolt-tpm-*` (Linux).

- [ ] **Step 5: Commit**

```bash
git add .github/workflows/release.yml
git commit -m "ci(release): build static / pkcs11-dynamic / nvolt-tpm variants

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 9: Documentation

**Files:**
- Modify: `build/pkcs11/README.md`, `README.md`

**Interfaces:** none.

- [ ] **Step 1: Document the variant matrix**

In `build/pkcs11/README.md`, add a "Build variants" section with the table from this plan (default static / `-tags pkcs11` / `nvolt-tpm`), the per-platform provider reachability, and the hard rules (static ⟹ no dlopen on Linux; Windows/macOS use the dynamic build; darwin has no TPM).

- [ ] **Step 2: User-facing note in README.md**

In `README.md` near the PKCS#11 section, add: which binary to download — `nvolt` (dynamic, hardware tokens + TPM), `nvolt-static` (software only, minimal/container), `nvolt-tpm` (fully static TPM, Alpine/scratch).

- [ ] **Step 3: Commit**

```bash
git add build/pkcs11/README.md README.md
git commit -m "docs(pkcs11): document static / dynamic / nvolt-tpm build variants

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 10: Fork dual-upstream release tracking (fork-extras only)

**Files:**
- Create: `.github/workflows/track-releases.yml` (on the fork branch only)
- Test: workflow YAML validates; dry-run on `workflow_dispatch`.

**Interfaces:** none (CI automation).

- [ ] **Step 1: Wolf-release trigger**

Add a scheduled job (e.g. daily `cron`) that queries the latest wolfSSL/wolfTPM/wolfPKCS11 release tags (`gh release list` or the GitHub API), compares them to the pins at the top of `build/pkcs11/build-module.sh`, and — if any differ — opens a PR bumping the pins. Store the current pins in a small `build/pkcs11/versions.env` sourced by the script so the diff is a one-line change.

- [ ] **Step 2: Upstream-release trigger**

Add a second job that watches the upstream nvolt repo's release tags; when a new one appears, it merges/rebases the fork branch onto it (or opens a PR to do so) so the fork stays current with upstream security fixes.

- [ ] **Step 3: Shared rebuild+publish**

Both triggers, once merged, run the existing release matrix (Task 8) to rebuild `nvolt-*-pkcs11` and `nvolt-tpm-*` and publish to GitHub Releases with a version reflecting both the upstream tag and the wolf tags (e.g. `<nvolt-tag>+wolf<wolfpkcs11-tag>`).

- [ ] **Step 4: Validate + dry run**

Run: `python3 -c "import yaml; yaml.safe_load(open('.github/workflows/track-releases.yml')); print('YAML OK')"` then trigger via `workflow_dispatch` and confirm it detects "no change" when pins are current.

- [ ] **Step 5: Commit (on the fork branch)**

```bash
git add .github/workflows/track-releases.yml build/pkcs11/versions.env
git commit -m "ci(fork): track upstream nvolt + wolf releases, autobuild bundled binaries

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Notes for the implementer

- **Phase A (Tasks 1–4) is independently shippable** — it restores the fully-static default binary and is worth a PR on its own even if Phase B is deferred.
- **Phase B (Tasks 5–7) is the largest and most uncertain** — the cgo loader reimplements the PKCS#11 operations nvolt uses (enroll enumeration + OAEP decrypt) against the real `pkcs11.h`. Mirror `discover.go`/`session.go` logic exactly, but use C structs instead of the purego ABI-packing (`abipack.go` is not needed under cgo — the C compiler lays out the structs). If an operation is ambiguous, read the corresponding purego implementation for the intent, not the marshaling.
- **musl is the shipping target for `wolfpkcs11_static`** (clean fully-static cgo); glibc-static links but warns on `getaddrinfo` from swtpm sockets — use `TPM_INTERFACE=devtpm` for the real binary so no sockets are pulled in.
- Do not attempt static OpenSC or any static build on Windows/macOS — the dynamic `-tags pkcs11` build is correct there (their loaders are always present).
