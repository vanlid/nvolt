# Embedded wolfPKCS11 module

nvolt can talk to a TPM 2.0 through [wolfPKCS11](https://github.com/wolfSSL/wolfPKCS11),
which routes PKCS#11 key operations down to the chip via
[wolfTPM](https://github.com/wolfSSL/wolfTPM). `build-module.sh` compiles wolfSSL,
wolfTPM and wolfPKCS11 into a **single self-contained shared library** (~1.1 MB,
depends only on libc) that nvolt embeds and loads at runtime.

## The stack

```
nvolt ──PKCS#11 (dlopen)──▶ libwolfpkcs11.so ──wolfTPM──▶ TPM 2.0
                            (wolfSSL + wolfTPM statically linked in)
```

nvolt itself stays cgo-free: it `dlopen`s the module via `purego`, exactly as it
loads OpenSC/YubiKey modules. The only difference is that this module is carried
*inside* the nvolt binary and extracted on demand (see "How nvolt uses it").

## Building the module

```bash
# Native build for the current OS/arch. Defaults to the hardware TPM interface
# (devtpm on Linux, winapi on Windows) and writes to the //go:embed path.
build/pkcs11/build-module.sh

# CI / no hardware: build against the software TPM simulator interface.
TPM_INTERFACE=swtpm build/pkcs11/build-module.sh

# Custom output location:
build/pkcs11/build-module.sh /tmp/libwolfpkcs11.so
```

Requires: `gcc`, `make`, `autoconf`, `automake`, `libtool`, `git`.

Pinned upstream versions (edit the top of `build-module.sh` to bump):

| Component  | Tag              |
|------------|------------------|
| wolfSSL    | `v5.9.2-stable`  |
| wolfTPM    | `v4.1.0`         |
| wolfPKCS11 | `v2.1.0-stable`  |

### Why these build flags

- **wolfSSL `--enable-singlethreaded`** — removes the `pthread_*` references from
  the static archive. Without it, wolfTPM's and wolfPKCS11's autoconf link tests
  (`… conftest.c -lpthread -lwolfssl`) fail: with static libs the linker drops
  `-lpthread` before it reaches `-lwolfssl`, so `pthread_create` goes unresolved
  and configure wrongly reports "wolfSSL not found."
- **`--enable-cryptocb`** — the crypto-callback hook wolfPKCS11 uses to offload
  RSA/ECC to the TPM instead of computing in software.
- **`-fPIC` on the static deps** — so wolfSSL/wolfTPM archives can be linked into
  a shared object.
- **`--disable-dh`** — the TPM supports only RSA and ECC (no DH), which is all
  nvolt needs.
- **`--with-wolfcrypt=$PREFIX`** — points wolfTPM/wolfPKCS11 at our local wolfSSL
  install instead of a system copy.

## How nvolt uses it

The module is embedded behind a build tag so ordinary builds never need the
binary blob:

```bash
# 1. Produce the module at the embed path (internal/pkcs11/dist/module.bin):
build/pkcs11/build-module.sh

# 2. Build nvolt WITH the embedded module:
go build -tags wolfpkcs11_embed -o nvolt ./cmd/nvolt
#   or: make build-embedded
```

- **Default builds** (`go build ./...`, CI, `go test`) use a stub — no blob
  required, binary stays lean, everything stays cgo-free.
- **`-tags wolfpkcs11_embed`** compiles the ~1.1 MB module into the binary.

When compiled in, the built-in module appears as a **discovered option** like any
external one — `DetectModules` lists it, so `nvolt pkcs11 list` (and the enroll
selection) show it with no flag:

```
wolfPKCS11 (built-in, TPM)
    Path: embedded
    Source: embedded
```

It is listed last, so a plugged-in token or p11-kit proxy stays the default; on a
machine with nothing else installed it becomes the sole default. You can also
select it explicitly by path — the value is the sentinel **`embedded`**:

```bash
nvolt pkcs11 list --module embedded
NVOLT_PKCS11_MODULE=embedded nvolt init --pkcs11
```

`embedded` behaves as a real module path everywhere: `Open` materializes it to a
content-addressed file under the user cache dir (`~/.cache/nvolt/` on Linux) and
`dlopen`s that. Extraction is lazy (only when the module is actually opened —
never at startup, never for software-key or non-PKCS#11 commands) and idempotent
(the hash-named file is reused across calls and processes). A machine whose
`key_source.module` is `"embedded"` therefore carries no absolute path — it just
means "use nvolt's built-in module."

## `dist/module.bin`

The embed target `internal/pkcs11/dist/module.bin` is **git-ignored** — it is a
build artifact, produced by this script, consumed by `//go:embed`. Release
pipelines run the script per platform/arch before building with the tag.
