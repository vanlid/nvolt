# nvolt PKCS#11 / YubiKey support — design

**Date:** 2026-07-11
**Status:** Draft for review

## Goal

Let a machine use an **RSA private key held on a hardware token (YubiKey PIV)** — accessed
via **PKCS#11** — to perform nvolt's private-key operation, so the key never leaves the card.
Primary environment: YubiKey on a local Windows machine, nvolt running on a remote Linux box
reached over SSH (VS Code Remote-SSH).

## Background — how nvolt crypto works today

nvolt uses **envelope encryption**:

- A random **AES-256** "master key" encrypts secrets (AES-GCM) — `internal/crypto/encrypt.go`.
- The master key is **RSA-OAEP-SHA256-wrapped** to each authorized machine's public key —
  `internal/crypto/wrap.go: WrapKey`.
- Each machine has an RSA-4096 keypair; the private key is stored as PEM at
  `~/.nvolt/private_key.pem` (`internal/vault/machine.go`).

There is exactly **one private-key operation** in the entire system:

```
crypto.UnwrapKey(privateKey, wrappedKey)   // rsa.DecryptOAEP(sha256, ...)
```

Callers: `internal/vault/secrets.go` (pull) and `internal/cli/push.go` (push). Everything else
(`WrapKey`, fingerprints, machine ID) needs only the **public** key.

**Implication:** hardware integration only needs the card to perform an on-card RSA-OAEP decrypt.
The AES/GCM data path and the entire wrap/push path are untouched.

## Approach

Replace the concrete `*rsa.PrivateKey` with Go's stdlib `crypto.Decrypter` interface (which
`*rsa.PrivateKey` already implements). A factory returns the right decrypter for the machine —
software (PEM) or PKCS#11 (token). The PKCS#11 module is loaded **without cgo** via `purego`.

### Decision record

1. **No cgo, phased backends behind one seam.**
   - **Phase 1 (this branch): `purego` + native module loading.** `purego` `dlopen`s the PKCS#11
     module (`p11-kit-client.so`, or `opensc-pkcs11.so` directly) and calls `C_*` through a thin
     internal FFI binding — no cgo, single static binary, existing 6-target static release matrix
     (`CGO_ENABLED=0`) unchanged. Chosen first because it debugs against standard, known-good
     tooling and is **topology-agnostic** — it works for both WSL+p11-kit *and* the USB/IP-to-remote
     fallback. Requires one small native file on the remote (`p11-kit-client.so`).
   - **Phase 2 (fast-follow, designed-for now): pure-Go p11-kit RPC client.** A second key-source
     backend that speaks the p11-kit RPC protocol directly over the forwarded socket — no native
     libraries on the remote at all, a fully self-contained single binary. Slots behind the same
     `crypto.Decrypter` seam with no rework; gated on Phase 1 working. `google/go-p11-kit` (pure Go,
     server-only) is the reference for the wire codec. Only works in the p11-kit topology, which is
     why Phase 1 (the general path) lands first.
   - Fallback (documented only): cgo + `ThalesGroup/crypto11`, if purego FFI proves impractical on
     hardware.
2. **Forwarding = WSL + p11-kit** (user has WSL2 + admin). `usbipd-win` attaches the YubiKey to
   WSL2; inside WSL, `pcscd` + OpenSC + `p11-kit server` expose the module over a unix socket;
   a **separate** SSH session from WSL remote-forwards that socket to the remote; nvolt on the
   remote loads `p11-kit-client.so`. VS Code's own Remote-SSH connection is left untouched (do NOT
   route VS Code through WSL). Fallback topology: USB/IP straight to the remote + `opensc-pkcs11.so`.
   nvolt is **module-agnostic** — it only ever sees "a PKCS#11 module at path X", so the forwarding
   choice never enters nvolt's code.
3. **Scope = Phase 1 complete in one branch:** discovery (`list`), selection (`use`), on-card
   key generation (`generate`), full pull/push wiring, SoftHSM2 CI tests, and the WSL/p11-kit
   runbook — all in a single PR (targets `main`) built on the Phase-1 `purego` `.so`-loading
   backend. The Phase-2 pure-Go RPC-client backend is a separate follow-up branch, unblocked once
   Phase 1 is validated on hardware.
4. **PIN:** default `prompt` (no-echo TTY read at unwrap time); `env` (`NVOLT_PKCS11_PIN`) opt-in
   for automation (documented as weaker); `none` for pinpad tokens. PIN never persisted.

## Components

### 1. `internal/keyprovider/` (new)

The single seam. One code path on every platform (no build tags, thanks to purego).

- `provider.go` — `LoadDecrypter() (dec crypto.Decrypter, close func() error, err error)`.
  Reads the machine key-source descriptor and dispatches to a **backend**. The backend interface is
  transport-neutral: it yields a `crypto.Decrypter` + `close`, regardless of *how* the key is
  reached. This is what lets the Phase-2 RPC-client backend drop in with no caller changes.
- `software.go` — backend: wraps `*rsa.PrivateKey` from PEM (existing behaviour).
- `pkcs11.go` — Phase-1 backend: opens a PKCS#11 session via the purego FFI binding, returns a
  token-backed `crypto.Decrypter` bound to the selected key object, plus a `close` that logs out /
  closes the session / finalizes the module.
- `p11kit_rpc.go` — Phase-2 backend (follow-up): speaks the p11-kit RPC protocol over the forwarded
  socket directly; same `crypto.Decrypter` output, no native module.

### 2. `internal/pkcs11/` (new) — thin purego FFI binding

Not a full PKCS#11 implementation — only the calls nvolt uses:

`C_Initialize`, `C_Finalize`, `C_GetSlotList`, `C_GetTokenInfo`, `C_OpenSession`, `C_CloseSession`,
`C_Login`, `C_Logout`, `C_FindObjectsInit/FindObjects/FindObjectsFinal`, `C_GetAttributeValue`,
`C_Decrypt(Init)`, and `C_GenerateKeyPair` (for `generate`).

Handles `CK_ATTRIBUTE[]` and `CK_MECHANISM` marshaling (incl. `CKM_RSA_PKCS_OAEP` params, or
`CKM_RSA_X_509` for the raw fallback — see OAEP section).

### 3. `internal/crypto/wrap.go` — signature change

```go
func UnwrapKey(dec crypto.Decrypter, wrapped []byte) ([]byte, error) {
    return dec.Decrypt(rand.Reader, wrapped, &rsa.OAEPOptions{Hash: crypto.SHA256})
}
```

Software path behaviour is byte-for-byte identical (an `*rsa.PrivateKey` honours `*rsa.OAEPOptions`).

### 4. `internal/crypto/oaep_raw.go` (new, conditional)

Only needed if the token does not expose `CKM_RSA_PKCS_OAEP`: given a raw-RSA (`CKM_RSA_X_509`)
on-card result, strip OAEP-SHA256 padding in Go software (MGF1 + unpad, ~40 lines).

### 5. Key-source descriptor

Stored as a new optional `KeySource` field on `MachineInfo` in `pkg/types/types.go` (persisted in
the existing `~/.nvolt/machine.json` — no new file, keeps machine identity atomic). When absent,
`source` defaults to `software` for backward compatibility with existing machines:

```json
{ "source": "pkcs11",
  "module":    "/usr/lib/x86_64-linux-gnu/p11-kit-client.so",
  "uri":       "pkcs11:token=YubiKey%20PIV;id=%03;type=private",
  "pin_mode":  "prompt",
  "oaep_mode": "native" }
```

`oaep_mode` (`native` | `raw`) records which unwrap path was proven to work at enroll time (see
Validation), so `pull`/`push` don't have to rediscover it.

- `module` — `.so` path; overridable via `NVOLT_PKCS11_MODULE`.
- `uri` — RFC 7512 PKCS#11 URI naming token + object; explicit `--slot/--label/--id` flags map onto it.
- The card's **public key** is read once at enroll and stored exactly like today's PEM public key,
  so fingerprint / machine-ID / wrap logic are unchanged.

### 6. CLI — `internal/cli/pkcs11.go` (new) + flags

```
nvolt pkcs11 list   [--module PATH]                     # enumerate tokens + RSA private-key objects
nvolt pkcs11 use    --module PATH --uri 'pkcs11:...'     # adopt an on-card key as this machine's identity
nvolt pkcs11 generate --slot N --label nvolt --bits 2048 # on-card C_GenerateKeyPair
nvolt init --pkcs11   /   nvolt join --pkcs11            # run select-flow instead of generating PEM
```

- `list` — read-only discovery (label, id, key type/size, token serial).
- `use` — opens a session, **validates** (see below), reads the public key off the card, writes the
  descriptor + public key into machine config, regenerates fingerprint + machine ID. The PKCS#11
  analog of `machine init`.
- `generate` — on-card keypair (Yubico `ykcs11` supports `C_GenerateKeyPair`); if unsupported by the
  token/module, print the manual command (`ykman piv keys generate 9d …` /
  `yubico-piv-tool -a generate -s 9d …`) and instruct the user to run `pkcs11 use`.
- `init`/`join` gain `--pkcs11`; default (no flag) behaviour is unchanged.

## Data flow

**Pull / run (decrypt):**
```
LoadDecrypter() ──(pkcs11)──► open session, C_Login(PIN), find key object
UnwrapKey(dec, wrappedMasterKey) ──► dec.Decrypt(OAEP-SHA256) ──► C_Decrypt on card
                                     (touch prompt if PIV touch policy set)
AES-GCM decrypt secrets with master key   (unchanged)
```

**Push / add-machine (encrypt):** unchanged — `WrapKey(otherMachinePublicKey, masterKey)`. The
current machine's own re-read of the master key on push also goes through `LoadDecrypter()`.

## Error handling

- Module load failure (`dlopen`) → clear "PKCS#11 module not found at PATH; is the p11-kit tunnel
  up?" message.
- No matching key object for the URI → list what *was* found.
- `C_Login` PIN failure → surface the token's remaining-attempts if available; never log the PIN.
- OAEP mechanism not supported by token → automatic raw + software-unpad fallback (see below); if
  raw also unsupported, fail with an explicit, actionable error.
- Touch timeout → "no touch detected" hint.

## Validation & guardrails (enforced at `pkcs11 use`)

nvolt's whole scheme assumes an **RSA** key that can perform **OAEP-SHA256** decrypt. Rather than
trust that, `pkcs11 use` verifies it up front and refuses to enroll a key that won't work — turning
a silent, hard-to-debug `pull` failure into a clear enroll-time error. Checks, in order:

1. **Is it a PKCS#11 module?** `dlopen` succeeds and `C_GetFunctionList` resolves and returns a
   valid function list of a supported cryptoki version. Otherwise: "not a PKCS#11 module: PATH".
2. **Is the object an RSA private key?** `CKA_CLASS == CKO_PRIVATE_KEY` and
   `CKA_KEY_TYPE == CKK_RSA`. Reject EC/other with a clear message.
3. **Is it usable and strong enough?** `CKA_DECRYPT == true` and `CKA_MODULUS_BITS >= 2048`
   (matches the existing `crypto.ValidateRSAKey` minimum).
4. **Reconstruct the public key** from `CKA_MODULUS` + `CKA_PUBLIC_EXPONENT` into an
   `*rsa.PublicKey`; store it as PEM exactly like a software machine. This is what keeps the entire
   **wrap/push path (RSA-OAEP-SHA256) unchanged** — other machines wrap to this PEM as always.
5. **OAEP round-trip self-test.** Generate a random 32-byte value, wrap it with the card's public
   key using software OAEP-SHA256, then decrypt it through the token. If it round-trips → record
   `oaep_mode: native`. If the token rejects `CKM_RSA_PKCS_OAEP`, retry via raw `CKM_RSA_X_509` +
   software OAEP-unpad; if *that* round-trips → `oaep_mode: raw`. If neither works → refuse to
   enroll with an actionable error. This guarantees a subsequent `pull` will succeed.

Because step 4 stores a normal RSA public key and step 5 pins a working OAEP-SHA256 unwrap, the rest
of nvolt (AES-GCM data path, wrap, fingerprint, mixed software/hardware vaults) is untouched.

## OAEP-on-card — validation spike (build FIRST)

nvolt wraps with RSA-OAEP-SHA256, so the card must unwrap with OAEP-SHA256. YubiKey does raw RSA
on-card; whether `ykcs11`/OpenSC exposes `CKM_RSA_PKCS_OAEP` varies.

**Spike:** wrap a test AES key with the card's public key (software OAEP-SHA256), then
`dec.Decrypt(..., &rsa.OAEPOptions{Hash: crypto.SHA256})` via the FFI binding against the real
YubiKey **and** SoftHSM2.

- **OAEP supported** → pure PKCS#11 path, done.
- **Only raw** → `CKM_RSA_X_509` on card + `oaep_raw.go` software unpad.

Either way the on-disk wrap format stays OAEP-SHA256, so mixed software/hardware machines in the
same vault interoperate. The spike also validates that purego FFI can drive the module at all —
it is the make-or-break of the feature and gates the rest of the work.

## Dependencies & build

- Add `github.com/ebitengine/purego` (pure Go; no cgo). No other runtime deps.
- Build stays `CGO_ENABLED=0`; existing release matrix unchanged. purego supports linux
  amd64/arm64 + darwin (covers the remote and dev laptops); the native `.so` is loaded at runtime
  only when a PKCS#11 command runs.

## Testing

- **Software path** — existing unit tests unchanged (interface swap is behaviour-preserving).
- **PKCS#11 path** — integration tests against **SoftHSM2** in CI (a software PKCS#11 token):
  `list`, `use`, unwrap, `generate`, and the OAEP-vs-raw branch — no hardware needed.
- **Real YubiKey** — manual validation via the spike, documented in the runbook.
- Lint/format per existing Makefile (`make check`).

## Files touched

| File | Change |
|---|---|
| `internal/keyprovider/{provider,software,pkcs11}.go` | new — the `Decrypter` factory |
| `internal/pkcs11/*.go` | new — thin purego FFI binding |
| `internal/crypto/wrap.go` | `UnwrapKey` takes `crypto.Decrypter` |
| `internal/crypto/oaep_raw.go` | new — OAEP unpad over raw RSA (conditional) |
| `internal/vault/machine.go` | `LoadDecrypter()`; key-source load/store |
| `internal/cli/pkcs11.go` | new — `list` / `use` / `generate` |
| `internal/cli/{init,join,pull,push}.go`, `internal/vault/secrets.go` | wire-up |
| `pkg/types/types.go` | key-source descriptor |
| `docs/…/pkcs11-yubikey-runbook.md` | new — WSL + usbipd + p11-kit + SSH forward setup |

## Alternatives considered

- **cgo + `miekg/pkcs11` / `ThalesGroup/crypto11`** — the mainstream stack. Rejected as the default
  because cgo breaks the fully-static `CGO_ENABLED=0` cross-compiled release matrix (would force a
  build-tag split + a separate cgo artifact). Kept only as a documented fallback.
- **`google/go-p11-kit` as a client** — rejected: it is **server-only** (lets a Go program *act as*
  a PKCS#11 module, backed by e.g. PEM files) and bundles no card-access module, so it cannot
  *consume* the YubiKey. It remains the reference implementation for the Phase-2 RPC-client wire
  codec.
- **Embedding `p11-kit-client.so` via `go:embed`** — rejected: the `.so` transitively links
  `libp11-kit.so.0`, so embedding one file is not self-contained, and it is per-arch and fragile.
  The Phase-2 pure-Go RPC client is the correct way to get a self-contained single binary.
- **Static-linking p11-kit into nvolt** — rejected: requires cgo + static archives of p11-kit and
  its deps (`libffi`, `libtasn1`), defeating the no-cgo / cross-compile goal.

## Out of scope (v1)

- Non-RSA keys (EC) — nvolt's wrap is RSA-OAEP; EC would need a KEM redesign.
- Windows-native nvolt using the card directly (nvolt runs on the remote Linux).
- Multiple hardware keys per machine.

## Runbook summary (WSL + p11-kit)

```
# Windows (admin):
usbipd list ; usbipd bind --busid <x> ; usbipd attach --wsl --busid <x>
# WSL:
sudo service pcscd start
p11-kit server --provider /usr/lib/.../opensc-pkcs11.so 'pkcs11:'   # prints P11_KIT_SERVER_ADDRESS
ssh -R /home/USER/.nvolt/pkcs11.sock:$XDG_RUNTIME_DIR/p11-kit/... user@remote   # separate session
# Remote sshd needs: StreamLocalBindUnlink yes
# Remote:
nvolt pkcs11 use --module /usr/lib/.../p11-kit-client.so --uri 'pkcs11:...'
```
