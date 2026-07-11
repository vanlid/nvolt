# PKCS#11 Machine-Key Management — Design

**Goal:** Round out nvolt's machine-key management so a hardware (PKCS#11) key is a
first-class citizen everywhere a software key is, via six related changes:

1. **`machine add`** can register a machine from an *existing* public key (PEM or a
   PKCS#11 token), not only by generating a software keypair.
2. A new top-level **`nvolt rebind`** relocates *this* machine's existing key
   between software and hardware backing, gated on the public key being unchanged.
3. A new **`pkcs11 import`** loads an RSA private key onto a token via the standard
   `C_CreateObject`, sibling to `pkcs11 generate`.
4. The standalone **`pkcs11 use` is removed** — fresh enrollment stays
   `init/join --pkcs11`; `rebind` covers the same-key backing swap.
5. A consistent **`--pkcs11-*` flag-naming rule** across every command.
6. **Output verbosity**: default output is concise, human-readable; technical
   detail and error internals move behind `--verbose`/`--debug`.

**Status:** Design. Builds on the completed, Windows-validated PKCS#11 enroll
feature (branch `windows-abi-integrated`).

---

## Background

nvolt uses envelope encryption: each environment has an AES master key, wrapped
per machine with that machine's RSA public key at `wrapped_keys/<env>/<id>`. A
machine decrypts by unwrapping with its private key — a software file or a PKCS#11
token, selected at runtime through the `crypto.Decrypter` seam
(`keyprovider.LoadDecrypter`, which already switches on `key_source.source`).

A machine's **id embeds its key fingerprint** (`GenerateMachineID` appends 7 chars
of the pubkey SHA-256). So identity is coupled to key material: the same public key
always yields the same id and the same set of valid wrapped keys.

What already works and is unchanged:

- **`machine grant` / `rm` / `list`** operate on the vault's machine registry and
  are key-type-agnostic; `grant` unwraps via the PKCS#11-aware `LoadDecrypter`.
- **Hardware onboarding**: a machine self-enrolls with `join --pkcs11` (reads its
  card, registers its pubkey, clones the vault); an admin then `grant`s it.
- **Software hand-off**: `machine add <name>` generates a keypair and prints the
  private key to install on the target (CI, another device).

## Motivation & the gaps

- **`machine add` can only *generate*.** A hardware key can't be generated
  centrally (it lives on a card), and there is no way to register a machine from a
  *public key you already have*. This blocks pre-authorizing a hardware/external
  key and user-composed key rotation.
- **`pkcs11 use` was a footgun and mis-placed.** It could silently overwrite the
  local identity, and it lived under the `pkcs11` *utilities* group though it is a
  *current-machine identity* operation. Fresh enrollment is already covered by
  `init/join --pkcs11` (which include the module→token→key wizard), so the broad
  command is redundant. The one legitimate sliver it served — moving an existing
  key from software to hardware — becomes the safe, narrow `rebind`.
- **Flag names were inconsistent** across commands (`--module` bare on the pkcs11
  subcommands but ambiguous next to `--repo` on init/join).

## Non-Goals

- **No rotation/migration orchestration.** Changing to a *different* key stays
  user-composed from existing commands (see "User-composed rotation" below). A
  dedicated command may be designed later.
- **No generate-on-card in `machine add`.** Its `--pkcs11` source *reads* an
  existing key's pubkey. To register a freshly generated card key, compose
  `pkcs11 generate` then `machine add --pkcs11 --pkcs11-uri <newkey>`.
- **No identity-model change.** Ids stay fingerprint-derived; there is no `--id`
  override. `rebind` works precisely *because* it keeps the pubkey (hence the id)
  the same.
- **`pkcs11` stays the group name** for the remaining utilities (`list`,
  `generate`); it is not renamed to `p11`.

---

## Feature 1 — `machine add` from an existing public key

`machine add <name>` gains a mutually-exclusive **key source** (default unchanged):

```
nvolt machine add <name>                                   # default: generate a software keypair (UNCHANGED)
nvolt machine add <name> --pubkey <file.pem>               # register from a PEM public key
nvolt machine add <name> --pkcs11 [--pkcs11-module <p>] [--pkcs11-uri <u>]   # read pubkey from a token
```

**Behavior** (both new sources reuse the whole existing add flow, differing only in
where the pubkey comes from and what is *not* printed):

1. Obtain the RSA public key — `--pubkey`: PEM-decode the file; `--pkcs11`: resolve
   module/token/key via the same `resolveEnrollTarget` helper enroll uses (explicit
   flags or the interactive wizard on a TTY) and read the object's public
   components. Reading a public object needs **no PIN**, so `machine add` has **no
   `--pkcs11-pin-mode` flag**.
2. Validate: RSA, **≥ 2048 bits** (same check as `keyprovider/pkcs11.go:89`).
3. Register exactly like the generate path: compute the fingerprint, build
   `MachineInfo{ ID: GenerateMachineID(name, name, fingerprint), PublicKey,
   Fingerprint, Hostname: name, ... }` with **no private key** and **no
   `KeySource`** (a registry entry records only the pubkey; `KeySource`, including
   any local module path, is the owning machine's local concern), then
   `AddMachineToVault` and commit/push in global mode.
4. Output: `Registered <id> — grant it with `nvolt machine grant <id> -e <env>``.
   The "save this private key…" block appears **only** on the generate path.

## Feature 2 — `nvolt rebind` (pubkey-gated backing swap)

A new **top-level** command (alongside `init`/`join`, the other current-machine
identity commands — *not* under `machine`, whose subcommands act on the vault
registry, and *not* under `pkcs11`, since it also has a `--software` direction).

```
nvolt rebind --pkcs11 [--pkcs11-module <p>] [--pkcs11-uri <u>] [--pkcs11-pin-mode <m>]   # -> hardware
nvolt rebind --software [--privkey <private.pem>]                                        # -> software
```

Exactly one direction (`--pkcs11` or `--software`) is required — there is no
ambiguous no-arg form.

**Purpose:** move *this* machine's identity between software and hardware backing
**without changing the key** — the new backing's public key **must equal** the
current identity's. Because the pubkey (and thus the fingerprint and id) is
unchanged, **every wrapped key stays valid and no vault is touched.** Real use
case: get your existing software key onto the card first — `nvolt pkcs11 import` on
tokens that support PKCS#11 import, or `ykman piv keys import` on a YubiKey — then
`nvolt rebind --pkcs11 …` so nvolt unwraps via the card.

**Non-destructive by design:** `rebind` only re-points config and *installs* a key
into the forced location when one is missing. It **never deletes or overwrites** a
key file — nothing else in nvolt does, and the user stays in control.

**Behavior:**

1. Load the current `machine-info`. If none exists → error: "no machine identity
   yet; use `init`/`join --pkcs11`". (`rebind` changes an existing identity; it
   does not create one.)
2. Establish the target backing's key and gate on the pubkey (**must equal** the
   current identity's public key; mismatch → error: "that key's public key doesn't
   match this machine's identity; `rebind` only relocates the same key — to change
   to a different key, register it with `machine add` and re-grant"):
   - **`--pkcs11 …`** (→ hardware): resolve module/token/key, run the existing
     enroll read + **self-test** (`keyprovider.Enroll` — proves the card can
     actually decrypt; needs the PIN, hence `--pkcs11-pin-mode`). If the token
     holds no key matching your identity → error printing the `pkcs11
     import`/`ykman` command to put the key on the card first.
   - **`--software`** (→ software): the key must be a software PEM whose pubkey
     matches.
     - Without `--privkey`: require an existing key at `~/.nvolt/private_key.pem`
       and verify it matches (the natural "undo" of a sw→hw rebind, which left the
       key in place). No key present → error asking for `--privkey`.
     - With `--privkey <path>`: verify its pubkey matches, then install it — but
       only into an **empty** destination. If `~/.nvolt/private_key.pem` already
       exists and **matches**, `--privkey` is redundant → flip config, write
       nothing. If it exists and **differs**, refuse: "a different private key
       already exists at `~/.nvolt/private_key.pem` — remove or relocate it first."
3. Swap the local backing (id, pubkey, fingerprint, and all wrapped keys unchanged):
   - → hardware: set `key_source = {source: pkcs11, module, uri}`. **Leave**
     `~/.nvolt/private_key.pem` on disk and print that it is still present (and can
     still decrypt), with the command to remove it once the card is confirmed.
   - → software: ensure the matching key is at `~/.nvolt/private_key.pem` (per
     above), clear `key_source` (software).
4. No vault operation, no commit/push; no file deleted or overwritten.

`--pkcs11` and `--software` are mutually exclusive; `--privkey` is valid only with
`--software`.

## Feature 3 — `pkcs11 import`

A new subcommand sibling to `pkcs11 generate`, importing an RSA private key onto a
token via the standard PKCS#11 `C_CreateObject`.

```
nvolt pkcs11 import --privkey <private.pem> --token <label> \
                    [--label <l>] [--id <hex>] [--pkcs11-module <p>] [--pkcs11-pin-mode <m>]
```

**Behavior:**

1. PEM-decode the RSA private key from `--privkey`; validate RSA, ≥ 2048 bits.
2. Open a session on the token (`--token`), `C_Login` with the resolved PIN.
3. `C_CreateObject` with a private-key template — `CKA_CLASS=CKO_PRIVATE_KEY`,
   `CKA_KEY_TYPE=CKK_RSA`, `CKA_TOKEN=true`, `CKA_DECRYPT=true`,
   `CKA_ID`/`CKA_LABEL`, and the key material (`CKA_MODULUS`,
   `CKA_PUBLIC_EXPONENT`, `CKA_PRIVATE_EXPONENT`, `CKA_PRIME_1`, `CKA_PRIME_2`,
   `CKA_EXPONENT_1`, `CKA_EXPONENT_2`, `CKA_COEFFICIENT`). Optionally also create
   the matching `CKO_PUBLIC_KEY` object.
4. Report the created object's id/label.

**Pure PKCS#11, no PIV.** Auth is `C_Login` (PIN) only — no management key, no
`ykman`, no PIV protocol. Works on SoftHSM and any token that supports PKCS#11 key
import. On a token that requires out-of-band auth to write keys (**YubiKey via
OpenSC**), `C_CreateObject` returns the token's error (typically
`CKR_FUNCTION_NOT_SUPPORTED`) — exactly like `pkcs11 generate` there. Documented as
a token limitation; on YubiKey, use `ykman piv keys import`.

Reuses the existing packed `CK_ATTRIBUTE` marshaling (`packAttrsWindows` /
`abipack.go`); the only new Cryptoki entry is **`C_CreateObject` (index 20)**.

## Feature 4 — remove `pkcs11 use`

Delete the `pkcs11 use` subcommand and its flags/vars. Fresh hardware enrollment is
`init/join --pkcs11` (already wizard-enabled); same-key backing swap is `rebind`;
a different-key change is the user-composed rotation. The shared
`enrollPKCS11Machine`/`keyprovider.Enroll` code stays (used by init/join and, for
the self-test + key_source, by `rebind`). The `pkcs11` group keeps `list`,
`generate`, and the new `import`.

**Non-destructive alignment:** `enrollPKCS11Machine` today *secure-deletes* an
orphaned software `private_key.pem`. That path is only reachable in a broken
partial state (`IsMachineInitialized` already guards the normal case — a real
software identity returns `SoftwareConflict`, never an enroll), but for
consistency with `rebind` it changes to **inform, not delete**: leave the file and
print that it is still present and how to remove it. No nvolt command deletes a
user's key file.

## Feature 5 — `--pkcs11-*` flag rule

**A PKCS#11 flag that crosses into the general commands (`init`, `join`,
`machine add`, `rebind`) carries the `--pkcs11-*` prefix on *every* command it
appears on — so it reads identically whether on a general command or a `pkcs11`
subcommand. Flags that live only inside the `pkcs11` subcommand group stay bare
(the group name already scopes them and prefixing would add pure stutter), as do
generic file inputs.** The mild stutter this leaves on shared flags under the
`pkcs11` group (`pkcs11 generate --pkcs11-module`) is accepted for uniformity.

| Flag | Appears on | Name |
|---|---|---|
| module | `pkcs11 list/generate/import`, `init`, `join`, `machine add`, `rebind` | `--pkcs11-module` (crosses general → prefixed) |
| uri | `init`, `join`, `machine add`, `rebind` | `--pkcs11-uri` (crosses general → prefixed) |
| pin-mode | `pkcs11 generate/import`, `init`, `join`, `rebind` | `--pkcs11-pin-mode` (crosses general → prefixed) |
| pkcs11 (toggle / hw direction) | `init`, `join`, `machine add`, `rebind` | `--pkcs11` |
| software (sw direction) | `rebind` | `--software` (rebind-only direction → bare) |
| token / label / id | `pkcs11 generate`, `pkcs11 import` | `--token` / `--label` / `--id` (pkcs11-group-internal → bare) |
| pubkey | `machine add` | `--pubkey` (public-key file → bare) |
| privkey | `rebind`, `pkcs11 import` | `--privkey` (private-key file → bare) |

## Feature 6 — output verbosity

Today the PKCS#11 commands print all their detail through **ungated**
`ui.PrintKeyValue`/`ui.Section`, so everything shows at the default level. Route
technical detail through nvolt's existing levels (`Info` < `Verbose` < `Debug`,
default `Info`) so the default is concise and human, and detail is opt-in.

**Scope:** the output *this feature owns* — `pkcs11 list`/`generate`/`import`, the
`--pkcs11` enroll summary (shared by `init`/`join`), `rebind`, and `machine add`'s
new-source path. Unrelated pre-existing output (`machine list`/`grant`, general
`init`/vault messages) is left untouched.

Per command — Info (default) vs Verbose:

- **`pkcs11 list`** — Info: a concise module → token → key tree (module label;
  token label; per key `RSA-<bits>`, or "no RSA key yet" + the generate hint).
  Verbose: module `Path`/`Source`, key `ID` and full `Label`.
- **enroll (`init/join --pkcs11`)** — Info: `Machine <id> is now backed by the
  on-card key`, plus (if a software key was left on disk) the security notice that
  it is still present and how to remove it — this notice stays at Info, never
  hidden. Verbose: `Fingerprint`, `Module`, `URI`, `OAEP mode`.
- **`pkcs11 generate` / `pkcs11 import`** — Info: one-line success (what was
  created/imported on which token). Verbose: `Label`, `ID`, `Bits`.
- **`rebind`** — Info: `<id> now backed by <hardware|software>`, plus (sw→hw) the
  same at-Info notice that `~/.nvolt/private_key.pem` is still present + removal
  command. Verbose: fingerprint, and module/uri (hw) or key path (sw).
- **`machine add` (new sources)** — Info: `Registered <id>` + grant hint. Verbose:
  fingerprint and the source (pubkey file path / token uri).

**Errors:** the user-facing message stays human (CKR codes already render as names
via `ckrvName`, never raw hex); technical context (module path, failing function,
raw `CK_RV`) is emitted via `ui.Debug` during the operation, not baked into the
default error text.

**Mechanism:** replace the ungated `ui.PrintKeyValue`/`ui.Section` detail lines with
`ui.Verbose`/`ui.Debug`, keeping a concise `ui.Success`/`ui.Info` summary at the
default level (level-checked key-value helpers may be added if cleaner).

## User-composed rotation (documented, not automated)

Changing to a **different** key (rotation) reuses existing commands; `rebind` does
**not** apply (different pubkey). From the machine's still-active old identity:

```bash
nvolt machine add my-laptop --pkcs11 --pkcs11-uri 'pkcs11:...new-key...'   # register the new pubkey
nvolt machine grant my-laptop-<newfp> -e production                        # re-wrap access (repeat per env)

# swap this machine's identity to the new key (different key -> re-enroll, not rebind):
rm ~/.nvolt/machines/machine-info.json
nvolt join --pkcs11 --pkcs11-uri 'pkcs11:...new-key...'                    # re-establish identity in the vault

nvolt machine rm my-laptop-<oldfp>                                         # retire the old machine
```

Use the **same name** in `machine add` and the re-enroll so the granted id matches
the new local id (custom name takes precedence over hostname in `GenerateMachineID`).
This friction is the deliberate trade for not building orchestration; it is
documented, not hidden. The common, clean case — *same* key sw→hw — is the
one-command `rebind` and needs none of this.

## Architecture & Units

- **`internal/cli/machine.go`** — `runMachineAdd` grows a source switch; extract a
  pure `machineAddPublicKey(source) (*rsa.PublicKey, error)`; move key generation +
  private-key output under the generate-only branch.
- **`internal/cli/rebind.go`** (new) — the `rebind` command: require exactly one of
  `--pkcs11`/`--software`; load current identity; establish the target key (token
  via `keyprovider.Enroll` self-test for `--pkcs11`; existing/`--privkey` PEM for
  `--software`); enforce the pubkey-match gate; flip `key_source`. **Non-destructive**
  — sw→hw leaves `private_key.pem` and prints the still-present notice; sw install
  writes only to an empty destination (matching-existing → flip only; differing →
  refuse). Reuses `resolveEnrollTarget` and `keyprovider.Enroll`; adds no
  secure-delete.
- **`internal/cli/pkcs11.go`** — remove the `use` subcommand; add the `import`
  subcommand; reuse/extract a `ReadTokenPublicKey(module, uri) (*rsa.PublicKey,
  error)` from the enroll path for `machine add --pkcs11`; rename the shared
  `list`/`generate`/`import` `--module`/`--pin-mode` flags to `--pkcs11-*`, leaving
  the group-internal `--token`/`--label`/`--id` and generic `--privkey` bare.
- **`internal/pkcs11`** — add `idxCreateObject = 20` in `cryptoki.go` and a
  `CreateObject(session, template []CK_ATTRIBUTE) (handle, error)` wrapper that
  reuses the existing packed `CK_ATTRIBUTE` marshaling (`packAttrsWindows` on
  Windows, native structs elsewhere). A helper builds the RSA private-key template
  from an `*rsa.PrivateKey` (modulus, exponents, primes, CRT params as big-endian
  byte attributes).
- **`internal/cli/init.go`** — rename shared enroll flags in
  `addPKCS11EnrollFlags`/`pkcs11OptsFromFlags` to `--pkcs11-module`/`--pkcs11-uri`/
  `--pkcs11-pin-mode` (toggle stays `--pkcs11`).
- **`internal/cli/root.go`** — register the new top-level `rebind` command.
- **`internal/crypto`** — reuse existing public/private-key PEM helpers.

Boundaries: pubkey *sourcing* (file/token) is isolated from *registration*
(`machine add`) and from *backing swap* (`rebind`); the RSA-≥2048 validation and
the token-pubkey read are each one shared function.

## Error Handling

- Unreadable/missing `--pubkey`/`--privkey`, non-RSA, sub-2048, malformed PEM → clear
  error naming the input.
- `rebind` with no direction (neither `--pkcs11` nor `--software`) or both → explicit
  "specify exactly one of --pkcs11 / --software" error; `--privkey` without
  `--software` → "—privkey is only valid with --software".
- `rebind` with no current identity → directs to `init`/`join --pkcs11`.
- `rebind` pubkey mismatch → the "same key only" message pointing at `machine add`.
- `rebind --pkcs11` self-test failure (card can't decrypt / wrong PIN) → the
  existing enroll self-test error; the swap is **not** performed.
- `rebind --pkcs11` with no key on the token matching the identity → error printing
  the `pkcs11 import`/`ykman` command to put the key on the card first.
- `rebind --software` with no `--privkey` and no existing `~/.nvolt/private_key.pem`
  → "no software key present; supply --privkey <path>".
- `rebind --software --privkey <p>` when a **different** key already exists at
  `~/.nvolt/private_key.pem` → refuse ("remove or relocate it first"); nothing is
  overwritten.
- Mutually-exclusive sources set together (`machine add` `--pubkey`+`--pkcs11`) →
  explicit "choose one" error.
- Not in a vault (`machine add`) → existing `findVaultPath` error.

## Testing

- **Unit (no hardware):** `machineAddPublicKey` for `--pubkey` (valid RSA-2048 ok;
  sub-2048, non-RSA, malformed rejected); source mutual-exclusivity. Registered
  `MachineInfo` has pubkey + expected id, no private key, no `KeySource`.
- **Unit:** `rebind` pubkey-match gate + non-destructive rules — matching pubkey
  flips `key_source`, leaving id/wrapped keys untouched; mismatch errors and changes
  nothing; no-identity errors; no direction / both directions error; sw→hw **does
  not delete** `private_key.pem` (still on disk after) and emits the notice;
  `--software` with no `--privkey` and no on-disk key errors; `--software --privkey`
  over a **differing** existing key refuses and leaves it intact; over a matching
  existing key flips config without rewriting.
- **Integration (SoftHSM, gated on `NVOLT_TEST_PKCS11_MODULE`, via `hsmtest`):**
  `pkcs11 import --privkey <pem>` creates a usable RSA private key on the token (found
  by `pkcs11 list`, and it decrypts an OAEP round-trip); `machine add --pkcs11
  --pkcs11-uri <key>` registers from the token pubkey; `rebind --pkcs11` over a
  software identity whose key was imported to the token swaps to `key_source=pkcs11`
  and **leaves** `private_key.pem`; a following `rebind --software` (no `--privkey`)
  flips back using that same on-disk key.
- **Flag-rename:** `--help` for `init`, `join`, `pkcs11 list/generate`, `machine
  add`, `rebind` shows shared flags as `--pkcs11-*`, `generate` still bare
  `--token/--label/--id`.
- **Removal:** `pkcs11 use` is gone; its former tests are removed or re-homed onto
  `rebind`/init-join as appropriate.
- **Verbosity:** at the default level, `pkcs11 list`/enroll/`generate`/`import`/
  `rebind`/`machine add` output contains only the concise human summary — no module
  paths, URIs, key IDs, bits, or fingerprints; at `--verbose` those details appear.
  Assert via `captureStdout` + `ui.SetLevel`.
- Reuse `-vet=off` (pre-existing format-string vet warnings), as the suite does.

## Success Criteria

- `machine add --pubkey`/`--pkcs11` register a machine from an existing pubkey with
  no private key generated or printed; default `machine add` behavior is unchanged.
- `nvolt rebind --pkcs11` / `--software [--privkey]` swaps backing for the same key
  (pubkey-gated), changing only local `key_source` (and installing a software key
  into an empty slot when needed); it **never deletes or overwrites** a key file and
  touches no vault; a different key is refused with a clear pointer to `machine add`.
  No nvolt command deletes a user's software key — it informs instead.
- `nvolt pkcs11 import --privkey <pem>` loads an RSA private key onto a supporting
  token via `C_CreateObject`; on a token that rejects PKCS#11 import (YubiKey) it
  surfaces the token's error, like `generate`.
- `pkcs11 use` no longer exists; `pkcs11` retains `list`/`generate`/`import`.
- Shared PKCS#11 flags read as `--pkcs11-*` on every command; unique flags stay bare.
- Default output of these commands is concise and human; `--verbose`/`--debug`
  reveal technical detail; error messages are human by default with internals
  surfaced only under `--debug`.
- All six targets cross-compile; `CGO_ENABLED=0` static build preserved.
