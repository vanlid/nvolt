# Register a Machine From an Existing Public Key — Design

**Goal:** Let `nvolt machine add` register a machine from a public key you already
have — read from a PEM file or a PKCS#11 token — instead of only generating a new
software keypair. This closes the one remaining PKCS#11 gap in machine management
and makes user-composed key migration/self-rotation possible.

**Status:** Design. Builds on the completed, Windows-validated PKCS#11 enroll
feature (branch `windows-abi-integrated`).

---

## Background & Motivation

nvolt uses envelope encryption: each environment has an AES master key, wrapped
per machine with that machine's RSA public key at `wrapped_keys/<env>/<id>`. A
machine decrypts by unwrapping its wrapped key with its private key (software file
or PKCS#11 token, via the `crypto.Decrypter` seam).

Machine management is already key-type-agnostic where it matters:

- **`machine grant`** unwraps the master key via the PKCS#11-aware
  `keyprovider.LoadDecrypter` and re-wraps it to any machine's stored pubkey — so
  it already works whether the granting machine is software- or hardware-backed.
- **`machine rm` / `machine list`** operate on machine ids and are type-agnostic.
- Hardware machines **self-enroll** via `join --pkcs11` (read the card, register
  the pubkey, clone the vault); an admin then `grant`s them. This path is
  complete today.

The **one gap**: `machine add` only ever *generates* a software keypair and prints
the private key for hand-off. A hardware key can't be generated centrally — it
lives on a card — and there is no way to register a machine from a *public key you
already have*. That blocks two things:

1. **Pre-authorizing** a hardware (or externally generated) key: register its
   pubkey, then `grant` it, before/without the owner running `join`.
2. **User-composed self-rotation** on a single machine: register the new key's
   pubkey → `grant` it your envs from your still-active old identity → swap your
   local config → `rm` the old machine. Without central pubkey registration this
   is a chicken-and-egg problem (you can't register the new key without first
   switching to it and losing the access you need to grant).

## Non-Goals (explicitly out of scope)

- **No rotation/migration orchestration command.** Sequencing register → grant →
  swap-config → rm stays user-composed from existing commands. A dedicated
  `machine rotate` may be designed later if the manual flow proves too fiddly.
- **No generate-on-card in `machine add`.** The `--pkcs11` source *reads* an
  existing key's pubkey. To register a freshly generated card key, compose
  `pkcs11 generate` then `machine add --pkcs11 --pkcs11-uri <newkey>`.
- **No change to the *behavior* of `pkcs11 use`, `init --pkcs11`, or
  `join --pkcs11`** — only their shared flags are renamed per the prefix rule
  above. `pkcs11 use` is retained as the local-identity-set primitive (used in the
  manual config-swap step of rotation). The command group stays named `pkcs11`
  (not renamed to `p11`).
- **No change to the default `machine add` behavior** (generate + hand off the
  private key) — that remains correct for CI and software hand-off.

## Feature

`machine add <name>` gains a mutually-exclusive **key source**:

```
nvolt machine add <name>                                  # default: generate a software keypair (UNCHANGED)
nvolt machine add <name> --pubkey <file.pem>              # register from a PEM public key
nvolt machine add <name> --pkcs11 \                       # read the pubkey from a PKCS#11 token
                        [--pkcs11-module <path>] \        #   module/uri optional; wizard resolves on a TTY
                        [--pkcs11-uri <uri>]
```

### Behavior

The two new sources reuse the *entire* existing `machine add` flow and differ only
in where the public key comes from and what is (not) printed:

1. **Obtain the public key**
   - `--pubkey <file>`: read and PEM-decode the file into an `*rsa.PublicKey`.
   - `--pkcs11 …`: resolve module/token/key via the same `resolveEnrollTarget`
     helper enroll uses (explicit `--pkcs11-module`/`--pkcs11-uri`, or the
     interactive module→token→key wizard on a terminal), then read the object's
     RSA public components (modulus/exponent). This needs **no PIN**: on the
     target tokens (e.g. YubiKey PIV) the public key/certificate is a public
     object readable without login, so `machine add --pkcs11` has **no
     `--pkcs11-pin-mode` flag** (unlike enroll). A token that requires login to
     read public objects is out of scope for this change.
2. **Validate**: the key must be RSA and **≥ 2048 bits** — the same check as
   enroll (`keyprovider/pkcs11.go:89`). Reject non-RSA, sub-2048, or malformed
   input with a clear error.
3. **Register** (identical to the generate path): compute the fingerprint, build
   `types.MachineInfo{ ID: GenerateMachineID(name, name, fingerprint),
   PublicKey, Fingerprint, Hostname: name, Description, CreatedAt }`, then
   `AddMachineToVault`, and commit/push in global mode.
   - **No `KeySource` is recorded** in the vault entry. `KeySource` (including any
     local module path) is the *owning* machine's local concern, set when that
     machine enrolls locally; recording it here would be wrong and could leak a
     local path into the shared vault. This matches the generate path, which also
     records no `KeySource`.
   - **No private key** is generated or written.
4. **Output**: `Registered <id> — grant it access with
   `nvolt machine grant <id> -e <env>``. The "save this private key…" hand-off
   block is emitted **only** on the default generate path.

### Flag rules

- `--pubkey` and `--pkcs11` (on `machine add`) are mutually exclusive; either one
  suppresses key generation. Neither given → unchanged generate behavior.
- `--pkcs11-module` / `--pkcs11-uri` are only meaningful with `--pkcs11`.
- **Prefix rule — shared flags carry the prefix everywhere, unique flags stay
  bare.** A PKCS#11 flag that appears on more than one command gets the
  `--pkcs11-*` prefix on *every* command it appears on, so it reads identically
  wherever you meet it; a flag unique to a single command keeps a bare name. This
  makes shared flags self-evident and uniform, at the cost of a little stutter on
  the `pkcs11` subcommands (`nvolt pkcs11 use --pkcs11-module …`), which is
  accepted in exchange for one consistent name per shared concept.

Concretely:

| Flag | Commands it appears on | Name |
|---|---|---|
| module | `pkcs11 list`, `pkcs11 use`, `pkcs11 generate`, `init`, `join`, `machine add` | `--pkcs11-module` (shared → prefixed) |
| uri | `pkcs11 use`, `init`, `join`, `machine add` | `--pkcs11-uri` (shared → prefixed) |
| pin-mode | `pkcs11 use`, `pkcs11 generate`, `init`, `join` | `--pkcs11-pin-mode` (shared → prefixed) |
| pkcs11 (mode toggle) | `init`, `join`, `machine add` | `--pkcs11` (unchanged) |
| token / label / id | `pkcs11 generate` only | `--token` / `--label` / `--id` (unique → bare) |
| pubkey | `machine add` only | `--pubkey` (unique → bare) |

This spec therefore renames the shared flags on **all** existing PKCS#11-touching
commands — the `pkcs11` subcommands as well as `init`/`join` — not just the new
`machine add` source.

## Intended usage: user-composed self-rotation

Documented in the README, not automated:

```bash
# From the machine's still-active OLD identity (which has vault access):
nvolt machine add my-laptop --pkcs11 --pkcs11-uri 'pkcs11:...new-key...'   # register new pubkey
nvolt machine grant my-laptop-<newfp> -e production                        # re-wrap access to it
# ...repeat grant for each environment you use...

# Swap this machine's local identity to the new key:
rm ~/.nvolt/machines/machine-info.json
nvolt pkcs11 use --pkcs11-uri 'pkcs11:...new-key...'                       # local identity now = new key

nvolt machine rm my-laptop-<oldfp>                                        # retire the old machine
```

Note the id-matching requirement: use the **same name** in `machine add` and in
`pkcs11 use` so the granted id matches your new local id (`GenerateMachineID`
gives a custom name precedence over hostname, so a consistent name yields a
consistent id). This friction is the deliberate trade for not building the
orchestration; it is documented, not hidden.

## Architecture & Units

- **`internal/cli/machine.go`** — `runMachineAdd` grows a small source switch. Extract
  a pure helper `machineAddPublicKey(source) (*rsa.PublicKey, error)` that returns
  the pubkey for the chosen source, keeping the register/commit tail shared and
  testable. The private-key generation + hand-off output moves under the
  generate-only branch.
- **`internal/cli/pkcs11.go`** — reuse `resolveEnrollTarget` (wizard/uri) to pick
  the key, and reuse the token public-key read that enroll already performs in
  `keyprovider` — extracting/exporting a `ReadTokenPublicKey(module, uri)
  (*rsa.PublicKey, error)` from the enroll path so both callers share one
  implementation (the plan pins down the exact function to factor out). Also
  rename the shared flags on `pkcs11 list`/`use`/`generate` to `--pkcs11-module`,
  `--pkcs11-uri`, `--pkcs11-pin-mode`, leaving `generate`'s unique `--token`,
  `--label`, `--id` bare.
- **`internal/cli/init.go`** — rename the shared enroll flags in
  `addPKCS11EnrollFlags`/`pkcs11OptsFromFlags` to `--pkcs11-module`,
  `--pkcs11-uri`, `--pkcs11-pin-mode` (toggle stays `--pkcs11`).
- **`internal/crypto`** — reuse the existing public-key PEM decode; add nothing new
  unless a helper is missing.

Boundaries: pubkey *sourcing* (file vs token) is isolated from *registration*
(shared with generate). Validation is one function reused across sources.

## Error Handling

- Missing/unreadable `--pubkey` file, or PEM that is not an RSA public key →
  clear error naming the file.
- RSA key `< 2048` bits → the same message enroll uses.
- `--pkcs11` with no resolvable module/token/key and no TTY → the existing
  autodetect/wizard errors from `resolveEnrollTarget`.
- Both `--pubkey` and `--pkcs11` set → explicit "choose one" error.
- Vault not found / not in a vault → existing `findVaultPath` error.

## Testing

- **Unit (no hardware):** `machineAddPublicKey` for `--pubkey` — valid RSA-2048
  PEM accepted; sub-2048 rejected; non-RSA (e.g. EC) rejected; malformed PEM
  rejected. Mutual-exclusivity of `--pubkey`/`--pkcs11`.
- **Unit:** registered `MachineInfo` has the pubkey + fingerprint + expected id,
  **no** private key on disk, and **no** `KeySource`.
- **Integration (SoftHSM, gated on `NVOLT_TEST_PKCS11_MODULE`):** `machine add
  --pkcs11 --pkcs11-uri <token-key>` against a self-provisioned `hsmtest` token
  registers the machine from the token's pubkey and writes it into the vault.
- **Flag-rename:** `--help` for `init`, `join`, and `pkcs11 list`/`use`/`generate`
  shows the shared flags as `--pkcs11-module`/`--pkcs11-uri`/`--pkcs11-pin-mode`,
  while `generate` still shows bare `--token`/`--label`/`--id`; `pkcs11OptsFromFlags`
  reads the renamed flags.
- Reuse `-vet=off` (pre-existing format-string vet warnings) as the rest of the
  suite does.

## Success Criteria

- `machine add <name> --pubkey <pem>` and `machine add <name> --pkcs11 …` register
  a machine from an existing pubkey, with no private key generated or printed.
- The default `machine add <name>` is byte-for-byte unchanged in behavior.
- `init`/`join`/`machine add` present PKCS#11 flags as `--pkcs11-*`; `pkcs11`
  subcommands keep bare flags.
- The documented self-rotation flow works end-to-end with existing commands.
- All targets cross-compile; `CGO_ENABLED=0` static build preserved.
