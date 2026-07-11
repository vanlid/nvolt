# PKCS#11 / YubiKey setup runbook — WSL + p11-kit forwarding

This is the operator runbook for the target environment: a YubiKey plugged into a
**local Windows machine**, with `nvolt` running on a **remote Linux box** that you
reach via **VS Code Remote-SSH**. It walks through attaching the YubiKey to WSL2,
exposing it over a p11-kit socket, forwarding that socket to the remote over a
second SSH session, and enrolling the on-card key with `nvolt pkcs11`.

For the design rationale (why purego + no cgo, why WSL+p11-kit over the USB/IP
fallback, the validation/OAEP self-test nvolt runs at enroll time, etc.), see the
design spec: [`docs/superpowers/specs/2026-07-11-nvolt-pkcs11-yubikey-design.md`](superpowers/specs/2026-07-11-nvolt-pkcs11-yubikey-design.md).

## 1. Overview / topology

```
 Windows (local)                      WSL2 (Linux VM on Windows)
┌────────────────────┐   usbipd-win   ┌──────────────────────────────┐
│                     │  attach --wsl │                              │
│   YubiKey (USB) ────┼───────────────┼──►  pcscd  (smart-card daemon)│
│                     │               │       │                      │
│  usbipd list/bind   │               │       ▼                      │
│  usbipd attach      │               │   opensc-pkcs11.so           │
│                     │               │       │                      │
│                     │               │       ▼                      │
│                     │               │  p11-kit server               │
│                     │               │  (unix socket, prints         │
│                     │               │   P11_KIT_SERVER_ADDRESS)      │
│                     │               └───────────┬──────────────────┘
│                     │                            │
│                     │              ssh -R <remote-sock>:<local p11-kit socket>
│                     │              (SEPARATE ssh session, started FROM WSL)
│                     │                            │
│                     │                            ▼
│                     │               ┌──────────────────────────────┐
│  VS Code            │  Remote-SSH   │  Remote Linux box            │
│  Remote-SSH  ───────┼───────────────┼─►  (separate, parallel        │
│  (its own SSH conn) │               │     SSH session — unrelated  │
│                     │               │     to the tunnel above)     │
│                     │               │                              │
│                     │               │  ~/.nvolt/pkcs11.sock  ◄──────┼── forwarded socket
│                     │               │       │                      │
│                     │               │       ▼                      │
│                     │               │  p11-kit-client.so           │
│                     │               │       │                      │
│                     │               │       ▼                      │
│                     │               │  nvolt pkcs11 / init / pull  │
│                     │               └──────────────────────────────┘
└─────────────────────┘
```

**Two independent SSH sessions to the same remote host:**

1. **VS Code's own Remote-SSH connection** — how you edit/run code on the remote.
2. **A second, separate SSH session, started from inside WSL**, whose only job is
   to remote-forward the p11-kit unix socket (`ssh -R ...`) from WSL to the
   remote box.

**Do NOT route VS Code's Remote-SSH connection through WSL**, and do not try to
make VS Code's own SSH connection carry the socket forward. Keep the two
sessions separate: one for your editor/terminal, one dedicated to the PKCS#11
socket tunnel. This keeps the tunnel's lifecycle (which you may want to restart
independently, e.g. after replugging the YubiKey) decoupled from your VS Code
connection.

`nvolt` itself is **module-agnostic** — it only ever sees "a PKCS#11 module at
path X" on the remote filesystem. The forwarding mechanism (WSL+p11-kit here, or
the USB/IP-straight-to-remote fallback in §7) never enters nvolt's code.

### Alternative topology: YubiKey and nvolt both on Windows

If the YubiKey is plugged into the **same Windows machine** where you'll run
`nvolt` (e.g. a Windows build of `nvolt.exe`), none of the above applies — skip
WSL, p11-kit, and USB/IP entirely. `nvolt` loads PKCS#11 modules natively on
Windows via `LoadLibraryEx`, so just point `--module` at the Windows `.dll`
directly:

```powershell
nvolt pkcs11 use `
  --module "C:\Program Files\OpenSC Project\OpenSC\pkcs11\opensc-pkcs11.dll" `
  --uri 'pkcs11:token=<TOKEN>;id=%01;type=private'
```

(or Yubico's own `ykcs11.dll`, typically under `C:\Program Files\Yubico\Yubico
PIV Tool\bin\`). The rest of this runbook — enrollment flags, PIN modes, OAEP
fallback, touch policy — behaves the same; only the module path and forwarding
machinery differ. The WSL/p11-kit-forwarding sections below remain the primary
path for the "YubiKey on Windows, nvolt on a remote Linux box" topology.

## 2. Windows steps (as Administrator)

Install [`usbipd-win`](https://github.com/dorssel/usbipd-win) (via `winget` or the
MSI installer), then attach the YubiKey to WSL:

```powershell
# List USB devices and their bus IDs
usbipd list

# Bind the YubiKey's bus ID (one-time, persists across reboots)
usbipd bind --busid <BUSID>

# Attach it to the running WSL2 instance
usbipd attach --wsl --busid <BUSID>
```

While attached, the YubiKey is **exclusively owned by WSL** — Windows (and any
Windows-side smart-card/PIV tooling) cannot see it until you `usbipd detach` (or
unplug/replug) it back.

## 3. WSL steps

Install the PC/SC daemon, OpenSC's PKCS#11 module, and p11-kit:

```bash
sudo apt update
sudo apt install -y pcscd opensc p11-kit
sudo service pcscd start
```

Verify the card is visible through PKCS#11 (path varies by distro — see §8):

```bash
pkcs11-tool --module /usr/lib/x86_64-linux-gnu/opensc-pkcs11.so -L   # list slots/tokens
pkcs11-tool --module /usr/lib/x86_64-linux-gnu/opensc-pkcs11.so -O   # list objects (keys/certs)
```

Start a p11-kit server exposing the module over a unix socket:

```bash
p11-kit server --provider /usr/lib/x86_64-linux-gnu/opensc-pkcs11.so 'pkcs11:'
```

By default `p11-kit server` **daemonizes** — it forks to the background and
immediately returns your shell prompt, printing two lines:

```
export P11_KIT_SERVER_ADDRESS=unix:path=...
export P11_KIT_SERVER_PID=...
```

`P11_KIT_SERVER_ADDRESS` (a path under `$XDG_RUNTIME_DIR/p11-kit/`) is the
**local socket** you forward in the next step; the server keeps running in the
background even after this shell command returns and even if you close the
terminal. To stop it later, run `p11-kit server -k` (or
`kill $P11_KIT_SERVER_PID` using the PID printed above).

## 4. SSH forward — a SEPARATE session, not VS Code's

From a **new WSL terminal** (not the one running `p11-kit server`, and not your
VS Code Remote-SSH terminal), forward the p11-kit socket to the remote:

```bash
ssh -R /home/USER/.nvolt/pkcs11.sock:$XDG_RUNTIME_DIR/p11-kit/pkcs11-<something> user@remote
```

- The remote-side path (`/home/USER/.nvolt/pkcs11.sock`) is where the socket will
  appear on the remote box — pick any path you'll reference consistently below.
- The local-side path (`$XDG_RUNTIME_DIR/p11-kit/pkcs11-<something>`) comes
  directly from the `P11_KIT_SERVER_ADDRESS` printed in §3 — copy it exactly.
- Keep this SSH session open for as long as you need the token; closing it tears
  down the forward.

**Remote sshd requirement:** the remote's `/etc/ssh/sshd_config` must have:

```
StreamLocalBindUnlink yes
```

(then `sudo systemctl reload sshd`). Without this, a stale socket file left over
from a previous forward will block `sshd` from re-binding the same path on
reconnect, and the `-R` forward will silently fail to listen.

## 5. Remote (Linux) steps

Install p11-kit's client shim, which provides `p11-kit-client.so` — a PKCS#11
module that simply proxies every call over the forwarded socket to the real
module running in WSL:

```bash
sudo apt install -y p11-kit-modules
```

Point p11-kit at the forwarded socket (same remote-side path as the `-R` target
in §4):

```bash
export P11_KIT_SERVER_ADDRESS=unix:path=/home/USER/.nvolt/pkcs11.sock
```

Add this `export` to your shell profile if you want it to persist across
sessions on the remote.

### Discover the key

```bash
nvolt pkcs11 list --module /usr/lib/x86_64-linux-gnu/pkcs11/p11-kit-client.so
```

This enumerates RSA private-key objects visible on the token (label, hex id,
modulus bits) without a PIN — discovery does not log in.

### Enroll the on-card key as this machine's identity

```bash
nvolt pkcs11 use \
  --module /usr/lib/x86_64-linux-gnu/pkcs11/p11-kit-client.so \
  --uri 'pkcs11:token=<TOKEN>;id=%01;type=private' \
  --pin-mode prompt
```

Or fold enrollment into `init`/`join` directly:

```bash
nvolt init --pkcs11 \
  --module /usr/lib/x86_64-linux-gnu/pkcs11/p11-kit-client.so \
  --uri 'pkcs11:token=<TOKEN>;id=%01;type=private'

# or, to join an existing vault:
nvolt join --pkcs11 \
  --module /usr/lib/x86_64-linux-gnu/pkcs11/p11-kit-client.so \
  --uri 'pkcs11:token=<TOKEN>;id=%01;type=private'
```

`nvolt pkcs11 use` and `init|join --pkcs11` run the identical enroll flow: they
open a session, log in, validate the key (RSA, `>= 2048` bits, decrypt-capable),
run an OAEP-SHA256 self-test round-trip, and — only if all of that succeeds —
write the module path, URI, PIN mode, and the OAEP mode it proved (`native` or
`raw`) into this machine's `machine-info.json`, replacing the software keypair.
If a machine identity already exists, `nvolt pkcs11 use` accepts `--force` to
overwrite it (this also deletes any orphaned software private key left on
disk); `init --pkcs11` and `join --pkcs11` have no `--force` flag and always
error out if a machine identity is already initialized.

Flags (all under `nvolt pkcs11 use` and the `--pkcs11` branch of `init`/`join`):

| Flag | Meaning | Default |
|---|---|---|
| `--module` | Path to the PKCS#11 module (`.so`) | `$NVOLT_PKCS11_MODULE` |
| `--uri` | RFC 7512 `pkcs11:` URI naming the token + key (required) | — |
| `--pin-mode` | `prompt` \| `env` \| `none` | `prompt` |
| `--force` | Overwrite an existing machine identity (`nvolt pkcs11 use` only) | `false` |

PIN modes:
- `prompt` (default) — no-echo TTY prompt at unwrap time.
- `env` — reads `NVOLT_PKCS11_PIN` (useful for automation; weaker than a
  TTY prompt since the PIN sits in the environment).
- `none` — no PIN sent (pinpad-authenticated tokens that don't take a
  software PIN).

### Normal use after enrollment

Once enrolled, use `nvolt` exactly as with a software identity — `pull`/`push`
transparently open a PKCS#11 session and unwrap the vault's master AES key
on-card instead of reading `private_key.pem`:

```bash
nvolt pull
nvolt push
```

Each of these prompts for the PIN per the enrolled `--pin-mode` (or reads
`NVOLT_PKCS11_PIN` under `env` mode). If the YubiKey's PIV slot has a touch
policy set, you'll also be prompted to touch the key (see §7).

## 6. PIV key provisioning (if the token has no suitable key yet)

`nvolt pkcs11 list` only shows what's already on the card. If there's no RSA
key in the PIV slot you want to use, provision one first — either manually with
Yubico's own tooling, or via nvolt's on-card generation:

**Manual (Yubico tooling), e.g. slot `9d` (key management):**

```bash
ykman piv keys generate 9d pub.pem
# or:
yubico-piv-tool -a generate -s 9d
```

**Via nvolt** (works against any token/module that supports `C_GenerateKeyPair`,
e.g. SoftHSM2 always, real YubiKey PIV via OpenSC/ykcs11 depending on
firmware/module support):

```bash
nvolt pkcs11 generate \
  --module /usr/lib/x86_64-linux-gnu/pkcs11/p11-kit-client.so \
  --token '<TOKEN>' --label my-key --id 03 --bits 2048 --pin-mode prompt
```

`--token`, `--label`, and `--id` are required; `--bits` defaults to 2048 (the
nvolt minimum). The private key is generated on-card and never leaves the
device. After generating, run `nvolt pkcs11 use` (or `init --pkcs11`) with a
`pkcs11:` URI pointing at the new `id`/`token` to enroll it.

## 7. Troubleshooting

**"module not found" / `dlopen` failure.** `nvolt pkcs11 list|use|generate`
fails to open the `.so` at the given `--module` path. Check:
- Is the path correct for this distro (see §8)?
- **Is the p11-kit tunnel up?** — if you're pointed at `p11-kit-client.so`, that
  module only works while (a) the WSL-side `p11-kit server` from §3 is still
  running, (b) the `ssh -R` forward from §4 is still connected, and (c)
  `P11_KIT_SERVER_ADDRESS` on the remote points at the live forwarded socket. A
  closed SSH session or a WSL reboot silently breaks the chain; restart from §3.

**OAEP mode surprises.** At enroll time nvolt runs an OAEP-SHA256 self-test and
records `oaep_mode: native` or `oaep_mode: raw` in `machine-info.json`. Real
YubiKeys (and SoftHSM2, depending on version) frequently do **not** support
native `CKM_RSA_PKCS_OAEP`; nvolt automatically falls back to raw RSA
(`CKM_RSA_X_509`) on the card plus a software OAEP-SHA256 unpad in that case —
this is expected and not a misconfiguration. Do not assume native OAEP works
everywhere; if enrollment fails outright with "token cannot perform OAEP-SHA256
unwrap", neither mode round-tripped and the key/module combination cannot back
nvolt's wrap scheme.

**Touch policy.** If the PIV slot's key was generated with a touch policy
("always" or "cached"), `pull`/`push` will hang waiting for a physical touch on
the YubiKey after the PIN is accepted — touch the key's contact when its LED
flashes. A timeout with no touch surfaces as a decrypt failure.

**Fallback topology (USB/IP straight to the remote).** If WSL isn't available,
or the p11-kit hop is unreliable, `usbipd-win` (which speaks the standard
USB/IP protocol, not just the WSL-attach shortcut) can share the YubiKey
straight to the remote Linux box instead of to WSL: on Windows, `usbipd bind
--busid <BUSID>` as before; on the **remote** box, `usbip attach -r
<windows-ip> -b <BUSID>` (requires `usbip` client tools and the `vhci-hcd`
kernel module there, and TCP port 3240 reachable from the remote to Windows).

Note: the `usbip` client binary (e.g. Debian/Ubuntu's `usbip` or
`linux-tools-*` package) is only needed for this USB/IP-to-remote fallback —
it's a separate tool from the WSL-kernel-integrated `usbipd attach --wsl`
happy path in §2, which needs no `usbip` binary on the Linux side at all.
Don't expect `usbip` to be installed (or needed) in the normal WSL flow.

In that topology there's no p11-kit server/socket forward at all — `pcscd` +
`opensc-pkcs11.so` run directly on the remote, and `nvolt` points `--module` at
`opensc-pkcs11.so` there instead of `p11-kit-client.so`. This avoids the SSH
socket-forward step entirely but requires low-latency, stable network access
from the remote box straight to Windows over USB/IP, and loses the "just
re-plug locally" convenience of the WSL path.

## 8. Paths vary by distro

The `.so` paths in this runbook (`/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so`,
`/usr/lib/x86_64-linux-gnu/pkcs11/p11-kit-client.so`) are Debian/Ubuntu (amd64)
conventions. On other distros or architectures, find the real path with:

```bash
dpkg -L opensc-pkcs11 | grep pkcs11.so             # Debian/Ubuntu — opensc-pkcs11.so
dpkg -L p11-kit-modules | grep p11-kit-client.so   # Debian/Ubuntu — p11-kit-client.so
find / -name 'opensc-pkcs11.so' -o -name 'p11-kit-client.so' 2>/dev/null
```

Note: `opensc-pkcs11.so` ships in the `opensc-pkcs11` package (a dependency of
`opensc`, not `opensc` itself), so `dpkg -L opensc` will not find it.

and pass whatever it reports as `--module` (or set `NVOLT_PKCS11_MODULE`, which
every `nvolt pkcs11 *` subcommand and `init|join --pkcs11` fall back to when
`--module` is omitted).

## See also

- Design spec: [`docs/superpowers/specs/2026-07-11-nvolt-pkcs11-yubikey-design.md`](superpowers/specs/2026-07-11-nvolt-pkcs11-yubikey-design.md)
  — envelope-encryption background, the `crypto.Decrypter` seam, the OAEP
  validation spike, and why Phase 1 is purego + WSL/p11-kit.
