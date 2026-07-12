#!/usr/bin/env bash
#
# Build a self-contained wolfPKCS11 PKCS#11 module (wolfSSL + wolfTPM statically
# linked in) for nvolt's TPM-backed key source. The output is a single shared
# library with no wolf* runtime dependencies — only libc — suitable for
# embedding into the nvolt binary (see build/pkcs11/README.md) or shipping as a
# standalone module.
#
# Usage:
#   build/pkcs11/build-module.sh [OUTPUT_PATH]
#
# Environment overrides:
#   TPM_INTERFACE    devtpm | winapi | swtpm   (default: devtpm on Linux, winapi on
#                    Windows/MSYS). Use swtpm for CI/testing without hardware.
#   OUTPUT_PATH      where to copy the finished module
#                    (default: internal/pkcs11/dist/module.bin — the //go:embed path)
#   JOBS             parallel make jobs (default: nproc)
#   STATIC_ARCHIVES  when set to a directory, additionally install
#                    libwolfpkcs11.a/libwolftpm.a/libwolfssl.a and their headers
#                    into <dir>/lib and <dir>/include, for cgo static linking
#                    into nvolt-tpm. The shared module is still built either way.
#
# The result is stripped and its dependencies are printed for verification.
set -euo pipefail

# --- Pinned upstream versions (bump deliberately; these are the tested set) ---
# These are the fallback defaults used if build/pkcs11/versions.env is
# missing; when present, versions.env is sourced below and its values win.
# A version bump is then a one-line change to versions.env instead of here.
WOLFSSL_TAG=v5.9.2-stable
WOLFTPM_TAG=v4.1.0
WOLFPKCS11_TAG=v2.1.0-stable

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
if [[ -f "$SCRIPT_DIR/versions.env" ]]; then
  # shellcheck source=build/pkcs11/versions.env
  source "$SCRIPT_DIR/versions.env"
fi

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
OUTPUT_PATH=${1:-${OUTPUT_PATH:-"$REPO_ROOT/internal/pkcs11/dist/module.bin"}}
JOBS=${JOBS:-$(nproc 2>/dev/null || echo 4)}

# Resolve a relative STATIC_ARCHIVES against the repo root NOW, before we cd into
# the temp build dir: the install step below runs from $WORK, so a relative path
# would otherwise land in $WORK/<path> instead of the repo checkout.
if [ -n "${STATIC_ARCHIVES:-}" ]; then
  case "$STATIC_ARCHIVES" in
    /*) ;;
    *) STATIC_ARCHIVES="$REPO_ROOT/$STATIC_ARCHIVES" ;;
  esac
fi

# --- Target selection ---------------------------------------------------------
# TARGET=<os>-<arch> cross-compiles from a Linux host; unset builds natively.
# All four TPM targets build from one Linux box given the cross toolchains:
#   linux-arm64    -> gcc-aarch64-linux-gnu
#   windows-amd64  -> mingw-w64 (x86_64-w64-mingw32)
#   windows-arm64  -> llvm-mingw (aarch64-w64-mingw32)
# Darwin is intentionally unsupported: Macs have no TPM (Secure Enclave != TPM 2.0).
TARGET=${TARGET:-}
HOST_TRIPLE=""            # autotools --host (empty = native)
DEFAULT_IFACE=""
case "$TARGET" in
  ""|linux-amd64)  DEFAULT_IFACE=devtpm ;;                                    # native
  linux-arm64)     HOST_TRIPLE=aarch64-linux-gnu;    DEFAULT_IFACE=devtpm ;;
  windows-amd64)   HOST_TRIPLE=x86_64-w64-mingw32;   DEFAULT_IFACE=winapi ;;
  windows-arm64)   HOST_TRIPLE=aarch64-w64-mingw32;  DEFAULT_IFACE=winapi ;;
  darwin-*)        echo "darwin has no TPM 2.0 (Secure Enclave != TPM); no wolf module for macOS" >&2; exit 2 ;;
  *) echo "unknown TARGET: $TARGET (want linux-amd64|linux-arm64|windows-amd64|windows-arm64)" >&2; exit 2 ;;
esac

# --- wolfTPM hardware interface ---
TPM_INTERFACE=${TPM_INTERFACE:-$DEFAULT_IFACE}
case "$TPM_INTERFACE" in
  devtpm) TPM_FLAG=--enable-devtpm ;;
  winapi) TPM_FLAG=--enable-winapi ;;
  swtpm)  TPM_FLAG=--enable-swtpm ;;
  *) echo "unknown TPM_INTERFACE: $TPM_INTERFACE (want devtpm|winapi|swtpm)" >&2; exit 2 ;;
esac

# --- Cross-compile plumbing: --host makes autotools use <triple>-gcc etc. ---
HOST_FLAG=""
if [ -n "$HOST_TRIPLE" ]; then
  HOST_FLAG="--host=$HOST_TRIPLE"
  if ! command -v "${HOST_TRIPLE}-gcc" >/dev/null 2>&1 && ! command -v "${HOST_TRIPLE}-clang" >/dev/null 2>&1; then
    echo "cross toolchain for $TARGET not found (need ${HOST_TRIPLE}-gcc)" >&2; exit 3
  fi
fi

WORK=$(mktemp -d)
PREFIX="$WORK/prefix"
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$PREFIX"
export PKG_CONFIG_PATH="$PREFIX/lib/pkgconfig"

log() { printf '\n\033[1;32m== %s ==\033[0m\n' "$1" >&2; }

log "wolfSSL $WOLFSSL_TAG (single-threaded static; --enable-singlethreaded keeps the static link tests free of pthread symbols)"
git clone --depth 1 --branch "$WOLFSSL_TAG" https://github.com/wolfSSL/wolfssl.git "$WORK/wolfssl"
cd "$WORK/wolfssl"
./autogen.sh
# --disable-werror + specific -Wno-* flags: the Windows cross toolchains (mingw
# gcc, llvm-mingw clang) hit wolfSSL portability warnings promoted to errors —
# getpid() undeclared in random.c (-Werror=implicit-function-declaration, a
# *targeted* -Werror that a generic -Wno-error does NOT cancel) and
# -Wmissing-format-attribute in types.h. Disable werror at the source and
# suppress the underlying warnings so nothing is left to escalate.
./configure $HOST_FLAG --prefix="$PREFIX" --enable-static --disable-shared --enable-singlethreaded \
  --disable-examples --disable-crypttests --disable-werror \
  --enable-aescfb --enable-rsapss --enable-keygen --enable-pwdbased \
  --enable-scrypt --enable-cryptocb \
  C_EXTRA_FLAGS="-fPIC -Wno-error -Wno-implicit-function-declaration -Wno-nested-externs -Wno-missing-format-attribute -DWOLFSSL_PUBLIC_MP -DWC_RSA_DIRECT -DHAVE_AES_ECB -DHAVE_AES_KEYWRAP"
make -j"$JOBS"
make install

log "wolfTPM $WOLFTPM_TAG (interface: $TPM_INTERFACE)"
git clone --depth 1 --branch "$WOLFTPM_TAG" https://github.com/wolfSSL/wolfTPM.git "$WORK/wolfTPM"
cd "$WORK/wolfTPM"
./autogen.sh
./configure $HOST_FLAG --prefix="$PREFIX" --enable-static --disable-shared "$TPM_FLAG" \
  --disable-examples --with-wolfcrypt="$PREFIX" CFLAGS="-fPIC"
make -j"$JOBS"
make install

log "wolfPKCS11 $WOLFPKCS11_TAG (shared module; wolfSSL+wolfTPM baked in as static archives)"
git clone --depth 1 --branch "$WOLFPKCS11_TAG" https://github.com/wolfSSL/wolfPKCS11.git "$WORK/wolfPKCS11"
cd "$WORK/wolfPKCS11"
./autogen.sh
./configure $HOST_FLAG --prefix="$PREFIX" --enable-static --enable-singlethreaded --enable-wolftpm --disable-dh \
  --disable-examples --with-wolfcrypt="$PREFIX" \
  CPPFLAGS="-I$PREFIX/include" CFLAGS="-DWOLFPKCS11_TPM_STORE -I$PREFIX/include" \
  LDFLAGS="-L$PREFIX/lib"
make -j"$JOBS"

if [ -n "${STATIC_ARCHIVES:-}" ]; then
  log "installing static archives + headers to $STATIC_ARCHIVES (cgo static-link mode)"
  # wolfPKCS11 static archive is not installed by the shared-module build; add
  # --enable-static to its configure (above) and install here.
  make -C "$WORK/wolfPKCS11" install >/dev/null   # installs libwolfpkcs11.a when --enable-static
  mkdir -p "$STATIC_ARCHIVES/lib" "$STATIC_ARCHIVES/include"
  cp "$PREFIX"/lib/libwolfpkcs11.a "$PREFIX"/lib/libwolftpm.a "$PREFIX"/lib/libwolfssl.a "$STATIC_ARCHIVES/lib/"
  cp -r "$PREFIX"/include/wolfpkcs11 "$PREFIX"/include/wolfssl "$PREFIX"/include/wolftpm "$STATIC_ARCHIVES/include/"
  echo "static archives installed to $STATIC_ARCHIVES" >&2
fi

SO=$(find "$WORK/wolfPKCS11" \( -name 'libwolfpkcs11.so*' -o -name 'libwolfpkcs11*.dll' \) -type f | head -1)
[ -n "$SO" ] || { echo "build produced no module" >&2; exit 1; }

mkdir -p "$(dirname "$OUTPUT_PATH")"
cp "$SO" "$OUTPUT_PATH"
# Use the target's strip for cross builds (native strip can't touch PE/ARM objects).
STRIP="strip"; [ -n "$HOST_TRIPLE" ] && command -v "${HOST_TRIPLE}-strip" >/dev/null && STRIP="${HOST_TRIPLE}-strip"
"$STRIP" --strip-unneeded "$OUTPUT_PATH" 2>/dev/null || true

log "RESULT"
echo "target:  ${TARGET:-native ($(uname -s)-$(uname -m))}" >&2
echo "module:  $OUTPUT_PATH" >&2
echo "size:    $(ls -lh "$OUTPUT_PATH" | awk '{print $5}')" >&2
echo "type:    $(file -b "$OUTPUT_PATH" 2>/dev/null | cut -c1-60)" >&2
# ldd/readelf only meaningful for a native ELF; use readelf -d for cross ELF deps.
if [ -z "$HOST_TRIPLE" ]; then
  echo "deps (want no libwolfssl/libwolftpm):" >&2
  ldd "$OUTPUT_PATH" 2>/dev/null | sed 's/^/  /' >&2 || true
else
  echo "NEEDED (want no libwolfssl/libwolftpm; system libs only):" >&2
  { "${HOST_TRIPLE}-readelf" -d "$OUTPUT_PATH" 2>/dev/null || readelf -d "$OUTPUT_PATH" 2>/dev/null; } | grep NEEDED | sed 's/^/  /' >&2 || true
fi
