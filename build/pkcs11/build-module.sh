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

# WOLF_DEBUG=1 compiles the wolf stack with DEBUG_WOLFTPM, so wolfTPM prints every
# TPM2 command and its response code (TPM_RC) to stderr. That turns an opaque
# CKR_FUNCTION_FAILED from C_Initialize into the actual failing operation +
# code — the difference between "storage hierarchy is Windows-owned" and "NV out
# of space" and "unsupported key template". Debug builds are NOT stripped (keep
# symbols/asserts). Only wired into the dev-channel debug artifacts; normal and
# release builds leave WOLF_DEBUG unset, so WOLF_DEBUG_DEFS is empty and nothing
# changes.
WOLF_DEBUG_DEFS=""
WOLF_DEBUG_STRIP=1
if [ "${WOLF_DEBUG:-0}" = "1" ]; then
  WOLF_DEBUG_DEFS="-DDEBUG_WOLFTPM"
  WOLF_DEBUG_STRIP=0
fi

# Token store: FILESYSTEM, not TPM-NVRAM. We keep -DWOLFPKCS11_TPM (keys are
# generated/wrapped/used inside the TPM) but deliberately do NOT define
# -DWOLFPKCS11_TPM_STORE. The NV-store path stores the token in TPM NVRAM, whose
# read/write needs a TPM hierarchy authorization that Windows owns and does not
# grant user apps — C_Initialize failed there with TPM_RC_AUTH_UNAVAILABLE on a
# TPM2_NV_Read. The filesystem store keeps only TPM-wrapped key blobs on disk
# (private keys never leave the TPM), and nvolt points WOLFPKCS11_TOKEN_PATH at
# its own config dir. (WOLFPKCS11_TPM and WOLFPKCS11_TPM_STORE are independent
# #ifdefs in wolfPKCS11, so dropping the latter does not downgrade keys to
# software.)

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

# wolfPKCS11's wp11_TpmInit (src/internal.c) has an unconditional printf that
# dumps the TPM caps banner ("Mfg AMD (0), Vendor AMD, Fw 6.32 ..., FIPS ...,
# CC-EAL4 ...") on EVERY C_Initialize. Embedded in nvolt that spams the banner
# on every command that touches the TPM. Gate the printf behind the
# NVOLT_TPM_CAPS env var so it is silent by default; nvolt sets NVOLT_TPM_CAPS=1
# only for `pkcs11 list` and when -v/--debug is on. getenv is already declared
# here: wolfpkcs11/pkcs11.h (included by internal.c) pulls in <stdlib.h> unless
# WOLFPKCS11_USER_ENV/NO_ENV is set, which this build never sets. Called right
# after each wolfPKCS11 clone, before it is configured/built (both the Windows
# cmake path and the Linux autotools path below share $WORK/wolfPKCS11).
patch_tpm_caps_banner() {
  perl -0pi -e 's/(\bprintf\("Mfg %s.*?cc_eal4\);)/if (getenv("NVOLT_TPM_CAPS") != NULL) { $1 }/s' \
    "$WORK/wolfPKCS11/src/internal.c"
}

# =============================================================================
# Windows targets: CMake cross-build (separate from the autotools path below).
# -----------------------------------------------------------------------------
# autotools+libtool cannot emit a self-contained DLL from the static wolf .a
# archives under mingw: libtool rewrites the link, drops -ldl and mishandles
# -no-undefined, so the shared-object link never succeeds (this is what failed
# for the windows targets, NOT mingw itself). CMake invokes `<triple>-gcc
# -shared` directly, bypassing libtool, and produces a wolfPKCS11.dll whose only
# runtime dependencies are Windows system DLLs — wolfSSL + wolfTPM are baked in
# as static archives, and the TPM backend talks to TBS (TPM Base Services), the
# native Windows TPM 2.0 API, so no wolf* or libgcc runtime DLL is needed.
#
# The Linux/musl autotools path below is untouched and still serves every
# linux-* target and the STATIC_ARCHIVES (nvolt-tpm-static) build.
# =============================================================================
if [[ "$TARGET" == windows-* ]]; then
  command -v cmake >/dev/null || { echo "cmake required for windows targets (>=3.24; older cmake leaks generator-expressions from the wolf imported configs)" >&2; exit 3; }
  command -v ninja >/dev/null || { echo "ninja required for windows targets" >&2; exit 3; }

  case "$TARGET" in
    windows-amd64) TRIPLE=x86_64-w64-mingw32;  SYSPROC=x86_64  ;;
    windows-arm64) TRIPLE=aarch64-w64-mingw32; SYSPROC=aarch64 ;;
  esac
  # Windows 10 API level. mingw's <tbs.h> only declares TBS_HCONTEXT (the handle
  # wolfTPM's WINAPI/TBS backend stores) when _WIN32_WINNT >= 0x0600; without it
  # the handle degrades to int and tpm2_winapi.c fails to compile (assigning NULL
  # to an int, which wolfTPM's -Werror makes fatal).
  WINNT=0x0A00

  TC="$WORK/toolchain-$TARGET.cmake"
  cat > "$TC" <<EOF
set(CMAKE_SYSTEM_NAME Windows)
set(CMAKE_SYSTEM_PROCESSOR $SYSPROC)
set(CMAKE_C_COMPILER  $TRIPLE-gcc)
set(CMAKE_RC_COMPILER $TRIPLE-windres)
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY BOTH)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE BOTH)
EOF

  cmake_build() { # <src-dir> <extra cmake args...>
    local src=$1; shift
    cmake -S "$src" -B "$src/build" -G Ninja \
      -DCMAKE_TOOLCHAIN_FILE="$TC" \
      -DCMAKE_PREFIX_PATH="$PREFIX" -DCMAKE_INSTALL_PREFIX="$PREFIX" \
      -DCMAKE_BUILD_TYPE=Release "$@" >&2
    cmake --build "$src/build" --parallel "$JOBS" >&2
  }

  log "wolfSSL $WOLFSSL_TAG (static, cmake cross -> $TRIPLE)"
  git clone --depth 1 --branch "$WOLFSSL_TAG" https://github.com/wolfSSL/wolfssl.git "$WORK/wolfssl"
  cmake_build "$WORK/wolfssl" -DBUILD_SHARED_LIBS=OFF \
    -DWOLFSSL_EXAMPLES=no -DWOLFSSL_CRYPT_TESTS=no -DWOLFSSL_SINGLE_THREADED=yes \
    -DWOLFSSL_AESCFB=yes -DWOLFSSL_KEYGEN=yes -DWOLFSSL_PWDBASED=yes \
    -DWOLFSSL_CRYPTOCB=yes -DWOLFSSL_PUBLIC_MP=yes -DWOLFSSL_WC_RSA_DIRECT=yes \
    -DWOLFSSL_AESKEYWRAP=yes -DWOLFSSL_RSA_PSS=yes \
    -DCMAKE_C_FLAGS="-DHAVE_AES_ECB -DWOLFSSL_PUBLIC_MP -DHAVE_SCRYPT"
  cmake --install "$WORK/wolfssl/build" >&2

  log "wolfTPM $WOLFTPM_TAG (static, WINAPI/TBS interface)"
  git clone --depth 1 --branch "$WOLFTPM_TAG" https://github.com/wolfSSL/wolfTPM.git "$WORK/wolfTPM"
  cmake_build "$WORK/wolfTPM" -DBUILD_SHARED_LIBS=OFF \
    -DWOLFTPM_EXAMPLES=OFF -DWOLFTPM_INTERFACE=WINAPI -DWOLFTPM_SINGLE_THREADED=yes \
    -DCMAKE_C_FLAGS="-D_WIN32_WINNT=$WINNT $WOLF_DEBUG_DEFS"
  cmake --install "$WORK/wolfTPM/build" >&2
  # wolfTPM's cmake install omits the example HAL header that wolfPKCS11's TPM
  # path #includes as <hal/tpm_io.h> (autotools installs it; cmake does not).
  # tpm_io.c itself is already compiled into libwolftpm.a, so staging the header
  # is enough. Mirrors the autotools layout ($PREFIX/include/hal/).
  mkdir -p "$PREFIX/include/hal"
  cp "$WORK/wolfTPM/hal/"*.h "$PREFIX/include/hal/"

  log "wolfPKCS11 $WOLFPKCS11_TAG (shared DLL; wolfSSL+wolfTPM baked in, TBS-backed)"
  git clone --depth 1 --branch "$WOLFPKCS11_TAG" https://github.com/wolfSSL/wolfPKCS11.git "$WORK/wolfPKCS11"
  patch_tpm_caps_banner   # gate the TPM caps-banner printf behind NVOLT_TPM_CAPS
  # Notes on the link flags:
  #  -ltbs (via CMAKE_C_STANDARD_LIBRARIES, so it lands LAST on the link line,
  #    after -lwolftpm): wolfPKCS11 links wolfTPM as a raw -lwolftpm rather than
  #    the wolftpm::wolftpm imported target, so it does not inherit wolfTPM's
  #    declared TBS dependency; add it explicitly or Tbsi_*/Tbsip_* stay undefined.
  #  -static-libgcc: drop the libgcc_s_seh-1.dll runtime dependency so the module
  #    loads on a stock Windows box with no mingw runtime present.
  #  -DWP11_DLL: wolfPKCS11's visibility.h leaves WP11_API empty on mingw unless
  #    WP11_DLL is defined; without it the C_* PKCS#11 entry points are never
  #    marked __declspec(dllexport) and C_GetFunctionList is not exported, so the
  #    module has no usable PKCS#11 interface. (Some wolfSSL/wolfTPM internal
  #    symbols also land in the export table via mingw ld's default auto-export;
  #    harmless bloat — nvolt resolves only C_GetFunctionList by name.)
  cmake -S "$WORK/wolfPKCS11" -B "$WORK/wolfPKCS11/build" -G Ninja \
    -DCMAKE_TOOLCHAIN_FILE="$TC" \
    -DCMAKE_PREFIX_PATH="$PREFIX" -DCMAKE_INSTALL_PREFIX="$PREFIX" \
    -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=ON \
    -DWOLFPKCS11_TPM=yes -DWOLFPKCS11_SINGLE_THREADED=yes \
    -DCMAKE_C_FLAGS="-D_WIN32_WINNT=$WINNT -DWP11_DLL $WOLF_DEBUG_DEFS" \
    -DCMAKE_SHARED_LINKER_FLAGS="-L$PREFIX/lib -static-libgcc" \
    -DCMAKE_C_STANDARD_LIBRARIES="-ltbs" >&2
  # Build only the library target: wolfPKCS11's examples #include <dlfcn.h>
  # (absent on Windows) and would fail the default `all` build.
  cmake --build "$WORK/wolfPKCS11/build" --target wolfpkcs11 --parallel "$JOBS" >&2

  # No `| head` here: under `pipefail`, head closing the pipe early would SIGPIPE
  # find and fail the assignment. -name '*.dll' excludes the *.dll.a import lib,
  # and the shared lib lands directly in build/, so this matches exactly one file.
  DLL=$(find "$WORK/wolfPKCS11/build" -maxdepth 1 -name 'libwolfpkcs11*.dll' -type f)
  [ -n "$DLL" ] || { echo "cmake build produced no wolfPKCS11 DLL" >&2; exit 1; }
  mkdir -p "$(dirname "$OUTPUT_PATH")"
  cp "$DLL" "$OUTPUT_PATH"
  [ "$WOLF_DEBUG_STRIP" = "1" ] && { "$TRIPLE-strip" --strip-unneeded "$OUTPUT_PATH" 2>/dev/null || true; }

  log "RESULT"
  echo "target:  $TARGET (cmake cross via $TRIPLE)" >&2
  echo "module:  $OUTPUT_PATH" >&2
  echo "size:    $(ls -lh "$OUTPUT_PATH" | awk '{print $5}')" >&2
  # Verify the PE export directory (survives strip, unlike the nm symbol table).
  # C_GetFunctionList is the single entry point nvolt resolves; assert on it.
  # NB1: read the WHOLE `objdump -p` dump, not a section slice — GNU binutils
  #   objdump (amd64/mingw) and LLVM objdump (arm64/llvm-mingw) format the export
  #   table completely differently, but both print the literal export names, so a
  #   substring match is toolchain-agnostic.
  # NB2: capture once and match with a bash `case` — piping objdump into `grep
  #   -q` would SIGPIPE objdump and, under `pipefail`, report a false failure on a
  #   *successful* match.
  EXPORTS=$("$TRIPLE-objdump" -p "$OUTPUT_PATH" 2>/dev/null)
  C_EXPORTS=$(printf '%s\n' "$EXPORTS" | grep -oE '\bC_[A-Za-z0-9_]+' | sort -u | wc -l)
  echo "exports: $C_EXPORTS PKCS#11 C_ functions" >&2
  case "$EXPORTS" in
    *C_GetFunctionList*) ;;
    *) echo "ERROR: module does not export C_GetFunctionList" >&2; exit 1 ;;
  esac
  echo "DLL deps (want system DLLs only; no libwolf*/libgcc):" >&2
  "$TRIPLE-objdump" -p "$OUTPUT_PATH" 2>/dev/null | awk '/DLL Name/{print "  "$3}' | sort -u >&2 || true
  exit 0
fi

log "wolfSSL $WOLFSSL_TAG (single-threaded static; --enable-singlethreaded keeps the static link tests free of pthread symbols)"
git clone --depth 1 --branch "$WOLFSSL_TAG" https://github.com/wolfSSL/wolfssl.git "$WORK/wolfssl"
cd "$WORK/wolfssl"
./autogen.sh
# wolfSSL portability fixes for the hardest cross / musl targets. These go on
# `make`, NOT `./configure`: configure's CFLAGS are also used for autoconf's
# feature tests, and -Wno-implicit-function-declaration there makes the compiler
# stop reporting undeclared functions, which aborts configure ("cannot make
# <cc> report undeclared builtins"). At make time the flags only affect the
# library build, and automake composes "$(AM_CFLAGS) $(CFLAGS)" so a `make
# CFLAGS=` lands after wolfSSL's own -Werror and wins.
#  - Windows (mingw gcc, llvm-mingw clang): random.c calls getpid() without a
#    header include -> implicit-decl / nested-extern errors. -include unistd.h
#    supplies the declaration (resolved from each compiler's OWN sysroot, so safe
#    on mingw/musl/glibc), so getpid emits no warning at all.
#  - Native musl aarch64: cpuid.c includes <asm/hwcap.h>, which musl-gcc doesn't
#    expose. For NATIVE builds only (empty --host) add the host kernel headers as
#    an idirafter fallback (musl's own headers still win); never for cross
#    builds, where host /usr/include is the wrong arch.
# NOTE: `make CFLAGS=` REPLACES the CFLAGS wolfSSL baked at configure time (which
# included -fPIC and the feature -D defines), so this must carry them itself —
# otherwise wolfSSL objects come out non-PIC and wolfPKCS11's shared-object link
# fails with "relocation ... can not be used when making a shared object".
WOLF_CFLAGS="-g -O2 -fPIC -include unistd.h -Wno-error -Wno-implicit-function-declaration -Wno-nested-externs -Wno-missing-format-attribute -DWOLFSSL_PUBLIC_MP -DWC_RSA_DIRECT -DHAVE_AES_ECB -DHAVE_AES_KEYWRAP"
if [ -z "$HOST_TRIPLE" ]; then
  MULTIARCH=$(gcc -print-multiarch 2>/dev/null || true)
  WOLF_CFLAGS="$WOLF_CFLAGS -idirafter /usr/include${MULTIARCH:+ -idirafter /usr/include/$MULTIARCH}"
fi
# configure stays clean so autoconf's function/decl detection works.
./configure $HOST_FLAG --prefix="$PREFIX" --enable-static --disable-shared --enable-singlethreaded \
  --disable-examples --disable-crypttests \
  --enable-aescfb --enable-rsapss --enable-keygen --enable-pwdbased \
  --enable-scrypt --enable-cryptocb \
  C_EXTRA_FLAGS="-fPIC -DWOLFSSL_PUBLIC_MP -DWC_RSA_DIRECT -DHAVE_AES_ECB -DHAVE_AES_KEYWRAP"
make -j"$JOBS" CFLAGS="$WOLF_CFLAGS"
make install

log "wolfTPM $WOLFTPM_TAG (interface: $TPM_INTERFACE)"
git clone --depth 1 --branch "$WOLFTPM_TAG" https://github.com/wolfSSL/wolfTPM.git "$WORK/wolfTPM"
cd "$WORK/wolfTPM"
./autogen.sh
./configure $HOST_FLAG --prefix="$PREFIX" --enable-static --disable-shared "$TPM_FLAG" \
  --disable-examples --with-wolfcrypt="$PREFIX" CFLAGS="-fPIC $WOLF_DEBUG_DEFS"
make -j"$JOBS"
make install

log "wolfPKCS11 $WOLFPKCS11_TAG (shared module; wolfSSL+wolfTPM baked in as static archives)"
git clone --depth 1 --branch "$WOLFPKCS11_TAG" https://github.com/wolfSSL/wolfPKCS11.git "$WORK/wolfPKCS11"
patch_tpm_caps_banner   # gate the TPM caps-banner printf behind NVOLT_TPM_CAPS
cd "$WORK/wolfPKCS11"
./autogen.sh
./configure $HOST_FLAG --prefix="$PREFIX" --enable-static --enable-singlethreaded --enable-wolftpm --disable-dh \
  --disable-examples --with-wolfcrypt="$PREFIX" \
  CPPFLAGS="-I$PREFIX/include" CFLAGS="-I$PREFIX/include $WOLF_DEBUG_DEFS" \
  LDFLAGS="-L$PREFIX/lib"
# On Windows, wolfPKCS11's examples #include <dlfcn.h> (Unix dlopen, absent on
# mingw), and --disable-examples doesn't stop `make all` building them — so build
# only the library (the module we embed). Its sources also use
# __attribute__((visibility)), unsupported on mingw (Windows uses dllexport),
# which wolfPKCS11's own -Werror makes fatal. `make CFLAGS=` overrides configure's
# CFLAGS, so re-add its -D/-I and drop -Werror; -include unistd.h mirrors the
# wolfSSL fix. Other targets keep plain `make all` unchanged.
if [[ "$HOST_TRIPLE" == *mingw* ]]; then
  make -j"$JOBS" src/libwolfpkcs11.la \
    CFLAGS="-g -O2 -I$PREFIX/include -include unistd.h -Wno-error -Wno-attributes $WOLF_DEBUG_DEFS"
else
  make -j"$JOBS"
fi

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
[ "$WOLF_DEBUG_STRIP" = "1" ] && { "$STRIP" --strip-unneeded "$OUTPUT_PATH" 2>/dev/null || true; }

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
