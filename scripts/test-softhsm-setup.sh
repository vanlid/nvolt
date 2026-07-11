#!/usr/bin/env bash
set -euo pipefail
export SOFTHSM2_CONF="${SOFTHSM2_CONF:-$PWD/.softhsm2/softhsm2.conf}"
TOKENDIR="$(dirname "$SOFTHSM2_CONF")/tokens"
# Idempotent: wipe any existing tokens so re-runs don't accumulate duplicate
# "nvolt-test" tokens/keys (which makes token/key selection ambiguous and
# breaks the integration tests). CI runs on a fresh runner; this matters for
# local re-runs.
rm -rf "$TOKENDIR"
mkdir -p "$TOKENDIR"
printf 'directories.tokendir = %s\nobjectstore.backend = file\n' "$TOKENDIR" > "$SOFTHSM2_CONF"
softhsm2-util --init-token --free --label nvolt-test --pin 1234 --so-pin 5678
MODULE="$(ls /usr/lib/softhsm/libsofthsm2.so /usr/lib/*/softhsm/libsofthsm2.so 2>/dev/null | head -1)"
pkcs11-tool --module "$MODULE" --token-label nvolt-test --login --pin 1234 \
  --keypairgen --key-type rsa:2048 --label nvolt-test --id 01
pkcs11-tool --module "$MODULE" --token-label nvolt-test --login --pin 1234 \
  --keypairgen --key-type rsa:1024 --label nvolt-weak --id 02
echo "MODULE=$MODULE"
echo "SOFTHSM2_CONF=$SOFTHSM2_CONF"
