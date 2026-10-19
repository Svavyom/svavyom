#!/bin/sh
# Signs a Svavyom release artifact. Usage: ci/sign/sign-artifact.sh METHOD ARTIFACT_DIR OUT_DIR
#   METHOD        gpg | minisign | cosign-key | ed25519
#   ARTIFACT_DIR  release-out/svavyom-<version> (it must pass `svavyom-ctl verify-artifact` first)
#   OUT_DIR       where the signatures and SIGNING-INFO.json are written (created, mode 0755)
# What is signed: SHA256SUMS and MANIFEST.json. SHA256SUMS lists the digest of every file, so one valid signature covers the whole artifact.
# Credentials come from the environment, never from arguments (they would show in `ps`):
#   SIGN_KEY_FILE      path of the private key file (Jenkins "secret file" credential)
#   SIGN_PASSPHRASE    passphrase of that key (gpg, minisign); COSIGN_PASSWORD for cosign
# The script prints no key material, keeps its working files in a private temporary directory and removes them on exit.
# It can also be run by hand, offline, by the release owner: the pipeline is only one way of calling it (docs/SIGNING-OPTIONS.md).
set -eu
umask 077
method="${1:-}"; art="${2:-}"; out="${3:-}"
[ -n "$method" ] && [ -d "$art" ] && [ -n "$out" ] || { echo "usage: $0 gpg|minisign|cosign-key|ed25519 ARTIFACT_DIR OUT_DIR" >&2; exit 2; }
[ -f "$art/SHA256SUMS" ] && [ -f "$art/MANIFEST.json" ] || { echo "ERROR: $art is not a release artifact (no SHA256SUMS / MANIFEST.json)" >&2; exit 2; }
: "${SIGN_KEY_FILE:?SIGN_KEY_FILE is not set}"
[ -f "$SIGN_KEY_FILE" ] || { echo "ERROR: SIGN_KEY_FILE does not exist" >&2; exit 2; }
# the signatures must be about the files as they are now
( cd "$art" && sha256sum --quiet -c SHA256SUMS ) || { echo "ERROR: the artifact does not match its SHA256SUMS; refusing to sign" >&2; exit 1; }
mkdir -p "$out"; chmod 0755 "$out"
work=$(mktemp -d); trap 'rm -rf "$work"' EXIT INT TERM
files="SHA256SUMS MANIFEST.json"
fingerprint=""
case "$method" in
  gpg)
    command -v gpg >/dev/null || { echo "ERROR: gpg is not installed" >&2; exit 2; }
    export GNUPGHOME="$work/gnupg"; mkdir -m 0700 "$GNUPGHOME"
    pp=""; if [ -n "${SIGN_PASSPHRASE:-}" ]; then printf '%s' "$SIGN_PASSPHRASE" > "$work/pp"; pp="--pinentry-mode loopback --passphrase-file $work/pp"; fi
    # shellcheck disable=SC2086
    gpg --batch --quiet $pp --import "$SIGN_KEY_FILE" 2>/dev/null
    fingerprint=$(gpg --batch --with-colons --list-secret-keys | awk -F: '$1=="fpr"{print $10; exit}')
    [ -n "$fingerprint" ] || { echo "ERROR: no secret key found in SIGN_KEY_FILE" >&2; exit 1; }
    for f in $files; do
      # shellcheck disable=SC2086
      gpg --batch --quiet $pp --armor --detach-sign --local-user "$fingerprint" --output "$out/$f.asc" "$art/$f"
    done
    gpg --batch --armor --export "$fingerprint" > "$out/svavyom-release-signing-key.asc"
    ;;
  minisign)
    command -v minisign >/dev/null || { echo "ERROR: minisign is not installed" >&2; exit 2; }
    for f in $files; do
      printf '%s\n' "${SIGN_PASSPHRASE:-}" | minisign -S -s "$SIGN_KEY_FILE" -m "$art/$f" -x "$out/$f.minisig" -t "svavyom release $(cat "$art/VERSION" 2>/dev/null || basename "$art")" >/dev/null
    done
    fingerprint="minisign"
    ;;
  cosign-key)
    command -v cosign >/dev/null || { echo "ERROR: cosign is not installed" >&2; exit 2; }
    for f in $files; do
      cosign sign-blob --yes --key "$SIGN_KEY_FILE" --tlog-upload=false --output-signature "$out/$f.sig" "$art/$f" >/dev/null
    done
    fingerprint="cosign"
    ;;
  ed25519)
    # A bare Ed25519 key made with OpenSSL (>= 3.0): `openssl genpkey -algorithm ed25519 -out release.key` and `openssl pkey -in release.key -pubout -out release.pub`.
    # `svavyom-ctl verify-artifact --signatures DIR --public-key release.pub` verifies this method with no other tool installed.
    command -v openssl >/dev/null || { echo "ERROR: openssl is not installed" >&2; exit 2; }
    pass=""; if [ -n "${SIGN_PASSPHRASE:-}" ]; then export SVAVYOM_SIGN_PASS="$SIGN_PASSPHRASE"; pass="-passin env:SVAVYOM_SIGN_PASS"; fi
    for f in $files; do
      # shellcheck disable=SC2086
      openssl pkeyutl -sign -rawin -inkey "$SIGN_KEY_FILE" $pass -in "$art/$f" -out "$work/$f.raw" 2>/dev/null || { echo "ERROR: openssl could not sign $f (is the key an Ed25519 key?)" >&2; exit 1; }
      base64 -w0 < "$work/$f.raw" > "$out/$f.ed25519"; printf '\n' >> "$out/$f.ed25519"
    done
    fingerprint=$(openssl pkey -in "$SIGN_KEY_FILE" ${pass:+-passin env:SVAVYOM_SIGN_PASS} -pubout -outform DER 2>/dev/null | sha256sum | cut -c1-16)
    ;;
  *) echo "ERROR: unknown method $method" >&2; exit 2 ;;
esac
{
  printf '{\n  "method": "%s",\n  "key_fingerprint": "%s",\n  "signed_at": "%s",\n  "artifact": "%s",\n' "$method" "$fingerprint" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$(basename "$art")"
  printf '  "SHA256SUMS_sha256": "%s",\n  "MANIFEST_json_sha256": "%s"\n}\n' "$(sha256sum "$art/SHA256SUMS" | cut -d' ' -f1)" "$(sha256sum "$art/MANIFEST.json" | cut -d' ' -f1)"
} > "$out/SIGNING-INFO.json"
echo "signed $(basename "$art") with $method; signatures are in $out"
