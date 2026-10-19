#!/bin/sh
# Verifies a signed Svavyom release artifact. Usage: ci/sign/verify-artifact.sh METHOD ARTIFACT_DIR SIGNATURE_DIR [PUBLIC_KEY]
#   METHOD  gpg | minisign | cosign-key | ed25519
#   PUBLIC_KEY  the trusted public key you obtained out of band (gpg: .asc file, minisign: .pub, cosign: .pub). For gpg it defaults to the key
#               shipped next to the signatures, which only proves the signature is internally consistent: compare its fingerprint with the one
#               published by the release owner before trusting it.
# Checks, in order: the detached signature of SHA256SUMS and of MANIFEST.json, then every file of the artifact against SHA256SUMS.
# Exit 0 only when all of them hold. Needs the same tool that signed (gpg, minisign or cosign).
set -eu
method="${1:-}"; art="${2:-}"; sigs="${3:-}"; pub="${4:-}"
[ -n "$method" ] && [ -d "$art" ] && [ -d "$sigs" ] || { echo "usage: $0 gpg|minisign|cosign-key|ed25519 ARTIFACT_DIR SIGNATURE_DIR [PUBLIC_KEY]" >&2; exit 2; }
work=$(mktemp -d); trap 'rm -rf "$work"' EXIT INT TERM
case "$method" in
  gpg)
    command -v gpg >/dev/null || { echo "ERROR: gpg is not installed" >&2; exit 2; }
    [ -n "$pub" ] || pub="$sigs/svavyom-release-signing-key.asc"
    [ -f "$pub" ] || { echo "ERROR: no public key (pass it as the fourth argument)" >&2; exit 2; }
    export GNUPGHOME="$work/gnupg"; mkdir -m 0700 "$GNUPGHOME"
    gpg --batch --quiet --import "$pub" 2>/dev/null
    fpr=$(gpg --batch --with-colons --list-keys | awk -F: '$1=="fpr"{print $10; exit}')
    for f in SHA256SUMS MANIFEST.json; do
      gpg --batch --status-fd 1 --verify "$sigs/$f.asc" "$art/$f" 2>/dev/null | grep -q "^\[GNUPG:\] VALIDSIG $fpr " || { echo "ERROR: bad or missing signature for $f" >&2; exit 1; }
    done
    echo "signature valid, key fingerprint $fpr"
    ;;
  minisign)
    command -v minisign >/dev/null || { echo "ERROR: minisign is not installed" >&2; exit 2; }
    [ -f "$pub" ] || { echo "ERROR: minisign needs the public key as the fourth argument" >&2; exit 2; }
    for f in SHA256SUMS MANIFEST.json; do minisign -V -p "$pub" -m "$art/$f" -x "$sigs/$f.minisig" >/dev/null || { echo "ERROR: bad signature for $f" >&2; exit 1; }; done
    echo "signature valid"
    ;;
  cosign-key)
    command -v cosign >/dev/null || { echo "ERROR: cosign is not installed" >&2; exit 2; }
    [ -f "$pub" ] || { echo "ERROR: cosign needs the public key as the fourth argument" >&2; exit 2; }
    for f in SHA256SUMS MANIFEST.json; do cosign verify-blob --key "$pub" --insecure-ignore-tlog=true --signature "$sigs/$f.sig" "$art/$f" >/dev/null 2>&1 || { echo "ERROR: bad signature for $f" >&2; exit 1; }; done
    echo "signature valid"
    ;;
  ed25519)
    command -v openssl >/dev/null || { echo "ERROR: openssl is not installed" >&2; exit 2; }
    [ -f "$pub" ] || { echo "ERROR: ed25519 needs the public key as the fourth argument" >&2; exit 2; }
    for f in SHA256SUMS MANIFEST.json; do
      base64 -d < "$sigs/$f.ed25519" > "$work/$f.raw" 2>/dev/null || { echo "ERROR: bad signature file for $f" >&2; exit 1; }
      openssl pkeyutl -verify -rawin -pubin -inkey "$pub" -in "$art/$f" -sigfile "$work/$f.raw" >/dev/null 2>&1 || { echo "ERROR: bad signature for $f" >&2; exit 1; }
    done
    echo "signature valid"
    ;;
  *) echo "ERROR: unknown method $method" >&2; exit 2 ;;
esac
( cd "$art" && sha256sum --quiet -c SHA256SUMS ) || { echo "ERROR: a file does not match SHA256SUMS" >&2; exit 1; }
echo "every file matches the signed SHA256SUMS"
