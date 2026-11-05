#!/bin/sh
# Creates the Ed25519 key pair that signs Svavyom releases, with OpenSSL (3.0 or later). Run it ONCE, on a machine you trust, and keep the private key offline.
# Usage: ci/sign/make-ed25519-key.sh NAME [OUT_DIR]        (OUT_DIR defaults to the current directory)
#   NAME.key  the private key: PKCS#8 PEM, encrypted with a passphrase you type (twice), mode 0600. NEVER commit it, copy it to a server or paste it anywhere.
#   NAME.pub  the public key: PEM. It is public: publish it in the release notes and README; users give it to `svavyom-ctl verify-artifact --public-key`.
# It prints the key's fingerprint (the same 16 hex digits ci/sign/sign-artifact.sh puts in SIGNING-INFO.json) and checks that the pair works by signing and verifying a test
# message. It refuses to overwrite an existing key. For a script or a test the passphrase can come from the environment (SIGN_NEW_PASSPHRASE); by hand, leave it unset.
set -eu
umask 077
name="${1:-}"; out="${2:-.}"
case "$name" in ''|*[!A-Za-z0-9._-]*) echo "usage: $0 NAME [OUT_DIR]   (NAME: letters, digits, . _ -; up to 64 characters)" >&2; exit 2 ;; esac
[ "${#name}" -le 64 ] || { echo "ERROR: the name is longer than 64 characters" >&2; exit 2; }
command -v openssl >/dev/null || { echo "ERROR: openssl is not installed" >&2; exit 2; }
case "$(openssl version 2>/dev/null)" in "OpenSSL 3."*|"OpenSSL 4."*|"OpenSSL 5."*) ;; *) echo "ERROR: OpenSSL 3.0 or later is needed (found: $(openssl version 2>/dev/null))" >&2; exit 2 ;; esac
[ -d "$out" ] || { echo "ERROR: $out is not a directory" >&2; exit 2; }
key="$out/$name.key"; pub="$out/$name.pub"
if [ -e "$key" ] || [ -e "$pub" ]; then echo "ERROR: $key or $pub already exists; refusing to overwrite a signing key" >&2; exit 1; fi
work=$(mktemp -d); trap 'rm -rf "$work"' EXIT INT TERM
if [ -n "${SIGN_NEW_PASSPHRASE:-}" ]; then
  export SVAVYOM_NEW_PASS="$SIGN_NEW_PASSPHRASE"
  openssl genpkey -algorithm ed25519 -aes-256-cbc -pass env:SVAVYOM_NEW_PASS -out "$key" 2>/dev/null
  passin="-passin env:SVAVYOM_NEW_PASS"
else
  echo "Choose a passphrase for the private key (you will be asked twice; write it down somewhere safe: without it the key is useless):"
  openssl genpkey -algorithm ed25519 -aes-256-cbc -out "$key"
  echo "Type the passphrase once more to check the key:"
  passin=""
fi
chmod 0600 "$key"
# shellcheck disable=SC2086
openssl pkey -in "$key" $passin -pubout -out "$pub"
chmod 0644 "$pub"
# the pair must work: sign a message with the private key, verify it with the public one
printf 'svavyom signing key self-test' > "$work/msg"
# shellcheck disable=SC2086
openssl pkeyutl -sign -rawin -inkey "$key" $passin -in "$work/msg" -out "$work/sig" 2>/dev/null || { rm -f "$key" "$pub"; echo "ERROR: the new key could not sign; nothing was kept" >&2; exit 1; }
openssl pkeyutl -verify -rawin -pubin -inkey "$pub" -in "$work/msg" -sigfile "$work/sig" >/dev/null 2>&1 || { rm -f "$key" "$pub"; echo "ERROR: the new pair does not verify; nothing was kept" >&2; exit 1; }
fp=$(openssl pkey -pubin -in "$pub" -pubout -outform DER 2>/dev/null | sha256sum | cut -c1-16)
echo
echo "created $key (PRIVATE: keep it offline, back it up on a second medium, never put it on a server)"
echo "created $pub (public: publish it)"
echo "fingerprint: $fp"
echo
echo "Public key (publish this in the release notes and README):"
cat "$pub"
