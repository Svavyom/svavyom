# Release signing

Svavyom releases are signed with an **Ed25519** key, named `dbscodesignkey`. The private key is held offline by the maintainer and is never on a server. The public key is `release-signing-key.pub` in this directory and is repeated in the release notes.

```
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAQHNxmclfJBcP/YTreCAhs/eFDZzlOsRblUnAd8vJLUU=
-----END PUBLIC KEY-----
```

**Fingerprint:** `247e9193c933b6fa` (the first 16 hex digits of the SHA-256 of the DER form of the public key; `SIGNING-INFO.json` of a signed release names the same value).

Check it yourself before you trust it: `openssl pkey -pubin -in release-signing-key.pub -pubout -outform DER | sha256sum | cut -c1-16`. A key that arrives beside a release proves nothing: compare the fingerprint with the one in the project's README and release notes, obtained from a place you trust.

## Verifying a release
A signed release comes with a directory of signatures (`SHA256SUMS.ed25519`, `MANIFEST.json.ed25519`, `SIGNING-INFO.json`). The signature covers `SHA256SUMS` and `MANIFEST.json`; those list the SHA-256 of every file, so one valid signature covers the whole artifact.

```
svavyom-ctl verify-artifact DIR --signatures SIGDIR --public-key release-signing-key.pub
```
The signature check uses only the Go standard library; no `gpg` or other tool is involved. **Verify before you run anything from the artifact:** the `svavyom-ctl` inside an artifact is part of what is being verified. Use the `svavyom-ctl` already installed on the host (`/usr/libexec/svavyom/svavyom-ctl`) or check the two signatures with OpenSSL (3.0 or later):
```
for f in SHA256SUMS MANIFEST.json; do
  base64 -d SIGDIR/$f.ed25519 > /tmp/$f.sig
  openssl pkeyutl -verify -rawin -pubin -inkey release-signing-key.pub -in DIR/$f -sigfile /tmp/$f.sig
done
( cd DIR && sha256sum --quiet -c SHA256SUMS )
```

## Signing (the maintainer)
`make-ed25519-key.sh NAME [OUT_DIR]` makes a key pair once, on a machine you trust. `sign-artifact.sh ed25519 ARTIFACT_DIR OUT_DIR` signs an artifact that has passed `verify-artifact`, with `SIGN_KEY_FILE` (the private key) and `SIGN_PASSPHRASE` in the environment, never on a command line. It refuses to sign an artifact that does not match its `SHA256SUMS`.

## If the key is lost or exposed
Say so in the release notes, make a new key, publish its fingerprint beside the old one and sign the next release with the new key; users who verify must be told to trust the new fingerprint through a channel they trust. There is no automatic revocation in a preview release.

## Retired keys
* `a4671940514c19a7` was published in preview builds but never signed a release; its passphrase was lost on 2026-11-08 and it is retired. Do not trust a signature that names it.
