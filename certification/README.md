# Certification (development and release tool)

This directory is **not part of any release artifact**. The product never runs it and never mentions it; `tools/make_release.py` refuses to package it,
and the boundary gate classifies it as internal. It exists so that a release owner can prove, on a real host, that a built artifact does what the
documents claim.

## What it does
`certify.py` runs the qualification suites of `tools/` (preflight, install, create, lifecycle, console, storage, network) in a fixed order against an
**installed** system, then writes one record that binds: the suite results (with the SHA-256 of every log and result file), the release artifact under
test (version, commit, the digests of `MANIFEST.json` and `SHA256SUMS`), the host (OS, kernel, libvirt, QEMU) and the digest of the tools that ran.
The record can be signed (Ed25519 with OpenSSL) and later verified by anyone holding the public key and the evidence directory.

```
python3 certification/certify.py run     --run-id qr-20261014-a1b2c3 --out EVIDENCE --config /etc/svavyom/provision.json --base http://127.0.0.1:8443 \
         --password-file PW --pubkey KEY.pub --ssh-key KEY --image ubuntu-24.04
python3 certification/certify.py collect --run-id qr-20261014-a1b2c3 --out EVIDENCE --artifact release-out/svavyom-VERSION
python3 certification/certify.py sign    certification/records/qr-20261014-a1b2c3.json --key RELEASE.key
python3 certification/certify.py verify  certification/records/qr-20261014-a1b2c3.json --pubkey RELEASE.pub --evidence EVIDENCE --artifact release-out/svavyom-VERSION
python3 certification/certify.py matrix
```
A suite that was not given what it needs is **NOT_RUN**, never silently passed, and a record with any NOT_RUN suite is INCOMPLETE. `run --dry-run` prints
the plan. The evidence directory holds logs from a real host: keep it out of git (`qualification-out/` is a private path); the record holds digests only.

## The regression matrix
`matrix.json` lists the operating systems the product is expected to support or refuse (Ubuntu 24.04 supported; other Ubuntu releases, Debian, Alma and
Rocky refused). The refusals are regression-tested in `backend/internal/ctl` (`TestRegressionMatrixOfHostSystems`) on every run of the Go tests; a row is
**certified** only by a PASS record from a real host of that system. `MATRIX.md` is generated from the records.

## Honest limits
One real host exists today, so only the Ubuntu 24.04 row can be certified, and a record made on this machine is a development record: it is not the
hosted, two-person-reviewed release evidence DR-004 requires before a release.
