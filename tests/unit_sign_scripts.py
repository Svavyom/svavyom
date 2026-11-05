"""The release-signing scripts (ci/sign): the key generator makes a working Ed25519 pair, refuses to overwrite one and to take a bad name, and what it makes signs an artifact
through sign-artifact.sh in a way OpenSSL itself verifies under the public key. Needs openssl 3.x and sh; skipped where they are missing. (The Go verifier is tested against the
same scripts in backend/internal/ctl/signature_interop_test.go.)"""
import base64
import json
import os
import shutil
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MAKE = ROOT / "ci" / "sign" / "make-ed25519-key.sh"
SIGN = ROOT / "ci" / "sign" / "sign-artifact.sh"
PASS = "a test passphrase that is long enough"


def have_openssl3():
    if not shutil.which("openssl"):
        return False
    out = subprocess.run(["openssl", "version"], capture_output=True, text=True, check=False).stdout
    return out.startswith("OpenSSL 3.") or out.startswith("OpenSSL 4.") or out.startswith("OpenSSL 5.")


def run(argv, env=None, cwd=None):
    e = dict(os.environ)
    e.update(env or {})
    return subprocess.run(argv, capture_output=True, text=True, env=e, cwd=cwd, check=False)  # noqa: S603


@unittest.skipUnless(have_openssl3(), "needs openssl 3.x")
class Scripts(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def make(self, name="dbscodesignkey", out=None):
        return run(["sh", str(MAKE), name, str(out or self.tmp)], env={"SIGN_NEW_PASSPHRASE": PASS})

    def test_it_makes_an_encrypted_private_key_a_public_key_and_a_fingerprint(self):
        r = self.make()
        self.assertEqual(r.returncode, 0, r.stderr)
        key, pub = self.tmp / "dbscodesignkey.key", self.tmp / "dbscodesignkey.pub"
        self.assertEqual(stat.S_IMODE(key.stat().st_mode), 0o600)
        self.assertIn("ENCRYPTED PRIVATE KEY", key.read_text(), "the private key must be passphrase-protected")
        self.assertTrue(pub.read_text().startswith("-----BEGIN PUBLIC KEY-----"))
        self.assertRegex(r.stdout, r"fingerprint: [0-9a-f]{16}\n")
        self.assertNotIn(PASS, r.stdout + r.stderr)
        self.assertNotIn("PRIVATE KEY", r.stdout, "the private key is never printed")

    def test_it_refuses_to_overwrite_and_refuses_bad_names(self):
        self.assertEqual(self.make().returncode, 0)
        before = (self.tmp / "dbscodesignkey.key").read_bytes()
        r = self.make()
        self.assertEqual(r.returncode, 1)
        self.assertIn("refusing to overwrite", r.stderr)
        self.assertEqual((self.tmp / "dbscodesignkey.key").read_bytes(), before)
        for bad in ("", "a b", "../x", "x;y", "a" * 65):
            self.assertEqual(run(["sh", str(MAKE), bad, str(self.tmp)], env={"SIGN_NEW_PASSPHRASE": PASS}).returncode, 2, bad)
        self.assertEqual(run(["sh", str(MAKE), "ok", str(self.tmp / "missing")], env={"SIGN_NEW_PASSPHRASE": PASS}).returncode, 2)

    def test_what_it_makes_signs_an_artifact_and_openssl_verifies_it_under_the_public_key(self):
        self.assertEqual(self.make().returncode, 0)
        art = self.tmp / "svavyom-0.0.0-test"
        art.mkdir()
        (art / "VERSION").write_text("0.0.0-test\n")
        (art / "MANIFEST.json").write_text('{"version":"0.0.0-test"}\n')
        (art / "file.txt").write_text("hello\n")
        sums = subprocess.run(["sha256sum", "VERSION", "MANIFEST.json", "file.txt"], cwd=art, capture_output=True, text=True, check=True).stdout
        (art / "SHA256SUMS").write_text(sums)
        out = self.tmp / "sigs"
        r = run(["sh", str(SIGN), "ed25519", str(art), str(out)], env={"SIGN_KEY_FILE": str(self.tmp / "dbscodesignkey.key"), "SIGN_PASSPHRASE": PASS})
        self.assertEqual(r.returncode, 0, r.stderr)
        info = json.loads((out / "SIGNING-INFO.json").read_text())
        self.assertEqual(info["method"], "ed25519")
        fp = subprocess.run(["sh", "-c", "openssl pkey -pubin -in %s -pubout -outform DER | sha256sum | cut -c1-16" % (self.tmp / "dbscodesignkey.pub")],
                            capture_output=True, text=True, check=True).stdout.strip()
        self.assertEqual(info["key_fingerprint"], fp, "SIGNING-INFO names the fingerprint of the public key the generator printed")
        self.assertEqual(self.make("second").returncode, 0)
        for name in ("SHA256SUMS", "MANIFEST.json"):
            raw = base64.b64decode((out / (name + ".ed25519")).read_text().strip())
            sig = self.tmp / (name + ".sig")
            sig.write_bytes(raw)
            v = run(["openssl", "pkeyutl", "-verify", "-rawin", "-pubin", "-inkey", str(self.tmp / "dbscodesignkey.pub"), "-in", str(art / name), "-sigfile", str(sig)])
            self.assertEqual(v.returncode, 0, v.stdout + v.stderr)
            other = run(["openssl", "pkeyutl", "-verify", "-rawin", "-pubin", "-inkey", str(self.tmp / "second.pub"), "-in", str(art / name), "-sigfile", str(sig)])
            self.assertNotEqual(other.returncode, 0, "another key must not verify it")
        # a changed file is refused by the signer itself
        (art / "file.txt").write_text("changed\n")
        r = run(["sh", str(SIGN), "ed25519", str(art), str(self.tmp / "sigs2")], env={"SIGN_KEY_FILE": str(self.tmp / "dbscodesignkey.key"), "SIGN_PASSPHRASE": PASS})
        self.assertNotEqual(r.returncode, 0)


if __name__ == "__main__":
    unittest.main()
