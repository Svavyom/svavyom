"""Tests of the development certification tool (certification/certify.py, M4-E02-S01): never part of a release artifact."""
import base64
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "certification"))
import certify  # noqa: E402

HAVE_OPENSSL = shutil.which("openssl") is not None
RID = "qr-20261014-a1b2c3"


def artifact(d, version="0.1.0-preview.4"):
    a = Path(d) / f"svavyom-{version}"
    a.mkdir()
    (a / "MANIFEST.json").write_text(json.dumps({"version": version, "built_from": "abc123"}))
    (a / "SHA256SUMS").write_text("0" * 64 + "  MANIFEST.json\n")
    return a


def osrel(d, os_id="ubuntu", ver="24.04"):
    p = Path(d) / "os-release"
    p.write_text(f'ID={os_id}\nVERSION_ID="{ver}"\nPRETTY_NAME="x"\n')
    return str(p)


def results(out, statuses):
    out.mkdir(exist_ok=True)
    for s, st in statuses.items():
        (out / f"{RID}-{s}.log").write_text(f"log of {s}\n")
        (out / f"{RID}-{s}.result.json").write_text(json.dumps({"suite": s, "status": st, "exit": 0 if st == "PASS" else 1, "seconds": 1, "log": f"{RID}-{s}.log"}))


class Certify(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        self.suites = certify.load_matrix()["suites"]
        self.out = self.d / "ev"
        self.art = artifact(self.d)
        self.rec = self.d / "records"

    def collect(self, statuses=None, os_id="ubuntu", ver="24.04"):
        results(self.out, statuses or {s: "PASS" for s in self.suites})
        return certify.main(["collect", "--run-id", RID, "--out", str(self.out), "--artifact", str(self.art), "--records", str(self.rec), "--os-release", osrel(self.d, os_id, ver)])

    def record(self):
        return json.loads((self.rec / f"{RID}.json").read_text())

    def test_every_suite_passing_gives_a_pass_record_bound_to_the_artifact_and_host(self):
        self.assertEqual(self.collect(), 0)
        r = self.record()
        self.assertEqual(r["verdict"], "PASS")
        self.assertEqual(r["artifact"]["version"], "0.1.0-preview.4")
        self.assertEqual(r["host"]["os_id"], "ubuntu")
        self.assertEqual([s["suite"] for s in r["suites"]], self.suites)
        self.assertEqual(certify.check_record(r, self.out, self.art), [])

    def test_a_missing_suite_is_not_run_and_makes_the_record_incomplete_never_a_pass(self):
        self.collect({s: "PASS" for s in self.suites if s != "network"})
        r = self.record()
        self.assertEqual(r["verdict"], "INCOMPLETE")
        self.assertEqual([s["status"] for s in r["suites"] if s["suite"] == "network"], ["NOT_RUN"])

    def test_one_failure_fails_the_record(self):
        self.collect({**{s: "PASS" for s in self.suites}, "storage": "FAIL"})
        self.assertEqual(self.record()["verdict"], "FAIL")

    def test_a_record_is_never_overwritten(self):
        self.assertEqual(self.collect(), 0)
        self.assertEqual(self.collect(), 2)

    def test_tampering_with_evidence_the_artifact_the_verdict_or_the_suites_is_found(self):
        self.collect()
        r = self.record()
        (self.out / f"{RID}-lifecycle.log").write_text("edited\n")
        self.assertTrue(any("changed" in p for p in certify.check_record(r, self.out)))
        (self.art / "SHA256SUMS").write_text("1" * 64 + "  MANIFEST.json\n")
        self.assertTrue(any("sha256sums_sha256" in p for p in certify.check_record(r, None, self.art)))
        forged = json.loads(json.dumps(r))
        forged["suites"][0]["status"] = "FAIL"
        self.assertTrue(any("verdict" in p for p in certify.check_record(forged)))
        short = json.loads(json.dumps(r))
        short["suites"] = short["suites"][:-1]
        self.assertTrue(any("suites" in p for p in certify.check_record(short)))

    @unittest.skipUnless(HAVE_OPENSSL, "openssl is needed")
    def test_signature_verifies_and_breaks_on_any_change(self):
        self.collect()
        key, pub = self.d / "k.pem", self.d / "k.pub"
        subprocess.run(["openssl", "genpkey", "-algorithm", "ed25519", "-out", str(key)], check=True, capture_output=True)
        subprocess.run(["openssl", "pkey", "-in", str(key), "-pubout", "-out", str(pub)], check=True, capture_output=True)
        p = self.rec / f"{RID}.json"
        self.assertEqual(certify.main(["sign", str(p), "--key", str(key)]), 0)
        self.assertEqual(certify.main(["verify", str(p), "--pubkey", str(pub), "--evidence", str(self.out), "--artifact", str(self.art)]), 0)
        other, opub = self.d / "o.pem", self.d / "o.pub"
        subprocess.run(["openssl", "genpkey", "-algorithm", "ed25519", "-out", str(other)], check=True, capture_output=True)
        subprocess.run(["openssl", "pkey", "-in", str(other), "-pubout", "-out", str(opub)], check=True, capture_output=True)
        self.assertEqual(certify.main(["verify", str(p), "--pubkey", str(opub)]), 1, "another key must not verify")
        self.assertEqual(len(base64.b64decode(Path(str(p) + ".sig").read_text().strip())), 64)
        p.write_text(p.read_text().replace('"PASS"', '"FAIL"', 1))
        self.assertEqual(certify.main(["verify", str(p), "--pubkey", str(pub)]), 1, "an edited record must not verify")

    def test_the_matrix_lists_a_system_as_certified_only_by_a_passing_record_of_that_system(self):
        self.collect()
        out = self.d / "MATRIX.md"
        certify.main(["matrix", "--records", str(self.rec), "--out", str(out)])
        text = out.read_text()
        self.assertIn(f"| ubuntu-24.04 | supported | {RID} | no |", text)
        self.assertIn("| debian-13 | refused | none |", text)
        self.assertIn("| ubuntu-22.04 | refused | none |", text)

    def test_a_run_without_what_a_suite_needs_does_not_pass_it(self):
        out = self.d / "run"
        rc = certify.main(["run", "--run-id", RID, "--out", str(out), "--suites", "install,network"])
        self.assertEqual(rc, 0)  # nothing ran and nothing failed
        for s in ("install", "network"):
            self.assertEqual(json.loads((out / f"{RID}-{s}.result.json").read_text())["status"], "NOT_RUN")
        self.assertEqual(certify.main(["run", "--run-id", "bad", "--out", str(out)]), 2)
        self.assertEqual(certify.main(["run", "--run-id", RID, "--out", str(out), "--suites", "nonsense"]), 2)

    def test_the_planned_command_lines_hold_paths_never_secrets(self):
        class A:
            config, base, password_file, pubkey, ssh_key, image, run_id, out = "/etc/svavyom/provision.json", "http://127.0.0.1:8443", "/p/pw", "/k.pub", "/k", "debian", RID, "/ev"
        for s in certify.SUITE_SCRIPTS:
            argv = certify.suite_argv(s, A)
            self.assertIsNotNone(argv, s)
            self.assertNotIn("hunter2", " ".join(argv))
        self.assertIn("--password-file", certify.suite_argv("install", A))

    def test_the_release_tool_refuses_to_package_the_certification_directory(self):
        src = (ROOT / "tools" / "make_release.py").read_text()
        self.assertIn('rel.split("/")[0] == "certification"', src)
        self.assertNotIn("certification", (ROOT / "tools" / "make_release.py").read_text().split("PUBLIC_DIRS =")[1].split("\n")[0])


if __name__ == "__main__":
    unittest.main()
