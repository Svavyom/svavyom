"""tools/make_manifest.py (story M0-E01-S20): the manifest is made from the files, and refuses, with a typed finding and no output, when an input is missing or disagrees
with another. Everything here is synthetic: a made-up artifact, a made-up signing record, a made-up Ed25519 public key and two throw-away git repositories."""
import base64
import hashlib
import importlib.util
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("make_manifest", ROOT / "tools" / "make_manifest.py")
mm = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mm)

SPKI_PREFIX = bytes.fromhex("302a300506032b6570032100")
KEY_RAW = bytes(range(32))
OTHER_RAW = bytes(range(1, 33))
GATE_OK = "Ran 12 tests in 1.0s\n\nOK (skipped=1)\n\x1b[2m      Tests \x1b[22m \x1b[1m\x1b[32m445 passed\x1b[39m\x1b[22m\x1b[90m (445)\x1b[39m\nok  \texample/a\t1.2s\nok  \texample/b\t0.3s\nFAIL the signature does not match (an expected negative)\nmake check: all gates passed\n"
BROWSER_OK = "  135 passed (2.5m)\n"


def pem(raw):
    b = base64.b64encode(SPKI_PREFIX + raw).decode()
    return "-----BEGIN PUBLIC KEY-----\n%s\n-----END PUBLIC KEY-----\n" % b


def fingerprint(raw):
    return hashlib.sha256(SPKI_PREFIX + raw).hexdigest()[:16]


def sha(b):
    return hashlib.sha256(b).hexdigest()


def git_repo(path, files):
    path.mkdir(parents=True, exist_ok=True)
    for rel, body in files.items():
        p = path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(body)
    env = dict(os.environ, GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@example.org", GIT_COMMITTER_NAME="t", GIT_COMMITTER_EMAIL="t@example.org")
    for cmd in (["init", "-q"], ["add", "-A"], ["commit", "-q", "-m", "x"]):
        subprocess.run(["git", "-C", str(path), *cmd], check=True, env=env, capture_output=True)  # noqa: S603,S607
    return subprocess.run(["git", "-C", str(path), "rev-parse", "HEAD"], check=True, capture_output=True, text=True).stdout.strip()  # noqa: S603,S607


class Rig:
    def __init__(self, tmp):
        self.tmp = Path(tmp)
        t = self.tmp
        self.docs = t / "docs"
        self.docs_sha = git_repo(self.docs, {
            "decisions/index.json": json.dumps({"decisions": [
                {"id": "DR-034", "title": "Certificates", "status": "approved", "options_chosen": {"D1": "A"}, "stories": ["M0-E01-S19"]},
                {"id": "DR-042", "title": "Boot start", "status": "approved", "options_chosen": {"D1": "A"}, "stories": ["M0-E01-S18"]}]}),
            "backlog/stories.json": json.dumps({"stories": [{"id": "M0-E01-S18", "status": "verified"}, {"id": "M0-E01-S19", "status": "in-progress"}]}),
            "docs/KNOWN-LIMITATIONS.md": "# limits\n"})
        self.art = t / "svavyom-9.9.9"
        files = {"bin/api": b"api bytes", "docs/sbom/sbom.cdx.json": json.dumps({"components": [{}, {}, {}]}).encode(), "docs/sbom/licenses.json": b"{}", "THIRD-PARTY-NOTICES.md": b"notices"}
        for rel, body in files.items():
            (self.art / rel).parent.mkdir(parents=True, exist_ok=True)
            (self.art / rel).write_bytes(body)
        self.repo = t / "repo"
        self.built = git_repo(self.repo, {"docs-lock.json": json.dumps({"schema": 1, "commit": self.docs_sha}), "docs/sbom/go-modules.txt": "mod v1\n",
                                           "contracts/threats/review-findings.json": json.dumps({"findings": [{"id": "F-11", "severity": "low", "status": "open"}, {"id": "F-01", "severity": "high", "status": "fixed"}]})})
        manifest = {"schema": 1, "product": "svavyom", "version": "9.9.9", "classification": "Test", "license": "AGPL", "built_from": self.built, "schema_versions": {},
                    "files": [{"path": p, "sha256": sha(b), "size": len(b), "mode": 420, "audience": "public"} for p, b in sorted(files.items())]}
        (self.art / "MANIFEST.json").write_text(json.dumps(manifest))
        (self.art / "SHA256SUMS").write_text("".join("%s  %s\n" % (sha(b), p) for p, b in sorted(files.items())))
        self.sigs = t / "sigs"
        self.sigs.mkdir()
        self.write_info()
        self.pub = t / "key.pub"
        self.pub.write_text(pem(KEY_RAW))
        self.gate = t / "gate.log"
        self.gate.write_text(GATE_OK)
        self.out = t / "out"

    def write_info(self, **over):
        info = {"method": "ed25519", "key_fingerprint": fingerprint(KEY_RAW), "signed_at": "2026-11-13T03:08:50Z", "artifact": "svavyom-9.9.9",
                "SHA256SUMS_sha256": sha((self.art / "SHA256SUMS").read_bytes()), "MANIFEST_json_sha256": sha((self.art / "MANIFEST.json").read_bytes())}
        info.update(over)
        (self.sigs / "SIGNING-INFO.json").write_text(json.dumps(info))

    def argv(self, **over):
        a = {"--artifact": self.art, "--signatures": self.sigs, "--public-key": self.pub, "--gate-log": self.gate, "--ci-run": "https://github.com/o/r/actions/runs/123",
             "--ci-conclusion": "success", "--docs-repo": self.docs, "--repo": self.repo, "--out": self.out}
        a.update(over)
        return [x for k, v in a.items() for x in (k, str(v))]

    def run(self, **over):
        o, e = io.StringIO(), io.StringIO()
        with redirect_stdout(o), redirect_stderr(e):
            rc = mm.main(self.argv(**over))
        return rc, o.getvalue(), e.getvalue()


class ManifestGenerator(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.r = Rig(self.tmp)

    def failed_with(self, code, **over):
        rc, _, err = self.r.run(**over)
        self.assertEqual(rc, 1, err)
        self.assertIn("ERROR " + code, err)
        self.assertFalse(self.r.out.exists(), "a refused manifest writes nothing")

    def test_it_reproduces_the_facts_of_the_files(self):
        rc, out, err = self.r.run()
        self.assertEqual(rc, 0, err)
        m = json.loads((self.r.out / "RELEASE-MANIFEST-9.9.9.json").read_text())
        self.assertEqual(m["built_from"], self.r.built)
        self.assertEqual(m["docs_pin"], self.r.docs_sha)
        self.assertEqual(m["artifact"]["files"], 4)
        self.assertEqual(m["artifact"]["SHA256SUMS_sha256"], sha((self.r.art / "SHA256SUMS").read_bytes()))
        self.assertEqual(m["sbom"]["components"], 3)
        self.assertEqual(set(m["sbom"]["files"]), {"docs/sbom/sbom.cdx.json", "docs/sbom/licenses.json", "THIRD-PARTY-NOTICES.md", "docs/sbom/go-modules.txt"})
        self.assertEqual(m["signature"]["key_fingerprint"], fingerprint(KEY_RAW))
        self.assertEqual([b["decision"] for b in m["blockers"]], ["DR-034", "DR-042"])
        self.assertEqual(m["blockers"][0]["stories"], {"M0-E01-S19": "in-progress"})
        self.assertEqual(m["open_findings"], ["F-11 (low)"])
        self.assertEqual(m["gate"]["frontend_tests"], 445)
        self.assertEqual(m["gate"]["python_tests"], 12)
        self.assertEqual(m["gate"]["go_packages_ok"], 2)

    def test_the_markdown_has_the_sections_and_leaves_the_sign_off_empty(self):
        self.r.run()
        md = (self.r.out / "RELEASE-MANIFEST-9.9.9.md").read_text()
        for h in ("## Provenance", "## CI and gates", "## Bill of materials", "## Test summaries", "## Release blockers", "## Known limitations", "## Human sign-off"):
            self.assertIn(h, md)
        self.assertIn("Release manager: ______________________ Date: __________", md)
        self.assertIn("not made", md)
        self.assertIn("not run for this manifest", md)

    def test_an_archive_and_a_browser_log_are_added_when_given(self):
        arc = Path(self.tmp) / "svavyom-9.9.9.tar.gz"
        arc.write_bytes(b"archive")
        bl = Path(self.tmp) / "browser.log"
        bl.write_text(BROWSER_OK)
        rc, _, err = self.r.run(**{"--archive": arc, "--browser-log": bl})
        self.assertEqual(rc, 0, err)
        m = json.loads((self.r.out / "RELEASE-MANIFEST-9.9.9.json").read_text())
        self.assertEqual(m["artifact"]["archive"], {"name": arc.name, "sha256": sha(b"archive")})
        self.assertEqual(m["gate"]["browser_passed"], 135)

    def test_a_browser_log_with_a_failure_is_refused(self):
        bl = Path(self.tmp) / "browser.log"
        bl.write_text("  1 failed\n  134 passed (2m)\n")
        self.failed_with("GATE_NOT_PASSED", **{"--browser-log": bl})

    def test_a_file_that_changed_after_the_artifact_was_made_is_refused(self):
        (self.r.art / "bin/api").write_bytes(b"tampered")
        self.failed_with("DIGEST_MISMATCH")

    def test_a_signing_record_for_other_digests_is_refused(self):
        self.r.write_info(SHA256SUMS_sha256="0" * 64)
        self.failed_with("SIGNING_INFO_MISMATCH")

    def test_a_signing_record_for_another_artifact_is_refused(self):
        self.r.write_info(artifact="svavyom-1.0.0")
        self.failed_with("SIGNING_INFO_MISMATCH")

    def test_a_key_whose_fingerprint_is_not_the_recorded_one_is_refused(self):
        self.r.pub.write_text(pem(OTHER_RAW))
        self.failed_with("FINGERPRINT_MISMATCH")

    def test_a_gate_log_that_does_not_end_in_all_gates_passed_is_refused(self):
        self.r.gate.write_text(GATE_OK.replace("make check: all gates passed", "make: *** [x] Error 1"))
        self.failed_with("GATE_NOT_PASSED")

    def test_a_ci_run_that_did_not_pass_or_is_not_a_run_url_is_refused(self):
        self.failed_with("CI_NOT_PASSED", **{"--ci-conclusion": "failure"})
        self.failed_with("BAD_INPUT", **{"--ci-run": "not a url"})

    def test_a_commit_or_a_docs_pin_the_repositories_do_not_know_is_refused(self):
        m = json.loads((self.r.art / "MANIFEST.json").read_text())
        m["built_from"] = "a" * 40
        (self.r.art / "MANIFEST.json").write_text(json.dumps(m))
        self.r.write_info()
        self.failed_with("COMMIT_UNKNOWN")
        m["built_from"] = self.r.built
        (self.r.art / "MANIFEST.json").write_text(json.dumps(m))
        self.r.write_info()
        (self.r.repo / "docs-lock.json").write_text(json.dumps({"commit": "b" * 40}))
        self.failed_with("DOCS_PIN_UNKNOWN")

    def test_a_missing_input_is_named(self):
        self.r.gate.unlink()
        self.failed_with("MISSING_INPUT")

    def test_an_unknown_blocker_is_refused_and_evidence_must_exist(self):
        self.failed_with("BAD_INPUT", **{"--blockers": "DR-999"})
        rc, _, err = self.r.run(**{"--evidence": "evidence/none"})
        self.assertEqual(rc, 1)
        self.assertIn("MISSING_INPUT", err)

    def test_the_output_carries_no_host_address_or_secret_from_the_tool_itself(self):
        self.r.run()
        text = (self.r.out / "RELEASE-MANIFEST-9.9.9.md").read_text()
        self.assertNotRegex(text, r"\b\d{1,3}(\.\d{1,3}){3}\b")
        self.assertNotIn("PRIVATE KEY", text)


class GateLog(unittest.TestCase):
    def test_colours_are_stripped_and_the_largest_python_suite_is_reported(self):
        g = mm.summarize_gate_log(GATE_OK + "Ran 300 tests in 9s\n\nOK\n")
        self.assertEqual((g["frontend_tests"], g["python_tests"], g["passed"]), (445, 300, True))

    def test_a_failed_suite_is_not_counted_as_passing(self):
        g = mm.summarize_gate_log("Ran 5 tests in 1s\n\nFAILED (failures=1)\n")
        self.assertIsNone(g["python_tests"])
        self.assertFalse(g["passed"])


if __name__ == "__main__":
    unittest.main()
