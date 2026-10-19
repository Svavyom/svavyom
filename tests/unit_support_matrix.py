"""Tests for tools/support_matrix.py (story M0-E02-S05 AC01, tier T0, simulated)."""
import contextlib
import importlib.util
import io
import os
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("support_matrix", ROOT / "tools" / "support_matrix.py")
sm = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sm)
FIXTURE = ROOT / "tests" / "fixtures" / "distribution" / "support-matrix.json"


def run(argv):
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        rc = sm.main(argv)
    return rc, out.getvalue()


class SupportMatrix(unittest.TestCase):
    def test_unusable_docs_repo_is_exit_2(self):
        with tempfile.TemporaryDirectory() as tmp:
            rc, out = run(["--docs-repo", tmp, "--check", str(FIXTURE)])
        self.assertEqual(rc, 2)
        self.assertIn("ERROR USAGE", out)

    @unittest.skipUnless(os.environ.get("DOCS_REPO"), "needs DOCS_REPO (set by make check)")
    def test_fixture_copy_equals_pinned_docs_matrix(self):
        self.assertEqual(run(["--docs-repo", os.environ["DOCS_REPO"], "--check", str(FIXTURE)])[0], 0)

    @unittest.skipUnless(os.environ.get("DOCS_REPO"), "needs DOCS_REPO (set by make check)")
    def test_drift_and_out_never_overwrites(self):
        with tempfile.TemporaryDirectory() as tmp:
            drift = Path(tmp, "m.json")
            drift.write_bytes(FIXTURE.read_bytes().replace(b'"26.04"', b'"26.10"'))
            self.assertEqual(run(["--docs-repo", os.environ["DOCS_REPO"], "--check", str(drift)])[0], 1)
            out = Path(tmp, "out.json")
            self.assertEqual(run(["--docs-repo", os.environ["DOCS_REPO"], "--out", str(out)])[0], 0)
            self.assertEqual(out.read_bytes(), FIXTURE.read_bytes())
            self.assertEqual(run(["--docs-repo", os.environ["DOCS_REPO"], "--out", str(out)])[0], 2)


if __name__ == "__main__":
    unittest.main()
