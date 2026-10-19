"""Tests of the release-classification guard (tools/check_claims.py)."""
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import check_claims as cc  # noqa: E402

OK_README = "# Svavyom\nDevelopment Preview / Pre-Alpha\n"


def repo(files):
    d = tempfile.mkdtemp()
    for rel, text in {"README.md": OK_README, "docs/RELEASE-NOTES-DEVELOPMENT-PREVIEW.md": OK_README, **files}.items():
        p = Path(d) / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
    subprocess.run(["git", "init", "-q"], cwd=d, check=True)
    subprocess.run(["git", "add", "-A"], cwd=d, check=True)
    return d


class Claims(unittest.TestCase):
    def codes(self, files):
        return sorted({f[0] for f in cc.scan(repo(files))})

    def test_clean_repo_passes(self):
        self.assertEqual(self.codes({"docs/a.md": "Single host. Not production-ready; HA is excluded.\n"}), [])

    def test_each_overclaim_is_found(self):
        for text, code in (("A production-ready hypervisor manager.", "PRODUCTION_READY"), ("Our stable release is out.", "STABLE"),
                           ("Now with high availability!", "HA"), ("An enterprise-ready control plane.", "ENTERPRISE"), ("Zero-risk backups.", "ZERO_RISK"),
                           ("Supports live migration between hosts.", "LIVE_MIGRATION"), ("Multi-hypervisor support.", "MULTI_HOST"), ("Generally: general availability today.", "STABLE")):
            self.assertEqual(self.codes({"docs/x.md": text + "\n"}), [code], text)

    def test_ui_and_source_strings_are_scanned(self):
        self.assertEqual(self.codes({"frontend/src/a.tsx": '<p>This production-ready console...</p>\n'}), ["PRODUCTION_READY"])
        self.assertEqual(self.codes({"backend/x.go": 'const s = "enterprise-grade"\n'}), ["ENTERPRISE"])

    def test_a_denial_on_the_same_line_allows_the_words(self):
        for text in ("This is not production-ready.", "HA-ready: NOT SUPPORTED.", "Live migration is excluded from this launch.", "We never claim zero-risk backups."):
            self.assertEqual(self.codes({"docs/x.md": text + "\n"}), [], text)

    def test_the_classification_must_be_stated(self):
        d = repo({})
        (Path(d) / "README.md").write_text("# Svavyom\n")
        self.assertEqual({f[0] for f in cc.scan(d)}, {"CLASSIFICATION_MISSING"})

    def test_quoting_files_and_research_are_skipped(self):
        self.assertEqual(self.codes({"docs/LAUNCH-CLAIMS.md": "production-ready\n", "research/a.md": "enterprise-ready\n", "tests/t.py": "# stable release\n"}), [])


if __name__ == "__main__":
    unittest.main()
