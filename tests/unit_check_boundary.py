"""Tests of the public/private boundary check (tools/check_boundary.py)."""
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import check_boundary as cb  # noqa: E402

CFG = {"schema": 1, "public": ["README.md", "backend/**"], "internal": ["tests/**"], "private": ["**/*.key", "**/.env", "**/*.db", "**/qualification-out/**"],
       "private_exceptions": [], "content_markers": ["OPENSSH PRIVATE KEY"], "content_marker_exceptions": ["tests/**", "release/**"]}


def repo(files, cfg=CFG):
    d = tempfile.mkdtemp()
    for rel, text in {"release/boundary.json": json.dumps(cfg), **files}.items():
        p = Path(d) / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
    subprocess.run(["git", "init", "-q"], cwd=d, check=True)
    subprocess.run(["git", "add", "-A"], cwd=d, check=True)
    return d


class Boundary(unittest.TestCase):
    def codes(self, files, cfg=CFG):
        return sorted({f[0] for f in cb.check(repo({"release/x": "", **files}, dict(cfg, public=cfg["public"] + ["release/**"])))})

    def test_glob_semantics(self):
        self.assertTrue(cb.glob("backend/**", "backend/a/b/c.go"))
        self.assertTrue(cb.glob("docs/*.md", "docs/a.md"))
        self.assertFalse(cb.glob("docs/*.md", "docs/sub/a.md"))
        self.assertTrue(cb.glob("**/*.key", "a/b/server.key"))
        self.assertTrue(cb.glob("**/*.key", "server.key"))
        self.assertFalse(cb.glob("**/*.key", "server.keys"))

    def test_clean_tree_passes(self):
        self.assertEqual(self.codes({"README.md": "x", "backend/a.go": "x", "tests/t.py": "x"}), [])

    def test_unclassified_path_fails(self):
        self.assertEqual(self.codes({"README.md": "x", "surprise/new.txt": "x"}), ["BOUNDARY_UNCLASSIFIED"])

    def test_ambiguous_path_fails(self):
        self.assertEqual(self.codes({"tests/a": "x"}, dict(CFG, public=["tests/**"])), ["BOUNDARY_AMBIGUOUS"])

    def test_private_patterns_are_refused_when_tracked(self):
        for rel in ("backend/server.key", "backend/.env", "backend/state/svavyom.db", "backend/qualification-out/r/x"):
            self.assertIn("PRIVATE_TRACKED", self.codes({rel: "x"}), rel)

    def test_private_key_blocks_are_found_outside_tests(self):
        armor = "-----" + "BEGIN OPENSSH PRIVATE KEY" + "-----"  # built at run time: this file must not look like a key to secret scanners
        self.assertEqual(self.codes({"backend/notes.md": armor + "\nAAAA\n"}), ["PRIVATE_KEY_IN_TREE"])
        self.assertEqual(self.codes({"tests/fixture.txt": armor + "\n"}), [])

    def test_the_committed_boundary_classifies_this_repository(self):
        self.assertEqual(cb.check(Path(__file__).resolve().parents[1]), [])


if __name__ == "__main__":
    unittest.main()
