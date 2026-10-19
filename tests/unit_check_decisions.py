"""Tests for tools/check_decisions.py (story M0-E01-S03, tier T0, simulated).

Every test builds throwaway docs and platform git repositories in a
temporary directory; no host state, network or privileged access is used.
Decision ids such as DR-098 and DR-404 below are unregistered fixtures
(files under tests/ are excluded from the dependency scan).
"""
import hashlib
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CHECKER = ROOT / "tools" / "check_decisions.py"
spec = importlib.util.spec_from_file_location("check_decisions", CHECKER)
cd = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cd)

GIT_ENV = {
    **os.environ,
    "GIT_AUTHOR_NAME": "test", "GIT_AUTHOR_EMAIL": "test@example.invalid",
    "GIT_COMMITTER_NAME": "test", "GIT_COMMITTER_EMAIL": "test@example.invalid",
    "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1", "GIT_OPTIONAL_LOCKS": "0",
}


def git(repo, *args):
    return subprocess.run(["git", "-C", str(repo), *args], env=GIT_ENV, check=True,
                          capture_output=True).stdout.decode().strip()


def record(rid, status="approved", options=None):
    return {"id": rid, "status": status, "options_chosen": options or {}}


def snapshot(repo):
    digest = hashlib.sha256()
    for path in sorted(Path(repo).rglob("*")):
        if path.is_file() and not path.is_symlink():
            digest.update(str(path.relative_to(repo)).encode())
            digest.update(path.read_bytes())
    return digest.hexdigest()


class Fixture(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.docs = self.root / "docs"
        self.platform = self.root / "platform"
        for repo in (self.docs, self.platform):
            repo.mkdir()
            git(repo, "init", "-q", "-b", "main")
        (self.docs / "README.md").write_text("docs\n")
        self.pre_register = self.docs_commit("pre-register")
        self.deps = {"DR-006": {"D2": "A"}, "ADR-001": {}}

    def docs_commit(self, message, records=None):
        if records is not None:
            (self.docs / "decisions").mkdir(exist_ok=True)
            (self.docs / "decisions" / "index.json").write_text(json.dumps(
                {"schema": 1, "register_baseline": None, "decisions": records}))
        git(self.docs, "add", "-A")
        git(self.docs, "commit", "-q", "--allow-empty", "-m", message)
        return git(self.docs, "rev-parse", "HEAD")

    def good_register(self):
        return [record("DR-006", options={"D1": "A", "D2": "A", "D3": "A"}), record("ADR-001")]

    def platform_tree(self, pinned, files=None, deps=None):
        (self.platform / "docs-lock.json").write_text(json.dumps(
            {"schema": 1, "docs_repo": "cloud-product-docs", "commit": pinned}))
        (self.platform / "contracts").mkdir(exist_ok=True)
        (self.platform / "contracts" / "decision-deps.json").write_text(json.dumps(
            {"schema": 1, "decisions": self.deps if deps is None else deps}))
        default = {"tools/x.py": "# relies on DR-006 and ADR-001\n"}
        for name, text in (default if files is None else files).items():
            path = self.platform / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text)
        git(self.platform, "add", "-A")

    def run_check(self):
        raw = lambda name: (self.platform / name).read_bytes()  # noqa: E731
        return cd.check(str(self.platform), str(self.docs), raw("contracts/decision-deps.json"), raw("docs-lock.json"))

    def codes(self):
        return sorted({f[0] for f in self.run_check()})


class Positive(Fixture):
    def test_approved_at_pin_and_tip(self):
        pinned = self.docs_commit("register", self.good_register())
        self.docs_commit("later unrelated change")
        self.platform_tree(pinned)
        self.assertEqual(self.run_check(), [])

    def test_extra_options_in_register_are_fine(self):
        pinned = self.docs_commit("register", self.good_register())
        self.platform_tree(pinned, deps={"DR-006": {"D1": "A", "D3": "A"}, "ADR-001": {}})
        self.assertEqual(self.run_check(), [])

    def test_tests_directory_and_untracked_files_are_excluded(self):
        pinned = self.docs_commit("register", self.good_register())
        self.platform_tree(pinned, files={"tools/x.py": "DR-006 ADR-001\n",
                                          "tests/unit_y.py": "fixture ids DR-098 DR-404\n"})
        (self.platform / "notes.txt").write_text("untracked DR-404\n")
        self.assertEqual(self.run_check(), [])

    def test_token_boundaries(self):
        pinned = self.docs_commit("register", self.good_register())
        self.platform_tree(pinned, files={"tools/x.py": "DR-006 ADR-001 XDR-404 DR-0060 DR-NNN DR-12\n"})
        self.assertEqual(self.run_check(), [])


class Negative(Fixture):
    def test_undeclared_dependency(self):
        pinned = self.docs_commit("register", self.good_register())
        self.platform_tree(pinned, files={"docs/X.md": "See DR-404.\n"})
        findings = self.run_check()
        self.assertEqual({f[0] for f in findings}, {"DECISION_DEP_UNDECLARED"})
        self.assertIn("DR-404", {f[1] for f in findings})

    def test_approved_at_pin_but_superseded_at_tip(self):
        pinned = self.docs_commit("register", self.good_register())
        self.docs_commit("supersede", [record("DR-006", "superseded", {"D1": "A", "D2": "A", "D3": "A"}),
                                       record("ADR-001")])
        self.platform_tree(pinned)
        findings = self.run_check()
        self.assertEqual({f[0] for f in findings}, {"DECISION_NOT_APPROVED_AT_TIP"})
        self.assertTrue(any("tip" in f[2] and f[1] == "DR-006" for f in findings), findings)

    def test_approved_at_tip_but_not_at_pin(self):
        pinned = self.docs_commit("proposed", [record("DR-006", "proposed"), record("ADR-001")])
        self.docs_commit("approved", self.good_register())
        self.platform_tree(pinned)
        findings = self.run_check()
        self.assertEqual({(f[0], f[1]) for f in findings}, {("DECISION_NOT_APPROVED_AT_TIP", "DR-006")})
        self.assertIn("pinned", findings[0][2])

    def test_required_option_mismatch(self):
        pinned = self.docs_commit("register", [record("DR-006", options={"D2": "B"}), record("ADR-001")])
        self.platform_tree(pinned)
        self.assertEqual(self.codes(), ["DECISION_NOT_APPROVED_AT_TIP"])

    def test_declared_but_unregistered(self):
        pinned = self.docs_commit("register", [record("ADR-001")])
        self.platform_tree(pinned)
        self.assertEqual(self.codes(), ["DECISION_NOT_APPROVED_AT_TIP"])

    def test_pin_before_register(self):
        self.docs_commit("register", self.good_register())
        self.platform_tree(self.pre_register)
        self.assertEqual(self.codes(), ["DECISION_NOT_APPROVED_AT_TIP"])

    def test_malformed_register(self):
        pinned = self.docs_commit("register", self.good_register())
        (self.docs / "decisions" / "index.json").write_text('{"decisions": [{"id": "DR-006"}]}')
        self.docs_commit("break")
        self.platform_tree(pinned)
        self.assertEqual(self.codes(), ["DECISION_NOT_APPROVED_AT_TIP"])

    def test_oversized_register(self):
        pinned = self.docs_commit("register", self.good_register())
        (self.docs / "decisions" / "index.json").write_text(" " * (cd.MAX_INDEX_BYTES + 1))
        self.docs_commit("huge")
        self.platform_tree(pinned)
        self.assertEqual(self.codes(), ["DECISION_NOT_APPROVED_AT_TIP"])

    def test_rejected_status_and_duplicate_ids(self):
        pinned = self.docs_commit("register", self.good_register() + [record("DR-006", "rejected")])
        self.platform_tree(pinned)
        self.assertEqual(self.codes(), ["DECISION_NOT_APPROVED_AT_TIP"])


class Environment(Fixture):
    def test_pin_not_on_trusted_tip_is_usage_error(self):
        self.docs_commit("register", self.good_register())
        git(self.docs, "checkout", "-q", "-b", "side")
        side = self.docs_commit("side", self.good_register() + [record("DR-404")])
        git(self.docs, "checkout", "-q", "main")
        self.platform_tree(side)
        with self.assertRaises(cd.EnvError):
            self.run_check()

    def test_rewritten_docs_history_is_usage_error(self):
        pinned = self.docs_commit("register", self.good_register())
        git(self.docs, "reset", "-q", "--hard", self.pre_register)
        self.docs_commit("rewritten register", self.good_register() + [record("DR-404")])
        self.platform_tree(pinned)
        with self.assertRaises(cd.EnvError):
            self.run_check()

    def test_shallow_docs_repo_is_refused(self):
        self.docs_commit("register", self.good_register())
        pinned = self.docs_commit("tip", self.good_register())
        clone = self.root / "shallow"
        subprocess.run(["git", "clone", "-q", "--depth", "1", "file://" + str(self.docs), str(clone)],
                       env=GIT_ENV, check=True, capture_output=True)
        self.docs = clone
        self.platform_tree(pinned)
        with self.assertRaises(cd.EnvError):
            self.run_check()

    def test_malformed_deps_is_usage_error(self):
        pinned = self.docs_commit("register", self.good_register())
        for deps in ({"DR-6": {}}, {"DR-006": {"D2": ["A"]}}, {"DR-006": {"D2": "A; rm"}}):
            self.platform_tree(pinned, deps=deps)
            with self.assertRaises(cd.EnvError, msg=deps):
                self.run_check()
        (self.platform / "contracts" / "decision-deps.json").write_text("[]")
        with self.assertRaises(cd.EnvError):
            self.run_check()

    def test_writes_nothing_and_exit_codes(self):
        pinned = self.docs_commit("register", self.good_register())
        self.platform_tree(pinned, files={"tools/x.py": "DR-006 ADR-001 DR-404\n"})
        before = (snapshot(self.docs), snapshot(self.platform))
        proc = subprocess.run([sys.executable, str(CHECKER), "--docs-repo", str(self.docs),
                               "--repo", str(self.platform)], capture_output=True, env=GIT_ENV, check=False)
        self.assertEqual(proc.returncode, 1, proc.stdout)
        self.assertIn(b"DECISION_DEP_UNDECLARED DR-404", proc.stdout)
        self.assertEqual((snapshot(self.docs), snapshot(self.platform)), before)
        (self.platform / "tools" / "x.py").write_text("DR-006 ADR-001\n")
        proc = subprocess.run([sys.executable, str(CHECKER), "--docs-repo", str(self.docs),
                               "--repo", str(self.platform)], capture_output=True, env=GIT_ENV, check=False)
        self.assertEqual(proc.returncode, 0, proc.stdout)
        proc = subprocess.run([sys.executable, str(CHECKER), "--docs-repo", str(self.root / "missing"),
                               "--repo", str(self.platform)], capture_output=True, env=GIT_ENV, check=False)
        self.assertEqual(proc.returncode, 2, proc.stdout)


class Committed(unittest.TestCase):
    def test_every_reference_in_this_repository_is_declared(self):
        deps = cd.load_deps((ROOT / cd.DEPS_FILE).read_bytes())
        tokens = cd.tracked_tokens(cd.load_linkage(), str(ROOT))
        self.assertEqual(sorted(set(tokens) - set(deps)), [])


if __name__ == "__main__":
    unittest.main()
