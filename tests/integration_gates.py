"""Gate-defect integration tests (story M0-E02-S02 AC02, tier T1, simulated).

Run inside the dev container: `make test-integration`. For each gate, a fresh
temporary clone of the repository (committed content) first passes the gate unmodified, then gets
exactly one injected defect and must fail that gate with a recognisable
message. Nothing outside the temporary directory is modified.
"""
import os
import random
import string
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TIMEOUT = 900


def fake_token():
    # Built at runtime so this source file itself never contains a token.
    rng = random.Random(4242)
    return "ghp_" + "".join(rng.choice(string.ascii_letters + string.digits) for _ in range(36))


def write(rel, text):
    def mutate(root):
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    return mutate


def replace(rel, old, new):
    def mutate(root):
        path = root / rel
        text = path.read_text()
        assert old in text, (rel, old)
        path.write_text(text.replace(old, new))
    return mutate


def delete(rel):
    return lambda root: (root / rel).unlink()


CASES = [
    ("go-fmt", "unformatted Go file", write("backend/cmd/api/bad_fmt.go", "package main\nfunc  badFmt( ) {}\n"), "bad_fmt.go"),
    ("go-vet", "go vet printf error", write("backend/cmd/api/bad_vet.go",
        'package main\n\nimport "fmt"\n\nfunc badVet() { fmt.Printf("%d\\n", "text") }\n'), "Printf"),
    ("go-staticcheck", "unused function", write("backend/cmd/api/bad_sc.go", "package main\n\nfunc unusedHelper() {}\n"), "U1000"),
    ("go-gosec", "G204 command construction", write("backend/cmd/api/bad_sec.go",
        'package main\n\nimport "os/exec"\n\nfunc RunUser(arg string) error { return exec.Command("sh", "-c", arg).Run() }\n'), "G204"),
    ("go-test", "failing Go test", write("backend/cmd/api/bad_test.go",
        'package main\n\nimport "testing"\n\nfunc TestInjectedFailure(t *testing.T) { t.Fatal("injected failure") }\n'), "injected failure"),
    ("py-check", "failing Python test", write("tests/unit_injected_failure.py",
        "import unittest\n\nclass T(unittest.TestCase):\n    def test_fail(self):\n        self.fail('injected failure')\n"), "injected failure"),
    ("py-check", "Python syntax error", write("tools/bad_syntax.py", "def broken(:\n    pass\n"), "SyntaxError"),
    ("fe-check", "TypeScript type error", write("frontend/src/bad.ts", "export const n: number = 'text';\n"), "TS2322"),
    ("secrets", "fake GitHub token", lambda root: write("config/leaked.env", "GITHUB_TOKEN=%s\n" % fake_token())(root), "leaks found:"),
    # S02 review F4: committed secrets in formerly allowlisted paths are caught.
    ("secrets", "token in committed lockfile", replace("frontend/package-lock.json", '"lockfileVersion": 3,',
        '"lockfileVersion": 3,\n  "x": "%s",' % fake_token()), "leaks found:"),
    ("secrets", "token in committed go.sum", lambda root: (root / "toolchain/gotools/go.sum").open("a").write(
        "example.invalid/x v1 token=%s\n" % fake_token()), "leaks found:"),
    ("secrets", "token in committed node_modules", write("src/node_modules/x.js", "const t = '%s';\n" % fake_token()), "leaks found:"),
    ("secrets", "token in committed frontend/dist", write("frontend/dist/app.js", "const t = '%s';\n" % fake_token()), "leaks found:"),
    ("fe-install", "deleted lockfile", delete("frontend/package-lock.json"), "package-lock.json missing"),
    ("ci-policy", "unpinned workflow action", replace(".github/workflows/ci.yml",
        "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1", "actions/checkout@v4"), "not pinned"),
]


def make(root, target):
    proc = subprocess.run(["make", "--no-print-directory", target], cwd=root, stdout=subprocess.PIPE,
                          stderr=subprocess.STDOUT, text=True, timeout=TIMEOUT)
    return proc.returncode, proc.stdout


def git(root, *args):
    env = {**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.invalid",
           "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.invalid", "GIT_CONFIG_GLOBAL": os.devnull}
    subprocess.run(["git", "-C", str(root), *args], env=env, check=True, capture_output=True)


class GateDefects(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory(prefix="gates-")
        cls.passed_clean = set()

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def fresh_copy(self, name):
        # Clone (committed content and real history) so history-based gates
        # such as gitleaks see the same commits as the source repository.
        root = Path(self.tmp.name) / name
        git(Path(self.tmp.name), "clone", "-q", "--no-hardlinks", str(ROOT), str(root))
        return root

    def run_case(self, index, target, label, mutate, marker):
        if target not in self.passed_clean:
            clean = self.fresh_copy("clean-%s" % target)
            code, out = make(clean, target)
            self.assertEqual(code, 0, "clean copy must pass %s:\n%s" % (target, out[-4000:]))
            self.passed_clean.add(target)
        root = self.fresh_copy("defect-%02d" % index)
        mutate(root)
        # --force so defects in normally ignored paths are really committed.
        git(root, "add", "-A", "--force")
        git(root, "commit", "-q", "-m", "inject %s" % label)
        code, out = make(root, target)
        self.assertNotEqual(code, 0, "%s: gate %s did not fail:\n%s" % (label, target, out[-4000:]))
        self.assertIn(marker, out, "%s: gate %s failed without naming the defect:\n%s" % (label, target, out[-4000:]))
        print("PASS %-15s fails on %-26s (exit %d)" % (target, label, code), file=sys.stderr)


class MakeVariableInjection(unittest.TestCase):
    """S02 review F7: LINKAGE_BASE is validated, never expanded into shell text."""

    def test_linkage_base_injection_rejected(self):
        with tempfile.TemporaryDirectory(prefix="inject-") as tmp:
            pwned = Path(tmp) / "pwned"
            for value in ("x';touch %s;'" % pwned, "$(touch %s)" % pwned, "-x", "a..b", ""):
                with self.subTest(value=value):
                    proc = subprocess.run(
                        ["make", "--no-print-directory", "verify-linkage", "DOCS_REPO=/workspace/cloud-product-docs"],
                        cwd=ROOT, env={**os.environ, "LINKAGE_BASE": value, "LINKAGE_MODE": "full", "REQUIRE_COMMITS": "0"},
                        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=TIMEOUT)
                    self.assertNotEqual(proc.returncode, 0, proc.stdout)
                    self.assertIn("ERROR invalid LINKAGE_BASE", proc.stdout)
                    self.assertFalse(pwned.exists())


class ReviewCycle2Gates(unittest.TestCase):
    """S02 review cycle 2: N2 make defaults, N3 secrets fail-closed without history."""

    def test_secrets_fails_without_git_history(self):
        with tempfile.TemporaryDirectory(prefix="nogit-") as tmp:
            root = Path(tmp) / "repo"
            git(Path(tmp), "clone", "-q", "--no-hardlinks", str(ROOT), str(root))
            (root / ".git").rename(Path(tmp) / "moved-git")
            code, out = make(root, "secrets")
            self.assertNotEqual(code, 0, out)
            self.assertIn("ERROR secrets: git history unavailable", out)

    def test_linkage_defaults_apply_when_unset(self):
        env = {k: v for k, v in os.environ.items() if k not in ("LINKAGE_MODE", "REQUIRE_COMMITS", "LINKAGE_BASE")}
        proc = subprocess.run(["make", "--no-print-directory", "verify-linkage", "DOCS_REPO=/workspace/cloud-product-docs",
                               "LINKAGE_BASE=HEAD~1"], cwd=ROOT, env=env, stdout=subprocess.PIPE,
                              stderr=subprocess.STDOUT, text=True, timeout=TIMEOUT)
        self.assertNotIn("must be", proc.stdout)
        self.assertIn("OK lock", proc.stdout)
        self.assertIn("commits", proc.stdout)


def _make_test(index, case):
    def test(self):
        self.run_case(index, *case)
    return test


for _i, _case in enumerate(CASES):
    setattr(GateDefects, "test_%02d_%s" % (_i, _case[0].replace("-", "_")), _make_test(_i, _case))


if __name__ == "__main__":
    unittest.main(verbosity=2)
