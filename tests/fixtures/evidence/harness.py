"""Hermetic harness for M0-E02-S04 evidence tests: builds a throwaway docs repo and platform repo
(real git, local only) and crafts evidence records exactly as the recorder would."""
import copy
import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
FIX = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "tools"))


def load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / "tools" / ("%s.py" % name))
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


ec = load("evidence_common")
ce = load("check_evidence")
GIT_ENV = dict(os.environ, GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@invalid", GIT_COMMITTER_NAME="t",
               GIT_COMMITTER_EMAIL="t@invalid", GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM="1")
STORY = "M9-E01-S01"
ACS = {"AC01": "unit", "AC02": "integration", "AC03": "guest-integration", "AC04": "bare-metal"}
GO_UNIT = "backend/pkg/demo_test.go"
GO_LV = "backend/hv/libvirttest/lv_test.go"
PY_UNIT = "tests/unit_demo.py"
CLASSES = {"schema": 1, "description": "test fixture classification", "rules": [
    {"id": "py-unit", "glob": "tests/unit_*.py", "tier": "unit", "kinds": ["functional", "negative"]},
    {"id": "go-lv", "glob": "backend/hv/libvirttest/*_test.go", "tier": "simulated_libvirt", "kinds": ["functional"]},
    {"id": "go-unit", "glob": "backend/pkg/*_test.go", "tier": "unit", "kinds": ["functional"]}]}


def git(repo, *args):
    proc = subprocess.run(["git", *args], cwd=repo, env=GIT_ENV, capture_output=True, text=True, check=False)
    if proc.returncode != 0:
        raise RuntimeError("git %s: %s" % (args, proc.stderr))
    return proc.stdout.strip()


def write(repo, rel, text):
    p = Path(repo) / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text if isinstance(text, str) else json.dumps(text, indent=1))


def commit(repo, msg="c"):
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "--allow-empty", "-m", msg)
    return git(repo, "rev-parse", "HEAD")


class World:
    """A docs repo + platform repo pair. Call .close() (or use addCleanup)."""

    def __init__(self, taxonomy=None, classes=None):
        self.tmp = Path(tempfile.mkdtemp(prefix="evidence-test-"))
        self.docs = self.tmp / "docs"
        self.root = self.tmp / "platform"
        for repo in (self.docs, self.root):
            repo.mkdir()
            git(repo, "init", "-q", "-b", "main")
        self.taxonomy = taxonomy or json.loads((FIX / "taxonomy.json").read_text())
        write(self.docs, "contracts/evidence-taxonomy.json", self.taxonomy)
        write(self.docs, "backlog/stories.json", [{"id": STORY, "status": "ready"}, {"id": "M9-E01-S02", "status": "verified"}])
        write(self.docs, "backlog/acceptance.json",
              [dict(id="%s-%s" % (STORY, k), story_id=STORY, given="g", when="w", then="t", verification="v", tier=t, status="unverified")
               for k, t in ACS.items()] +
              [dict(id="M9-E01-S02-AC01", story_id="M9-E01-S02", given="g", when="w", then="t", verification="v", tier="unit", status="unverified")])
        self.docs_sha = commit(self.docs, "docs")
        write(self.root, "docs-lock.json", {"schema": 1, "docs_repo": "cloud-product-docs", "commit": self.docs_sha})
        write(self.root, ec.CLASSES_PATH, classes or CLASSES)
        write(self.root, "contracts/evidence/record.schema.json", (ROOT / "contracts/evidence/record.schema.json").read_text())
        write(self.root, PY_UNIT, "import unittest\nclass Demo(unittest.TestCase):\n    def test_ok(self):\n        pass\n")
        write(self.root, GO_UNIT, "package pkg\n\nimport \"testing\"\n\nfunc TestDemo(t *testing.T) { t.Log(1) }\n")
        write(self.root, GO_LV, "//go:build libvirt_test\n\npackage libvirttest\n\nimport \"testing\"\n\n"
                                "func TestLV(t *testing.T) { t.Log(1) }\n")
        write(self.root, "toolchain/versions.env", "GO_VERSION=1.27.1\n")
        write(self.root, "evidence/records/.gitkeep", "")
        write(self.root, "evidence/logs/.gitkeep", "")
        self.rev = commit(self.root, "platform")
        self.inventory = {"unit": {GO_UNIT: frozenset({"TestDemo"})},
                          "simulated_libvirt": {GO_LV: frozenset({"TestLV"}), GO_UNIT: frozenset({"TestDemo"})}}
        self.deps = {"unit": {"backend/pkg"}, "simulated_libvirt": {"backend/hv/libvirttest"}}

    def close(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def discover(self, root, taxonomy):
        found = ce.discover_other(root)
        for p in Path(root, "backend").rglob("*_test.go"):
            found.add(p.relative_to(root).as_posix())
        return found

    def patch(self, testcase):
        """Stub the Go toolchain calls (discovery, inventory, deps) for hermetic host runs."""
        from unittest import mock
        testcase.addCleanup(mock.patch.stopall)
        mock.patch.object(ce, "go_test_inventory", side_effect=lambda root, tier, go="go": self.inventory.get(tier, {})).start()
        mock.patch.object(ce, "go_dep_dirs", side_effect=lambda root, tier, dirs, go="go": self.deps.get(tier, set())).start()

    def run(self):
        return ce.run(self.root, str(self.docs), discover=self.discover)

    def codes(self):
        findings, _ = self.run()
        return sorted({f[0] for f in findings})

    def record(self, tests=(PY_UNIT + "::Demo.test_ok",), tier="unit", acs=("AC01",), result="PASS", outcome="pass",
               log=True, mutate=None, mutate_log=None, rev=None, kinds=None, gate=None, commit_it=False, env_line=None):
        """Craft a record the way record_evidence.py would; optional mutate(record) before id; returns record."""
        subject = {"gate": gate} if gate else {"tests": sorted(tests)}
        t = self.taxonomy["tiers"][tier]
        if kinds is None:
            kinds = sorted(self.taxonomy["gates"][gate]["kinds"]) if gate else ce.record_kinds(CLASSES, subject["tests"])
        env = {"kind": "local_container", "image": "sha256:" + "a" * 64, "toolchain": {"GO_VERSION": "1.27.1"},
               "apt_versions_sha256": "b" * 64, "os": "Debian GNU/Linux 13 (trixie)", "kernel": "6.0", "arch": "x86_64"}
        if tier == "simulated_libvirt":
            env["libvirt"] = "11.3.0"
        rec = {"schema": 1, "story": STORY, "acceptance": ["%s-%s" % (STORY, a) for a in acs], "subject": subject,
               "tier": tier, "kinds": kinds, "environment_class": t["environment_class"], "cost_class": t["cost_class"],
               "origin": "local", "run_by": "agent", "environment": env, "command": ec.expected_command(subject, tier),
               "revision": {"platform": rev or self.rev, "tree_clean": True, "docs": self.docs_sha},
               "started_at": "2026-10-06T00:00:00Z", "finished_at": "2026-10-06T00:01:00Z", "result": result,
               "exit_code": None}
        text = None
        if log:
            exit_code = 0 if (result == "PASS") else 1
            lines = [json.dumps({"evidence_env": env_line or {k: env.get(k) for k in ("os", "kernel", "arch",
                                                                                     "apt_versions_sha256", "libvirt")
                                                               if k in env}})]
            if not gate:
                lines += [json.dumps({"evidence_test": r, "outcome": outcome}) for r in subject["tests"]]
            lines.append(json.dumps({"evidence_exit": exit_code}))
            text = "\n".join(["| some tool output"] + lines) + "\n"
            if mutate_log:
                text = mutate_log(text)
            rec["exit_code"] = exit_code
            rec["log"] = {"path": "", "sha256": hashlib.sha256(text.encode()).hexdigest()}
        elif result in ("NOT_RUN", "BLOCKED"):
            rec["reason"] = "not executed in this test"
            if result == "BLOCKED":
                rec["blocker"] = "HOSTED_CI_DEFERRED"
        if mutate:
            mutate(rec)
        rec["id"] = ec.record_id(rec)
        if "log" in rec and isinstance(rec["log"], dict) and rec["log"].get("path") == "":
            rec["log"]["path"] = "evidence/logs/%s.log" % rec["id"]
            write(self.root, rec["log"]["path"], text)
        write(self.root, "evidence/records/%s.json" % rec["id"], json.dumps(rec))
        if commit_it:
            commit(self.root, "evidence")
        return rec

    def rewrite(self, rec, **changes):
        """Overwrite a record file in place with changes (no id recomputation) — hostile edit."""
        bad = copy.deepcopy(rec)
        bad.update(changes)
        write(self.root, "evidence/records/%s.json" % rec["id"], json.dumps(bad))
        return bad
