#!/usr/bin/env python3
"""Test-evidence checker and report (story M0-E02-S04; DR-006 D1/D2/D3 = A).

Validates the docs-repo evidence taxonomy (at the pinned docs commit), the test
classification, every evidence record and the append-only history of evidence/.
Records are claims: this checker proves consistency, not authenticity
(authenticity of local evidence: make evidence-replay, plus review). Read-only.

Validity is judged at each record's own revisions; currency at HEAD. A valid
but non-current record is reported STALE (exit 0); it never counts as evidence.

Exit codes: 0 no findings, 1 findings, 2 usage or environment error.
"""
import argparse
import ast
import json
import os
import re
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import evidence_common as ec  # noqa: E402

ROOT = ec.ROOT
FINDING_CODES = ("EVIDENCE_INVALID", "EVIDENCE_UNTRACEABLE", "EVIDENCE_UNBOUND", "EVIDENCE_OVERSTATED",
                 "EVIDENCE_HOSTED_CLAIM", "EVIDENCE_MISMATCH", "EVIDENCE_TAMPERED", "EVIDENCE_STATUS_INVALID",
                 "EVIDENCE_DUPLICATE", "EVIDENCE_HISTORY_REWRITTEN", "TEST_UNCLASSIFIED", "TEST_AMBIGUOUS",
                 "CONTRACT_INVALID")
BASE_KEYS = {"schema", "id", "story", "acceptance", "subject", "tier", "kinds", "environment_class", "cost_class",
             "origin", "run_by", "environment", "command", "revision", "started_at", "finished_at", "result",
             "exit_code"}
OPTIONAL_KEYS = {"run_by_name", "reason", "blocker", "log", "ci_run_url"}
ENV_KEYS = {"kind", "image", "toolchain", "apt_versions_sha256", "os", "kernel", "arch"}
SHA_RE = re.compile(r"[0-9a-f]{40}")
ID_RE = re.compile(r"EV-[0-9a-f]{16}")
STORY_RE = re.compile(r"M\d+-E\d{2}-S\d{2}")
TS_RE = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z")
IMAGE_RE = re.compile(r"sha256:[0-9a-f]{64}")
TEST_LIKE_RE = re.compile(r"(?:.*_test\.[A-Za-z]+|.*test.*\.py|.*\.spec\.[A-Za-z]+|.*\.test\.[A-Za-z]+)")
# Paths (repo-relative, exact) not walked for test-like files: VCS data, dependency/build output, evidence, fixtures.
WALK_SKIP = {".git", "frontend/node_modules", "frontend/dist", "evidence"}
UNITTEST_NAME_RE = re.compile(r"(?:unit|integration)_.*\.py")
# toolchain/gotools pins tool versions (no tests; resolving it would need module downloads). Any test-like file
# placed there is still caught by the test-like walk and reported TEST_UNCLASSIFIED.
SKIP_MODULES = {"toolchain/gotools"}
GO_MODULE_FILES = ("go.mod", "go.sum")


class EnvError(Exception):
    pass


class Git:
    """Hardened git access (tools/check_linkage.py) for a repository."""

    def __init__(self, linkage, repo):
        self.linkage, self.repo = linkage, str(repo)

    def run(self, *args):
        return self.linkage.git(self.repo, *args)

    def blob(self, rev, path):
        if self.linkage.object_size(self.repo, "%s:%s" % (rev, path)) is None:
            return None
        return self.run("cat-file", "blob", "%s:%s" % (rev, path))

    def json_at(self, rev, path):
        raw = self.blob(rev, path)
        if raw is None:
            return None
        try:
            return ec.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError, RecursionError):
            return None

    def is_commit(self, sha):
        out = self.run("cat-file", "-t", sha)
        return out is not None and out.strip() == b"commit"

    def is_ancestor(self, a, b):
        return self.run("merge-base", "--is-ancestor", a, b) is not None

    def changed(self, a, b):
        out = self.run("diff", "--no-renames", "--name-only", a, b, "--")
        if out is None:
            raise EnvError("git diff %s %s failed" % (a, b))
        return [p for p in out.decode("utf-8", "replace").splitlines() if p]

    def dirty(self):
        """Paths with uncommitted changes (tracked or untracked) in the working tree (erratum r2b, N10)."""
        out = self.run("status", "--porcelain", "--no-renames", "--untracked-files=all")
        if out is None:
            raise EnvError("git status failed")
        return [line[3:] for line in out.decode("utf-8", "replace").splitlines() if len(line) > 3]


# ---- Go helpers (injectable in unit tests) -------------------------------------------------------------------
def go_env():
    ct = ec.load_check_threats()
    return ct, dict(os.environ, **ct.GO_ENV)


def go_json(root, module, args, go="go"):
    ct, env = go_env()
    try:
        proc = subprocess.run([go, *args], cwd=Path(root) / module, env=env, capture_output=True, timeout=900,
                              check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise EnvError("go %s: %s" % (args[0], exc.__class__.__name__)) from None
    if proc.returncode != 0:
        raise EnvError("go %s exited %d: %s" % (args[0], proc.returncode,
                                                proc.stderr.decode("utf-8", "replace").strip()[-400:]))
    try:
        return ct.json_stream(proc.stdout)
    except ValueError:
        raise EnvError("go produced malformed JSON") from None


def go_modules(root):
    mods = []
    for dirpath, dirnames, filenames in os.walk(root):
        rel = Path(dirpath).relative_to(root).as_posix()
        dirnames[:] = sorted(d for d in dirnames if (d if rel == "." else "%s/%s" % (rel, d)) not in WALK_SKIP)
        if "go.mod" in filenames and rel not in SKIP_MODULES:
            mods.append("" if rel == "." else rel)
    return sorted(mods)


def all_tags(taxonomy):
    return sorted({t for tier in taxonomy["tiers"] for t in ec.TIER_TAGS.get(tier, ())})


def discover_go(root, taxonomy, go="go"):
    """Go test files of every module, as `go list` sees them with default tags and with every tier's tags."""
    ct, _ = go_env()
    found = set()
    for module in go_modules(root):
        for tags in ((), tuple(all_tags(taxonomy))):
            tag_args = ["-tags", ",".join(tags)] if tags else []
            for pkg in go_json(root, module, ["list", *ct.GO_BUILD_FLAGS, *tag_args,
                                              "-json=Dir,TestGoFiles,XTestGoFiles", "./..."], go):
                for name in list(pkg.get("TestGoFiles") or []) + list(pkg.get("XTestGoFiles") or []):
                    try:
                        found.add((Path(pkg["Dir"]) / name).relative_to(Path(root).resolve()).as_posix())
                    except (ValueError, KeyError, TypeError):
                        continue
    return found


def go_dep_dirs(root, tier, pkg_dirs, go="go"):
    """Module-local package directories (repo-relative) that the cited test packages depend on, or None when a
    cited package no longer builds any test files for the tier (removed, emptied, only testdata left, or every file
    excluded by build tags): such a record is STALE, never an environment error (erratum r2b; review cycle 2 F1)."""
    ct, _ = go_env()
    tags = ec.TIER_TAGS.get(tier, ())
    tag_args = ["-tags", ",".join(tags)] if tags else []
    rel_dirs = ["./" + Path(d).relative_to("backend").as_posix() for d in sorted(pkg_dirs)]
    top = Path(root).resolve()
    for pkg in go_json(root, "backend", ["list", "-e", *ct.GO_BUILD_FLAGS, *tag_args,
                                         "-json=Dir,Error,TestGoFiles,XTestGoFiles", *rel_dirs], go):
        if pkg.get("Error") or not (pkg.get("TestGoFiles") or pkg.get("XTestGoFiles")):
            return None
    dirs = set()
    for pkg in go_json(root, "backend", ["list", *ct.GO_BUILD_FLAGS, *tag_args, "-deps", "-test",
                                         "-json=Dir,Standard", *rel_dirs], go):
        if pkg.get("Standard") or not isinstance(pkg.get("Dir"), str):
            continue
        try:
            dirs.add(Path(pkg["Dir"]).resolve().relative_to(top).as_posix())
        except ValueError:
            continue  # outside the repository (module cache): pinned by go.sum
    return dirs


def go_test_inventory(root, tier, go="go"):
    tags = ec.TIER_TAGS.get(tier, ())
    try:
        return ec.load_check_threats().go_inventory(root, go, tags)
    except Exception as exc:  # GoInventoryError from check_threats
        raise EnvError("go inventory: %s" % exc) from None


# ---- discovery and classification -----------------------------------------------------------------------------
def discover_other(root):
    found = set()
    for p in sorted((Path(root) / "tests").glob("*.py")):
        found.add(p.relative_to(root).as_posix())
    fe = Path(root) / "frontend"
    for pattern in ("src/**/*.test.ts", "src/**/*.test.tsx", "src/**/*.spec.ts", "src/**/*.spec.tsx", "e2e/**/*"):
        for p in fe.glob(pattern):
            if p.is_file() and "node_modules" not in p.parts:
                found.add(p.relative_to(root).as_posix())
    return found


def test_like_files(root):
    """Files that look like tests anywhere (and every .py under tests/): each must be discovered (fail closed)."""
    out = set()
    for dirpath, dirnames, filenames in os.walk(root):
        rel = Path(dirpath).relative_to(root).as_posix()
        dirnames[:] = [d for d in dirnames if (d if rel == "." else "%s/%s" % (rel, d)) not in WALK_SKIP]
        for f in filenames:
            path = f if rel == "." else "%s/%s" % (rel, f)
            in_fixtures = path.startswith("tests/fixtures/")
            if TEST_LIKE_RE.fullmatch(f) or UNITTEST_NAME_RE.fullmatch(f) \
                    or (path.startswith("tests/") and not in_fixtures and f.endswith(".py")):
                out.add(path)
    return out


def check_contracts(taxonomy, classes, schema=None):
    findings = []
    if schema is not None and (not isinstance(schema, dict) or schema.get("$id") != "contracts/evidence/record.schema.json"
                               or schema.get("properties", {}).get("schema", {}).get("const") != 1):
        findings.append(("CONTRACT_INVALID", "contracts/evidence/record.schema.json", "record schema missing or malformed"))
    tiers = taxonomy.get("tiers") if isinstance(taxonomy, dict) else None
    if not isinstance(tiers, dict) or not isinstance(taxonomy.get("ac_tier_map"), dict) \
            or taxonomy.get("origins_accepted_in_m0") != ["local"]:
        return [("CONTRACT_INVALID", "taxonomy", "docs-repo taxonomy malformed or accepts non-local origins")]
    for name, t in tiers.items():
        if t.get("accepted_in_m0") and (t.get("environment_class") != "simulated" or t.get("cost_class") not in ("T0", "T1")):
            findings.append(("CONTRACT_INVALID", "taxonomy", "tier %s accepted in M0 but not simulated T0/T1" % name))
    rules = classes.get("rules") if isinstance(classes, dict) else None
    if not isinstance(classes, dict) or set(classes) != {"schema", "description", "rules"} or classes.get("schema") != 1 \
            or not isinstance(rules, list) or not rules:
        return findings + [("CONTRACT_INVALID", ec.CLASSES_PATH, "must be {schema: 1, description, rules: [...]}")]
    ids = set()
    for rule in rules:
        rid = rule.get("id") if isinstance(rule, dict) else None
        if not isinstance(rid, str) or rid in ids or not set(rule) <= {"id", "glob", "exclude", "tier", "kinds"} \
                or not isinstance(rule.get("glob"), str) or not isinstance(rule.get("exclude", []), list) \
                or not isinstance(rule.get("kinds"), list) or not rule["kinds"] \
                or not set(rule["kinds"]) <= set(taxonomy.get("kinds", [])):
            findings.append(("CONTRACT_INVALID", str(rid), "rule needs a unique id, glob, kinds from the taxonomy"))
            continue
        ids.add(rid)
        if rule.get("tier") not in tiers or not tiers[rule["tier"]].get("accepted_in_m0"):
            findings.append(("CONTRACT_INVALID", rid, "rule maps to tier %r, which is not accepted in M0 "
                                                      "(only simulated T0/T1; DR-006 D2)" % (rule.get("tier"),)))
    return findings


def check_classification(root, taxonomy, classes, discovered):
    findings = []
    matched = set()
    for path in sorted(discovered):
        hits = ec.classify(classes, path)
        matched |= {r["id"] for r in hits}
        if not hits:
            findings.append(("TEST_UNCLASSIFIED", path, "no classification rule matches"))
        elif len(hits) > 1:
            findings.append(("TEST_AMBIGUOUS", path, "matches rules %s" % sorted(r["id"] for r in hits)))
    for rule in classes["rules"]:
        if rule.get("id") not in matched:
            findings.append(("CONTRACT_INVALID", str(rule.get("id")), "rule matches no test file"))
    for path in sorted(test_like_files(root) - discovered):
        findings.append(("TEST_UNCLASSIFIED", path, "test-like file not discovered by any runner (not executed)"))
    return findings


def check_history(git):
    out = git.run("log", "--diff-merges=first-parent", "--no-renames", "--diff-filter=MDT", "--name-status",
                  "--format=%H", "HEAD", "--", "evidence/")
    if out is None:
        raise EnvError("git log failed")
    findings = []
    commit = None
    for line in out.decode("utf-8", "replace").splitlines():
        if SHA_RE.fullmatch(line):
            commit = line
        elif line.strip():
            findings.append(("EVIDENCE_HISTORY_REWRITTEN", line.split("\t")[-1],
                             "%s in commit %s; evidence/ is append-only" % (line.split("\t")[0], (commit or "?")[:12])))
    added = git.run("log", "--diff-merges=first-parent", "--no-renames", "--diff-filter=A", "--name-only", "--format=",
                    "HEAD", "--", "evidence/")
    present = git.run("ls-tree", "-r", "--name-only", "HEAD", "--", "evidence/")
    if added is None or present is None:
        raise EnvError("git log/ls-tree failed")
    # Every evidence path ever added on the first-parent line, or on any merged branch, must still exist (r2b, M1).
    side = git.run("log", "--full-history", "--no-renames", "--diff-filter=A", "--name-only", "--format=", "HEAD", "--",
                   "evidence/")
    ever = {p for p in (added + (side or b"")).decode("utf-8", "replace").splitlines() if p}
    for path in sorted(ever - set(present.decode("utf-8", "replace").splitlines())):
        findings.append(("EVIDENCE_HISTORY_REWRITTEN", path, "added in history but missing at HEAD; evidence/ is append-only"))
    status = git.run("status", "--porcelain", "--untracked-files=no", "--", "evidence/")
    if status is None:
        raise EnvError("git status failed")
    for line in status.decode("utf-8", "replace").splitlines():
        if line[:2].strip() and line[:2] != "A ":
            findings.append(("EVIDENCE_HISTORY_REWRITTEN", line[3:], "uncommitted change %r to committed evidence"
                             % line[:2]))
    return findings


# ---- records -----------------------------------------------------------------------------------------------------
class Context:
    def __init__(self, root, git, docs, docs_sha, taxonomy, classes, go="go"):
        self.root, self.git, self.docs, self.docs_sha = Path(root), git, docs, docs_sha
        self.taxonomy, self.classes, self.go = taxonomy, classes, go
        self._acs, self._inv, self._classes_at = {}, {}, {}

    def backlog_at(self, sha):
        """({story: status}, {ac_id: ac}) at a docs commit, or None."""
        if sha not in self._acs:
            stories = self.docs.json_at(sha, "backlog/stories.json")
            acs = self.docs.json_at(sha, "backlog/acceptance.json")
            try:
                self._acs[sha] = ({s["id"]: s["status"] for s in stories}, {a["id"]: a for a in acs})
            except (TypeError, KeyError):
                self._acs[sha] = None
        return self._acs[sha]

    def classes_at(self, rev):
        if rev not in self._classes_at:
            self._classes_at[rev] = self.git.json_at(rev, ec.CLASSES_PATH)
        return self._classes_at[rev]

    def inventory(self, tier):
        if tier not in self._inv:
            self._inv[tier] = go_test_inventory(self.root, tier, self.go)
        return self._inv[tier]


def defines_test(kind, text, name):
    """The cited file itself defines the cited test (review N4): Go top-level func, Python class method."""
    if kind == "go":
        code = ec.load_check_threats().strip_go_comments(text)
        return re.search(r"^func %s\(\s*[A-Za-z_][A-Za-z0-9_]*\s+\*testing\.T\s*\)" % re.escape(name), code, re.M) is not None
    cls, meth = name.split(".", 1)
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError):
        return False
    return any(isinstance(c, ast.ClassDef) and c.name == cls and any(isinstance(f, ast.FunctionDef) and f.name == meth
                                                                       for f in c.body) for c in tree.body)


def record_kinds(classes, tests):
    kinds = set()
    for ref in tests:
        for rule in ec.classify(classes, ec.test_ref(ref)[1]):
            kinds |= set(rule["kinds"])
    return sorted(kinds)


def validate_shape(rec, name):
    """Schema-level checks; returns a finding or None."""
    if not isinstance(rec, dict) or not BASE_KEYS <= set(rec) or not set(rec) <= BASE_KEYS | OPTIONAL_KEYS:
        return ("EVIDENCE_INVALID", name, "keys must be %s plus optional %s" % (sorted(BASE_KEYS), sorted(OPTIONAL_KEYS)))
    env, rev, subject = rec["environment"], rec["revision"], rec["subject"]
    bad = (rec["schema"] != 1 or type(rec["schema"]) is not int or not isinstance(rec["id"], str)
           or not isinstance(rec["story"], str) or not STORY_RE.fullmatch(rec["story"])
           or not isinstance(rec["acceptance"], list) or not rec["acceptance"]
           or not all(isinstance(a, str) for a in rec["acceptance"]) or len(set(rec["acceptance"])) != len(rec["acceptance"])
           or not isinstance(subject, dict) or len(subject) != 1 or not set(subject) <= {"tests", "gate"}
           or ("tests" in subject and (not isinstance(subject["tests"], list) or not subject["tests"]
                                       or len(set(map(str, subject["tests"]))) != len(subject["tests"])))
           or ("gate" in subject and not isinstance(subject["gate"], str))
           or not isinstance(rec["tier"], str) or not isinstance(rec["kinds"], list)
           or not isinstance(rec["command"], list) or not all(isinstance(c, str) for c in rec["command"])
           or not isinstance(env, dict) or not ENV_KEYS <= set(env) or not set(env) <= ENV_KEYS | {"libvirt"}
           or not isinstance(env.get("toolchain"), dict) or not isinstance(env.get("image"), str)
           or not IMAGE_RE.fullmatch(env["image"])
           or not all(isinstance(env.get(k), str) and env[k] for k in ("os", "kernel", "arch"))
           or not isinstance(rev, dict) or set(rev) != {"platform", "tree_clean", "docs"}
           or not isinstance(rev["platform"], str) or not isinstance(rev["docs"], str)
           or not all(isinstance(rec[k], str) and TS_RE.fullmatch(rec[k]) for k in ("started_at", "finished_at"))
           or rec["finished_at"] < rec["started_at"]
           or rec["result"] not in ec.RESULTS or not (rec["exit_code"] is None or type(rec["exit_code"]) is int)
           or rec["run_by"] not in ("agent", "human")
           or (rec["run_by"] == "human" and not (isinstance(rec.get("run_by_name"), str) and len(rec["run_by_name"].strip()) >= 2))
           or (rec["run_by"] == "agent" and "run_by_name" in rec))
    if bad:
        return ("EVIDENCE_INVALID", name, "malformed record fields")
    if "tests" in subject and any(ec.test_ref(r) is None for r in subject["tests"]):
        return ("EVIDENCE_UNTRACEABLE", name, "malformed test reference (Go path::TestName or tests/x.py::Class.test)")
    if "tests" in subject and len({ec.test_ref(r)[0] for r in subject["tests"]}) != 1:
        return ("EVIDENCE_INVALID", name, "tests must all be Go or all Python (one runner)")
    return None


def check_record(ctx, path, rec):
    """Return (findings, state) for one record; state in {current, stale, None (invalid)}."""
    name = path.name
    tax = ctx.taxonomy
    # Hosted claims are classified before shape so they always surface as EVIDENCE_HOSTED_CLAIM (DR-004).
    if isinstance(rec, dict) and ("ci_run_url" in rec or ("origin" in rec and rec["origin"] not in tax["origins_accepted_in_m0"])
                                  or (isinstance(rec.get("environment"), dict)
                                      and rec["environment"].get("kind") not in tax["environment_kinds_accepted_in_m0"])):
        return [("EVIDENCE_HOSTED_CLAIM", name, "only local evidence is accepted in M0 (DR-004; DR-006 D2)")], None
    bad = validate_shape(rec, name)
    if bad:
        return [bad], None
    findings = []
    rid = ec.record_id(rec)
    if rec["id"] != rid or not ID_RE.fullmatch(rec["id"]):
        return [("EVIDENCE_INVALID", name, "id %s is not the content digest %s" % (rec["id"], rid))], None
    if name != rec["id"] + ".json":
        return [("EVIDENCE_INVALID", name, "file name must be <id>.json")], None
    # tier, environment and cost class (taxonomy at the pinned docs commit)
    tier = tax["tiers"].get(rec["tier"])
    if tier is None:
        return [("EVIDENCE_INVALID", name, "unknown tier %r" % rec["tier"])], None
    if not tier["accepted_in_m0"]:
        findings.append(("EVIDENCE_OVERSTATED", name, "tier %s (%s, %s) is not accepted in M0; only simulated T0/T1"
                         % (rec["tier"], tier["environment_class"], tier["cost_class"])))
    if rec["environment_class"] != tier["environment_class"] or rec["cost_class"] != tier["cost_class"]:
        findings.append(("EVIDENCE_OVERSTATED", name, "environment_class/cost_class must be %s/%s for tier %s"
                         % (tier["environment_class"], tier["cost_class"], rec["tier"])))
    if rec["tier"] == "simulated_libvirt" and "log" in rec and not rec["environment"].get("libvirt"):
        findings.append(("EVIDENCE_INVALID", name, "simulated_libvirt records must capture the libvirt version"))
    # result semantics (no log for NOT_RUN/BLOCKED; reason/blocker)
    res, code, has_log = rec["result"], rec["exit_code"], "log" in rec
    sem_ok = {"PASS": code == 0 and has_log and "reason" not in rec and "blocker" not in rec,
              "FAIL": has_log and "blocker" not in rec,
              "NOT_RUN": code is None and not has_log and isinstance(rec.get("reason"), str) and "blocker" not in rec,
              "BLOCKED": code is None and not has_log and isinstance(rec.get("reason"), str)
                         and rec.get("blocker") in tax["blockers"]}[res]
    if not sem_ok or (res in ("NOT_RUN", "BLOCKED") and len(rec.get("reason", "").strip()) < 3):
        findings.append(("EVIDENCE_STATUS_INVALID", name, "%s violates result semantics" % res))
    # revisions
    plat, docs_sha = rec["revision"]["platform"], rec["revision"]["docs"]
    if rec["revision"]["tree_clean"] is not True:
        findings.append(("EVIDENCE_MISMATCH", name, "revision.tree_clean must be true"))
    if not SHA_RE.fullmatch(plat) or not ctx.git.is_commit(plat) or not ctx.git.is_ancestor(plat, "HEAD"):
        return findings + [("EVIDENCE_MISMATCH", name, "revision.platform is not a commit reachable from HEAD")], None
    lock = ctx.git.json_at(plat, "docs-lock.json")
    if not isinstance(lock, dict) or lock.get("commit") != docs_sha:
        return findings + [("EVIDENCE_MISMATCH", name, "revision.docs differs from docs-lock.json at revision.platform")], None
    backlog = ctx.backlog_at(docs_sha) if SHA_RE.fullmatch(docs_sha) and ctx.docs.is_commit(docs_sha) \
        and ctx.docs.is_ancestor(docs_sha, ctx.docs_sha) else None
    if backlog is None:
        return findings + [("EVIDENCE_MISMATCH", name, "revision.docs is not a trusted docs commit")], None
    stories, acs = backlog
    # traceability at the record's own revisions
    if rec["story"] not in stories:
        return findings + [("EVIDENCE_UNTRACEABLE", name, "story %s unknown at revision.docs" % rec["story"])], None
    for ac in rec["acceptance"]:
        if ac not in acs or acs[ac].get("story_id") != rec["story"]:
            findings.append(("EVIDENCE_UNTRACEABLE", name, "%s is not an AC of %s at revision.docs" % (ac, rec["story"])))
        elif rec["tier"] not in tax["ac_tier_map"].get(acs[ac].get("tier"), []):
            findings.append(("EVIDENCE_OVERSTATED", name, "tier %s cannot evidence %s (backlog tier %s)"
                             % (rec["tier"], ac, acs[ac].get("tier"))))
    subject = rec["subject"]
    classes_at = ctx.classes_at(plat)
    if "gate" in subject:
        gate = tax["gates"].get(subject["gate"])
        if gate is None:
            return findings + [("EVIDENCE_UNTRACEABLE", name, "unknown gate %r" % subject["gate"])], None
        if gate["tier"] != rec["tier"]:
            findings.append(("EVIDENCE_OVERSTATED", name, "gate %s is tier %s" % (subject["gate"], gate["tier"])))
        if sorted(rec["kinds"]) != sorted(gate["kinds"]):
            findings.append(("EVIDENCE_INVALID", name, "kinds must be the gate's kinds %s" % sorted(gate["kinds"])))
    else:
        if not isinstance(classes_at, dict) or not isinstance(classes_at.get("rules"), list):
            return findings + [("EVIDENCE_UNTRACEABLE", name, "no test classification at revision.platform")], None
        for ref in subject["tests"]:
            kind, tpath, _ = ec.test_ref(ref)
            blob = ctx.git.blob(plat, tpath)
            if blob is None:
                findings.append(("EVIDENCE_UNTRACEABLE", name, "%s does not exist at revision.platform" % tpath))
                continue
            if not defines_test(kind, blob.decode("utf-8", "replace"), ec.test_ref(ref)[2]):
                findings.append(("EVIDENCE_UNTRACEABLE", name, "%s does not define %s at revision.platform"
                                 % (tpath, ec.test_ref(ref)[2])))
                continue
            hits = ec.classify(classes_at, tpath)
            if len(hits) != 1 or hits[0]["tier"] != rec["tier"]:
                findings.append(("EVIDENCE_OVERSTATED", name, "%s is classified %s, not %s"
                                 % (tpath, [h["tier"] for h in hits] or "unclassified", rec["tier"])))
        if not findings and sorted(rec["kinds"]) != record_kinds(classes_at, subject["tests"]):
            findings.append(("EVIDENCE_INVALID", name, "kinds must be the classified kinds %s"
                             % record_kinds(classes_at, subject["tests"])))
    if rec["command"] != ec.expected_command(subject, rec["tier"]):
        findings.append(("EVIDENCE_UNBOUND", name, "command is not the runner command generated for the cited subject"))
    # log integrity and binding
    if has_log:
        log = rec["log"]
        lp = ctx.root / "evidence" / "logs" / (rec["id"] + ".log")
        if not isinstance(log, dict) or set(log) != {"path", "sha256"} or log.get("path") != "evidence/logs/%s.log" % rec["id"]:
            findings.append(("EVIDENCE_INVALID", name, "log must be {path: evidence/logs/<id>.log, sha256}"))
        elif not lp.is_file() or lp.is_symlink() or lp.stat().st_size > ec.MAX_LOG_BYTES or ec.sha256_file(lp) != log.get("sha256"):
            findings.append(("EVIDENCE_TAMPERED", name, "log missing, oversized or digest mismatch"))
        else:
            env_line, outcomes, exit_code = ec.parse_runner_log(lp.read_text(encoding="utf-8", errors="replace"))
            findings.extend(check_binding(rec, name, env_line, outcomes, exit_code))
    if findings:
        return findings, None
    if "tests" in subject and res == "PASS" and ec.test_ref(subject["tests"][0])[0] == "go":
        inv = ctx.inventory(rec["tier"])
        for ref in subject["tests"]:
            _, tpath, tname = ec.test_ref(ref)
            if tname not in inv.get(tpath, ()):
                # judged at HEAD: only meaningful while the record is current
                if is_current(ctx, rec, plat, docs_sha)[0]:
                    findings.append(("EVIDENCE_UNBOUND", name, "%s is not run by go test for tier %s "
                                     "(Go-authoritative inventory; build tags, TestMain)" % (ref, rec["tier"])))
    if findings:
        return findings, None
    current, why = is_current(ctx, rec, plat, docs_sha)
    return [], ("current" if current else "stale:" + why)


def check_binding(rec, name, env_line, outcomes, exit_code):
    findings = []
    if exit_code is None:
        # runner crashed, timed out or was killed before reporting: only a FAIL record is consistent
        if rec["result"] == "FAIL" and rec["exit_code"] != 0:
            return []
        return [("EVIDENCE_STATUS_INVALID", name, "log has no runner exit line; only FAIL is possible")]
    if exit_code != rec["exit_code"]:
        return [("EVIDENCE_STATUS_INVALID", name, "log exit %r differs from record exit_code %r" % (exit_code, rec["exit_code"]))]
    env = rec["environment"]
    if not isinstance(env_line, dict) or any(env_line.get(k) != env.get(k) for k in ("os", "kernel", "arch", "apt_versions_sha256")) \
            or (rec["tier"] == "simulated_libvirt" and env_line.get("libvirt") != env.get("libvirt")):
        findings.append(("EVIDENCE_MISMATCH", name, "environment differs from the runner's environment line"))
    if "tests" in rec["subject"]:
        cited = set(rec["subject"]["tests"])
        if set(outcomes) != cited:
            findings.append(("EVIDENCE_UNBOUND", name, "log results %s do not match cited tests" % sorted(set(outcomes) ^ cited)))
        all_pass = cited <= set(outcomes) and all(outcomes[r] == "pass" for r in cited)
        if rec["result"] == "PASS" and not all_pass:
            findings.append(("EVIDENCE_UNBOUND", name, "PASS but the log shows %s"
                             % {r: outcomes.get(r, "missing") for r in sorted(cited) if outcomes.get(r) != "pass"}))
        if rec["result"] == "FAIL" and all_pass and exit_code == 0:
            findings.append(("EVIDENCE_STATUS_INVALID", name, "FAIL but every cited test passed"))
    elif rec["result"] == "FAIL" and exit_code == 0:
        findings.append(("EVIDENCE_STATUS_INVALID", name, "FAIL but the gate succeeded"))
    return findings


def is_current(ctx, rec, plat, docs_sha):
    """(current?, reason) judged at HEAD (plus uncommitted changes) and the pinned docs commit (erratum r2b)."""
    head_backlog = ctx.backlog_at(ctx.docs_sha)
    rec_backlog = ctx.backlog_at(docs_sha)
    fields = ("given", "when", "then", "verification", "tier")
    for ac in rec["acceptance"]:
        if head_backlog is None or ac not in head_backlog[1]:
            return False, "%s no longer exists" % ac
        if any(head_backlog[1][ac].get(f) != rec_backlog[1][ac].get(f) for f in fields):
            return False, "%s text changed since revision.docs" % ac
    changed = sorted({p for p in ctx.git.changed(plat, "HEAD") + ctx.git.dirty() if not p.startswith("evidence/")})
    subject = rec["subject"]
    if "gate" not in subject:
        for ref in subject["tests"]:
            hits = ec.classify(ctx.classes, ec.test_ref(ref)[1])
            if len(hits) != 1 or hits[0]["tier"] != rec["tier"]:
                return False, "classification of %s changed" % ref
    if "gate" in subject or ec.test_ref(subject["tests"][0])[0] == "py":
        hit = changed  # conservative: tests may read any file
    else:
        pkg_dirs = {str(Path(ec.test_ref(r)[1]).parent) for r in subject["tests"]}
        missing = sorted(d for d in pkg_dirs if not (ctx.root / d).is_dir())
        if missing:
            return False, "cited package removed: %s" % ", ".join(missing)
        dep_dirs = go_dep_dirs(ctx.root, rec["tier"], pkg_dirs, ctx.go)
        if dep_dirs is None:
            return False, "cited package no longer builds test files for tier %s" % rec["tier"]
        hit = [p for p in changed if not p.startswith("backend/") or p in ("backend/go.mod", "backend/go.sum")
               or any(p.startswith(d + "/") for d in dep_dirs)]
    return (False, "dependencies changed: %s" % ", ".join(hit[:5])) if hit else (True, "")


def human_verified(ctx, rid):
    if not ID_RE.fullmatch(rid):
        return False
    out = ctx.docs.run("grep", "-l", "-E", "^[[:space:]]*EVIDENCE-CONFIRMED: %s[[:space:]]*$" % rid, ctx.docs_sha,
                       "--", "merges", "decisions")
    return bool(out and out.strip())


# ---- driver -------------------------------------------------------------------------------------------------------
def load(root, docs_repo):
    linkage = ec.load_linkage()
    try:
        linkage.require_git_version()
        linkage.require_repo(docs_repo, "DOCS_REPO_UNAVAILABLE", "docs-repo")
        raw = (Path(root) / "docs-lock.json").read_bytes()
        lock_findings, sha = linkage.check_lock_bytes(raw, "docs-lock.json")
        docs_link = linkage.Docs(docs_repo)
        if lock_findings or not docs_link.commit_exists(sha) or not docs_link.is_trusted(sha):
            raise EnvError("docs-lock.json does not pin a trusted docs commit")
    except linkage.EnvError as exc:
        raise EnvError("%s: %s" % (exc.code, exc.message)) from None
    except OSError as exc:
        raise EnvError("cannot read docs-lock.json: %s" % exc.strerror) from None
    docs = Git(linkage, docs_repo)
    taxonomy = docs.json_at(sha, ec.TAXONOMY_PATH)
    if taxonomy is None:
        raise EnvError("%s missing or malformed at pinned docs commit %s" % (ec.TAXONOMY_PATH, sha[:12]))
    try:
        classes = ec.loads((Path(root) / ec.CLASSES_PATH).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        classes = {"_error": exc.__class__.__name__}
    return Git(linkage, root), docs, sha, taxonomy, classes


def run(root, docs_repo, go="go", discover=None):
    """Return (findings, (ctx, records)) where records = [(path, record, state)]."""
    git, docs, docs_sha, taxonomy, classes = load(root, docs_repo)
    try:
        schema = ec.loads((Path(root) / "contracts/evidence/record.schema.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        schema = "invalid"
    findings = check_contracts(taxonomy, classes, schema)
    if findings:
        return findings, (None, [])
    discovered = (discover or (lambda r, t: discover_go(r, t, go) | discover_other(r)))(root, taxonomy)
    findings += check_classification(root, taxonomy, classes, discovered)
    findings += check_history(git)
    ctx = Context(root, git, docs, docs_sha, taxonomy, classes, go)
    rec_dir = Path(root) / ec.RECORDS_DIR
    log_dir = Path(root) / ec.LOGS_DIR
    loaded = []
    for path in sorted(rec_dir.iterdir()) if rec_dir.is_dir() else []:
        if path.name == ".gitkeep":
            continue
        if path.suffix != ".json" or not path.is_file() or path.is_symlink():
            findings.append(("EVIDENCE_INVALID", path.name, "evidence/records holds only <id>.json files"))
            continue
        try:
            loaded.append((path, ec.loads(path.read_text(encoding="utf-8"))))
        except (ValueError, UnicodeDecodeError, RecursionError):
            findings.append(("EVIDENCE_INVALID", path.name, "not valid JSON (or duplicate keys)"))
    ids = {}
    for path, rec in loaded:
        rid = rec.get("id") if isinstance(rec, dict) else None
        if isinstance(rid, str):
            ids.setdefault(rid, []).append(path.name)
    duplicated = {rid for rid, names in ids.items() if len(names) > 1}
    for rid in sorted(duplicated):
        findings.append(("EVIDENCE_DUPLICATE", rid, "id appears in %s" % sorted(ids[rid])))
    records = []
    for path, rec in loaded:
        if isinstance(rec, dict) and isinstance(rec.get("id"), str) and rec["id"] in duplicated:
            records.append((path, rec, None))  # one code per duplicate (r2b, M6)
            continue
        try:
            f, state = check_record(ctx, path, rec)
        except (TypeError, KeyError, AttributeError, ValueError, RecursionError) as exc:
            f, state = [("EVIDENCE_INVALID", path.name, "malformed record: %s" % exc.__class__.__name__)], None
        findings += f
        records.append((path, rec, state))
    referenced = {r["id"] for _, r, _ in records if isinstance(r, dict) and isinstance(r.get("id"), str)}
    for path in sorted(log_dir.iterdir()) if log_dir.is_dir() else []:
        if path.name != ".gitkeep" and (path.suffix != ".log" or path.stem not in referenced):
            findings.append(("EVIDENCE_INVALID", path.name, "log not referenced by any record"))
    return findings, (ctx, records)


def report(ctx_records):
    ctx, records = ctx_records
    stories, acs = ctx.backlog_at(ctx.docs_sha)
    lines = ["# Evidence report: local evidence only; implies no release-gate credit and no story completion",
             "docs commit %s" % ctx.docs_sha, ""]
    by_ac = {}
    for path, rec, state in records:
        if state is None:
            continue
        for ac in rec["acceptance"]:
            by_ac.setdefault(ac, []).append((rec, state))
    shown = sorted({a for a, x in acs.items() if stories.get(x["story_id"]) in ("ready", "in-progress", "review", "verified", "done")}
                   | set(by_ac))
    lines.append("| Story (status) | AC (status, backlog tier) | Evidence state | Tests / gate -> record (tier, result, state, run by) |")
    lines.append("|---|---|---|---|")
    flagged = []
    for ac in shown:
        a = acs.get(ac)
        if a is None:
            continue
        recs = by_ac.get(ac, [])
        permitted = set(ctx.taxonomy["ac_tier_map"].get(a["tier"], []))
        cur = [r for r, s in recs if s == "current" and r["tier"] in permitted]
        if any(r["result"] == "FAIL" for r in cur):
            state = "FAILING"
        elif any(r["result"] == "PASS" for r in cur):
            state = "EVIDENCED_LOCAL"
        elif any(r["result"] == "BLOCKED" for r in cur):
            state = "BLOCKED"
        elif recs:
            state = "STALE" if any(s.startswith("stale") for _, s in recs) else "MISSING"
        else:
            state = "MISSING"
        desc = []
        for r, s in recs:
            prov = r["run_by"] if r["run_by"] == "agent" or human_verified(ctx, r["id"]) else "human (unverified)"
            subj = r["subject"].get("gate") and "gate:" + r["subject"]["gate"] or ", ".join(r["subject"]["tests"])
            desc.append("%s -> %s (%s, %s, %s, %s)" % (subj, r["id"], r["tier"], r["result"], s, prov))
        story = a["story_id"]
        lines.append("| %s (%s) | %s (%s, %s) | %s | %s |" % (story, stories.get(story), ac, a.get("status"), a["tier"],
                                                          state, "; ".join(desc) or "—"))
        if stories.get(story) in ("verified", "done") and state != "EVIDENCED_LOCAL":
            flagged.append(ac)
    if flagged:
        lines += ["", "**Flag (not a failure):** verified stories with ACs lacking current local evidence: %s"
                  % ", ".join(flagged)]
    return "\n".join(lines)


def main(argv=None):
    parser = argparse.ArgumentParser(description="Check test-evidence records (M0-E02-S04).")
    parser.add_argument("--docs-repo", required=True)
    parser.add_argument("--go", default="go")
    parser.add_argument("--report", action="store_true", help="print the story -> AC -> test -> evidence report")
    parser.add_argument("--states", action="store_true", help="print one JSON line per record (used by replay)")
    args = parser.parse_args(argv)
    try:
        findings, ctx_records = run(ROOT, args.docs_repo, args.go)
        text = report(ctx_records) if args.report and not findings else None
    except EnvError as exc:
        print("ERROR USAGE %s" % exc)
        return 2
    for code, subject, message in findings:
        print("ERROR %s %s: %s" % (code, subject, message))
    if findings:
        return 1
    _, records = ctx_records
    stale = [p.name for p, _, s in records if s and s.startswith("stale")]
    for p, _, s in records:
        if s and s.startswith("stale"):
            print("STALE %s: %s" % (p.name, s[6:]))
    if text:
        print(text)
    if args.states:
        for p, rec, s in records:
            print(json.dumps({"evidence_record": rec["id"], "state": s, "result": rec["result"]}, sort_keys=True))
    print("OK evidence: %d record(s), %d current, %d stale" % (len(records), len(records) - len(stale), len(stale)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
