#!/usr/bin/env python3
"""Threat model and data-boundary checker (story M0-E01-S02).

Validates contracts/threats/*.json against the M0-E01-S01 interface
contracts and the backlog at the pinned docs commit. Standard library only;
the docs repository is read through tools/check_linkage.py's hardened git
access (pinned objects, trusted ref, no network).

Every threat<->mitigation reference is recorded on both sides and must agree,
entries have exact key sets, and every kind requires specific controls, so
removing any entry or reference yields a typed finding.

Exit codes: 0 no findings, 1 findings, 2 usage or environment error.
"""
import argparse
import ast
import datetime
import importlib.util
import json
import os
import re
import subprocess
import sys
import unicodedata
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
STRIDE = ("spoofing", "tampering", "repudiation", "information_disclosure", "denial_of_service",
          "elevation_of_privilege")
REQUIRED_KINDS = ("injection", "authz_bypass", "replay")
# kind -> (allowed STRIDE categories, controls every threat of that kind must cite)
KINDS = {
    "impersonation": ({"spoofing"}, {"authn"}),
    "injection": ({"tampering"}, {"schema"}),
    "replay": ({"tampering"}, {"idempotency"}),
    "repudiation": ({"repudiation"}, {"audit"}),
    "disclosure": ({"information_disclosure"}, {"ownership", "redaction"}),
    "exhaustion": ({"denial_of_service"}, {"listener"}),
    "failure_row": ({"denial_of_service", "tampering"}, {"row_idempotency"}),
    "authz_bypass": ({"elevation_of_privilege"}, {"authz", "ownership"}),
    "local_privilege": ({"elevation_of_privilege", "spoofing"}, {"listener", "authn"}),
    "supply_chain": ({"tampering"}, {"digest"}),
    "exposure": ({"spoofing", "elevation_of_privilege"}, {"surface"}),
}
# control -> contract_field patterns valid as design evidence ({b}: the citing threat's boundary).
CONTROL_FIELDS = {
    "authn": (r"inventory\.boundaries\.{b}\.security\.peer_auth",),
    "authz": (r"inventory\.boundaries\.{b}\.security\.authz_model",),
    "ownership": (r"inventory\.boundaries\.{b}\.security\.ownership_check",),
    "audit": (r"inventory\.boundaries\.{b}\.audit",),
    "listener": (r"inventory\.boundaries\.{b}\.security\.listener",
                 r"prohibited\.categories\.(?:AGENT_TCP|REMOTE_HYPERVISOR)\.allowed_transports"),
    "schema": (r"request-schemas\.categories\.(?P<category>[a-z_]+)",
               r"prohibited\.categories\.(?:HYPERVISOR_XML|ARBITRARY_SHELL)(?:\.tokens)?"),
    "redaction": (r"prohibited\.redaction\.key_substrings",),
    "idempotency": (r"failure-matrix\.rows\.[a-z-]+\.idempotency", r"resources\.resources\.[A-Za-z]+\.generation_tracking"),
    "row_idempotency": (r"failure-matrix\.rows\.(?P<row>[a-z-]+)\.idempotency",),
    "digest": (r"request-schemas\.value_types\.digest",),
    "credential_block": (r"prohibited\.categories\.PROVIDER_CREDENTIALS\.tokens",),
    "surface": (),
}
# Code paths whose tests are runtime evidence for a boundary. Only boundaries
# whose implementation_status is not "not_implemented" may claim runtime
# evidence at all (review F1).
RUNTIME_PATHS = {"browser-api": ("backend/cmd/api/",)}
STATUSES = ("mitigated", "planned", "accepted")
OPEN_STORY_STATUSES = ("proposed", "ready", "in-progress", "review")
LEVELS = ("low", "medium", "high")
CLASSES = ("secret", "credential", "personal", "operational", "public")
PROTECTED_CLASSES = ("secret", "credential")
RULE_KEYS = ("loggable", "exportable", "redacted", "encrypted_at_rest")
ENVELOPE_KEYS = ("boundary", "category", "payload", "transport")
THREAT_KEYS = {"id", "boundary", "category", "kind", "description", "likelihood", "impact", "mitigations", "status"}
STATUS_KEYS = {"mitigated": set(), "planned": {"owner_story"}, "accepted": {"accepted_by", "accepted_on", "acceptance_ref"}}
MITIGATION_KEYS = {"id", "control", "description", "error_category", "evidence", "threats"}
ID_RE = re.compile(r"[TM]-[A-Z0-9]+(?:-[A-Z0-9]+)*")
STORY_RE = re.compile(r"M\d+-E\d{2}-S\d{2}")
DECISION_RE = re.compile(r"decisions/DR-\d{3}-[A-Za-z0-9-]+\.md")
TEST_REF_RE = re.compile(r"(?P<path>[A-Za-z0-9_./-]+)::(?P<name>[A-Za-z_][A-Za-z0-9_]*)")
PATH_PART_RE = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]*")
THREAT_FILES = ("threat-register", "mitigations", "data-classes")
INTERFACE_FILES = ("errors", "inventory", "resources", "prohibited", "failure-matrix", "request-schemas")
TEST_NAME_RE = re.compile(r"Test(?![a-z])[A-Za-z0-9_]*")
AI_NAMES = {"claude", "opus", "sonnet", "fable", "anthropic", "openai", "gpt", "chatgpt", "assistant", "bot", "agent",
            "llm", "copilot", "gemini"}
GO_TIMEOUT = 900
# Must equal the Makefile go-test gate (GO_TEST_FLAGS / GO_ENV there; pinned by a unit test).
GO_BUILD_FLAGS = ("-race",)
GO_TEST_FLAGS = GO_BUILD_FLAGS + ("-count=1",)
GO_ENV = {"GOFLAGS": "-mod=readonly", "GOTOOLCHAIN": "local", "GOWORK": "off"}
MAX_DECISION_BYTES = 1 << 20
FINDING_CODES = ("THREAT_MISSING", "THREAT_UNOWNED", "ACCEPTANCE_UNOWNED", "MITIGATION_DANGLING", "EVIDENCE_MISSING",
                 "RUNTIME_CLAIM", "FIELD_UNCLASSIFIED", "CREDENTIAL_LOGGABLE", "SECRET_UNREDACTED", "ROW_UNREFERENCED",
                 "CONTRACT_INVALID")


def reject_duplicates(pairs):
    keys = [k for k, _ in pairs]
    if len(keys) != len(set(keys)):
        raise ValueError("duplicate JSON key")
    return dict(pairs)


def load_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8"), object_pairs_hook=reject_duplicates)


def load_linkage():
    spec = importlib.util.spec_from_file_location("check_linkage", ROOT / "tools" / "check_linkage.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def docs_context(docs_repo):
    """Return ({story_id: status}, {decision path: text}) at the pinned docs commit, or raise SystemExit(2)."""
    linkage = load_linkage()
    try:
        linkage.require_git_version()
        linkage.require_repo(docs_repo, "DOCS_REPO_UNAVAILABLE", "docs-repo")
        raw = (ROOT / "docs-lock.json").read_bytes()
        findings, sha = linkage.check_lock_bytes(raw, "docs-lock.json")
        docs = linkage.Docs(docs_repo)
        if findings or not docs.commit_exists(sha) or not docs.is_trusted(sha) or docs.backlog(sha) is None:
            print("ERROR USAGE docs-lock.json does not pin a trusted, valid docs commit")
            raise SystemExit(2)
        listing = linkage.git(docs_repo, "ls-tree", "--name-only", "--end-of-options", sha, "decisions/") or b""
        decisions = {}
        for path in listing.decode("utf-8", "replace").splitlines():
            spec = "%s:%s" % (sha, path)
            size = linkage.object_size(docs_repo, spec)
            if DECISION_RE.fullmatch(path) and size is not None and size <= MAX_DECISION_BYTES:
                decisions[path] = (linkage.git(docs_repo, "cat-file", "blob", spec) or b"").decode("utf-8", "replace")
        return docs.backlog(sha)[0], decisions
    except linkage.EnvError as exc:
        print("ERROR USAGE %s: %s" % (exc.code, exc.message))
        raise SystemExit(2)
    except OSError as exc:
        print("ERROR USAGE cannot read docs-lock.json: %s" % exc.strerror)
        raise SystemExit(2)


def resolve_field(interfaces, dotted):
    """Resolve 'file.key.key...' (at least one key) inside the interface contracts; None if absent."""
    name, _, rest = dotted.partition(".")
    if not rest or name not in interfaces:
        return None
    node = interfaces[name]
    for part in rest.split("."):
        if not isinstance(node, dict) or part not in node:
            return None
        node = node[part]
    return node


def safe_path(root, rel):
    """Return the resolved file for a clean, relative, symlink-free path inside root, else None."""
    if not isinstance(rel, str) or "\\" in rel:
        return None
    parts = rel.split("/")
    if not all(PATH_PART_RE.fullmatch(p) for p in parts):
        return None
    path = Path(root)
    for part in parts:
        path = path / part
        if path.is_symlink():
            return None
    return path if path.is_file() else None


def strip_go_comments(text):
    """Remove Go comments and blank out string and rune literals (line numbers kept)."""
    out, i, n = [], 0, len(text)
    while i < n:
        c = text[i]
        if text.startswith("//", i):
            j = text.find("\n", i)
            i = n if j < 0 else j
        elif text.startswith("/*", i):
            j = text.find("*/", i + 2)
            out.append("\n" * text.count("\n", i, n if j < 0 else j))
            i = n if j < 0 else j + 2
        elif c in "\"'`":
            j = i + 1
            while j < n and text[j] != c:
                j += 2 if c != "`" and text[j] == "\\" else 1
            out.append('""' + "\n" * text.count("\n", i, j))
            i = j + 1
        else:
            out.append(c)
            i += 1
    return "".join(out)


class GoInventoryError(Exception):
    pass


def json_stream(raw):
    """Decode a stream of concatenated JSON objects (go list -json, go test -json)."""
    text, decoder, i, out = raw.decode("utf-8", "replace"), json.JSONDecoder(), 0, []
    while True:
        while i < len(text) and text[i].isspace():
            i += 1
        if i >= len(text):
            return out
        obj, i = decoder.raw_decode(text, i)
        out.append(obj)


def go_inventory(root, go="go", tags=()):
    """Return {repo-relative test file: frozenset(test names go test runs in its package)}.

    Authoritative (sponsor item 11): file selection, build constraints, go.mod
    ignore directives, nested modules and package clauses are decided by the
    pinned Go toolchain itself, with exactly the go-test gate's flags
    (GO_TEST_FLAGS, review cycle 5 C5-1). Packages that define TestMain supply
    no evidence: TestMain runs during listing and can list tests it never runs
    (C5-2); a package with any test file that cannot be scanned safely supplies none
    (C6-1). Files reached through a symlink are skipped (C5-3). Any go failure
    raises GoInventoryError (fail closed).
    """
    top = Path(root).resolve()
    env = dict(os.environ, **GO_ENV)

    def run(*args):
        try:
            proc = subprocess.run([go, *args], cwd=top / "backend", env=env, capture_output=True, timeout=GO_TIMEOUT,
                                  check=False)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise GoInventoryError("go %s: %s" % (args[0], exc.__class__.__name__)) from None
        if proc.returncode != 0:
            detail = proc.stderr.decode("utf-8", "replace")
            try:
                detail += "".join(e.get("Output", "") for e in json_stream(proc.stdout)
                                  if isinstance(e, dict) and e.get("Action") == "build-output")
            except ValueError:
                pass
            raise GoInventoryError("go %s exited %d: %s" % (args[0], proc.returncode, detail.strip()[-500:]))
        return proc.stdout

    try:
        tag_args = ("-tags", ",".join(tags)) if tags else ()  # M0-E02-S04: per-tier build tags; default unchanged
        packages = json_stream(run("list", *GO_BUILD_FLAGS, *tag_args, "-json=Dir,ImportPath,TestGoFiles,XTestGoFiles",
                                   "./..."))
        events = json_stream(run("test", *GO_TEST_FLAGS, *tag_args, "-list", ".", "-json", "./..."))
    except ValueError:
        raise GoInventoryError("go produced malformed JSON") from None
    listed = {}
    for event in events:
        name = event.get("Output", "").strip() if isinstance(event, dict) and event.get("Action") == "output" else ""
        if TEST_NAME_RE.fullmatch(name) and isinstance(event.get("Package"), str):
            listed.setdefault(event["Package"], set()).add(name)
    inventory = {}
    for pkg in packages:
        if not isinstance(pkg, dict) or not isinstance(pkg.get("Dir"), str):
            continue
        # Every test file Go compiles must be scanned for TestMain; if any listed file
        # cannot be scanned safely (symlink, unusual name, outside the repo, unreadable),
        # the whole package supplies no evidence (fail closed; review cycle 6 C6-1).
        files, complete = [], True
        for name in list(pkg.get("TestGoFiles") or []) + list(pkg.get("XTestGoFiles") or []):
            try:
                rel = (Path(pkg["Dir"]) / name).relative_to(top).as_posix()
            except ValueError:
                complete = False
                continue
            path = safe_path(top, rel)
            if path is None:
                complete = False
            else:
                files.append((rel, path))
        try:
            has_main = any(re.search(r"^func\s+TestMain\s*\(", strip_go_comments(path.read_text(encoding="utf-8",
                                                                                                errors="replace")), re.M)
                           for _, path in files)
        except OSError:
            has_main = True
        names = frozenset() if has_main or not complete else frozenset(listed.get(pkg.get("ImportPath"), ()))
        for rel, _ in files:
            inventory[rel] = names
    return inventory


def go_body(code, start):
    """Return the text between the brace before start and its matching close brace (comments/strings already blanked)."""
    depth, i = 1, start
    while i < len(code) and depth:
        depth += {"{": 1, "}": -1}.get(code[i], 0)
        i += 1
    return code[start:i - 1] if depth == 0 else ""


def runtime_test(root, ref, inventory=None):
    """Return the test file path if ref names an existing runtime test function, else None.

    Go: the pinned Go toolchain must list the test for the package containing
    the file (go_inventory; None = unavailable = rejected), and the file must
    define it as a top-level `func TestX(t *testing.T)` outside comments and
    strings, with a non-empty body that does not call t.Skip*. Python: a
    `test_*` function in tests/integration_*.py (module level or in a class).
    """
    match = TEST_REF_RE.fullmatch(ref) if isinstance(ref, str) else None
    if not match:
        return None
    rel, name = match.group("path"), match.group("name")
    path = safe_path(root, rel)
    if path is None:
        return None
    try:
        text = path.read_text(encoding="utf-8", errors="replace").lstrip("\ufeff")
    except OSError:
        return None
    if re.fullmatch(r"backend/(?:[^/]+/)*[^/]+_test\.go", rel):
        if not TEST_NAME_RE.fullmatch(name) or inventory is None or name not in inventory.get(rel, ()):
            return None
        code = strip_go_comments(text)
        pattern = r"^func %s\(\s*([A-Za-z_][A-Za-z0-9_]*)\s+\*testing\.T\s*\)\s*\{" % re.escape(name)
        match = re.search(pattern, code, re.M)
        body = go_body(code, match.end()) if match else ""
        # An empty or skipped test exercises nothing (review cycle 2 probes).
        if not body.strip() or re.search(r"\b%s\.Skip(?:f|Now)?\(" % match.group(1), body):
            return None
        return rel
    if re.fullmatch(r"tests/integration_[A-Za-z0-9_]+\.py", rel):
        if not name.startswith("test_"):
            return None
        try:
            tree = ast.parse(text)
        except (SyntaxError, ValueError):
            return None
        nodes = list(tree.body) + [n for c in tree.body if isinstance(c, ast.ClassDef) for n in c.body]
        return rel if any(isinstance(n, ast.FunctionDef) and n.name == name for n in nodes) else None
    return None


def meaningful(value):
    """Design evidence must be a non-empty, affirmative value."""
    return value is not None and value is not False and value not in ("", [], {})


def check(root, contracts_dir, interfaces_dir, stories, decisions=None, inventory=None):
    findings, decisions = [], decisions or {}
    interfaces, threats_doc = {}, {}
    try:
        for name in INTERFACE_FILES:
            interfaces[name] = load_json(Path(interfaces_dir) / ("%s.json" % name))
        for name in THREAT_FILES:
            threats_doc[name] = load_json(Path(contracts_dir) / ("%s.json" % name))
    except (OSError, ValueError, RecursionError) as exc:
        return [("CONTRACT_INVALID", "load", exc.__class__.__name__)]
    for name, doc in threats_doc.items():
        if not isinstance(doc, dict) or type(doc.get("schema")) is not int or doc.get("schema") != 1 \
                or not text(doc.get("description")):
            return [("CONTRACT_INVALID", name, "must be an object with schema 1 and a description")]
    try:
        findings.extend(check_threats(root, interfaces, threats_doc, stories, decisions, inventory))
        findings.extend(check_data_classes(interfaces, threats_doc["data-classes"]))
    except (TypeError, AttributeError, KeyError, ValueError) as exc:
        findings.append(("CONTRACT_INVALID", "structure", "malformed structure: %s" % exc.__class__.__name__))
    return findings


def unique_list(value):
    return isinstance(value, list) and value and all(isinstance(x, str) for x in value) and len(value) == len(set(value))


def text(value):
    return isinstance(value, str) and len(value.strip()) >= 10


def check_mitigations(root, interfaces, docs, inventory):
    findings, mitigations, bad = [], {}, set()
    errors = interfaces["errors"]["categories"]
    entries = docs["mitigations"]["mitigations"]
    if not isinstance(entries, list):
        return [("CONTRACT_INVALID", "mitigations", "mitigations must be a list")], mitigations, bad
    for m in entries:
        mid = m.get("id") if isinstance(m, dict) else None
        if not isinstance(mid, str) or not ID_RE.fullmatch(mid) or not mid.startswith("M-"):
            findings.append(("CONTRACT_INVALID", "mitigations", "mitigation needs an id M-..."))
            continue
        if mid in mitigations:
            findings.append(("CONTRACT_INVALID", mid, "duplicate mitigation id"))
            continue
        mitigations[mid] = m
        if set(m) != MITIGATION_KEYS:
            findings.append(("CONTRACT_INVALID", mid, "keys must be exactly %s" % sorted(MITIGATION_KEYS)))
        if m.get("control") not in CONTROL_FIELDS or not text(m.get("description")):
            findings.append(("CONTRACT_INVALID", mid, "control must be one of %s; description required" % sorted(CONTROL_FIELDS)))
        if not unique_list(m.get("threats")):
            findings.append(("MITIGATION_DANGLING", mid, "mitigation addresses no threats (orphan)"))
        if m.get("error_category") not in errors:
            findings.append(("EVIDENCE_MISSING", mid, "error_category must be a typed E01-S01 error category"))
        evidence = m.get("evidence")
        if not isinstance(evidence, dict) or len(evidence) != 1:
            findings.append(("EVIDENCE_MISSING", mid, "evidence must have exactly one of test_id, fixture, contract_field"))
            continue
        (kind, ref), = evidence.items()
        if kind == "test_id":
            ok = runtime_test(root, ref, inventory) is not None
        elif kind == "fixture":
            ok = isinstance(ref, str) and ref.startswith("tests/fixtures/") and safe_path(root, ref) is not None \
                and safe_path(root, ref).stat().st_size > 0
        elif kind == "contract_field":
            ok = isinstance(ref, str) and meaningful(resolve_field(interfaces, ref))
        else:
            ok = False
        if not ok:
            findings.append(("EVIDENCE_MISSING", mid, "evidence %s does not exist or is empty: %r" % (kind, ref)))
            bad.add(mid)
    return findings, mitigations, bad


def evidence_fits(interfaces, boundary, m):
    """Design evidence must be the field that specifies this control on this boundary."""
    ref = m["evidence"].get("contract_field")
    if ref is None:
        return True
    for pattern in CONTROL_FIELDS[m["control"]]:
        match = re.fullmatch(pattern.replace("{b}", re.escape(boundary)), ref)
        if not match:
            continue
        cat = match.groupdict().get("category")
        if cat is not None and cat not in interfaces["inventory"]["boundaries"][boundary]["permitted_request_categories"]:
            continue
        return True
    return False


def check_threats(root, interfaces, docs, stories, decisions, inventory):
    findings, mitigations, bad = check_mitigations(root, interfaces, docs, inventory)
    boundaries = interfaces["inventory"]["boundaries"]
    rows = interfaces["failure-matrix"]["rows"]
    threats = docs["threat-register"]["threats"]
    if not isinstance(threats, list):
        return findings + [("CONTRACT_INVALID", "threat-register", "threats must be a list")]
    seen, cites = set(), {}
    coverage, kinds_cov, row_refs = set(), set(), set()
    for t in threats:
        tid = t.get("id") if isinstance(t, dict) else None
        if not isinstance(tid, str) or not ID_RE.fullmatch(tid) or not tid.startswith("T-"):
            findings.append(("CONTRACT_INVALID", "threat-register", "threat needs an id T-..."))
            continue
        if tid in seen:
            findings.append(("CONTRACT_INVALID", tid, "duplicate threat id"))
            continue
        seen.add(tid)
        b, cat, kind, status = t.get("boundary"), t.get("category"), t.get("kind"), t.get("status")
        if b not in boundaries or cat not in STRIDE or kind not in KINDS or status not in STATUSES \
                or t.get("likelihood") not in LEVELS or t.get("impact") not in LEVELS or not text(t.get("description")):
            findings.append(("CONTRACT_INVALID", tid, "boundary, category, kind, status, likelihood, impact and description required"))
            continue
        expected = THREAT_KEYS | STATUS_KEYS[status] | ({"failure_row"} if kind == "failure_row" else set())
        missing, extra = expected - set(t), set(t) - expected
        if extra:
            findings.append(("CONTRACT_INVALID", tid, "unexpected keys %s" % sorted(extra)))
        if cat not in KINDS[kind][0]:
            findings.append(("CONTRACT_INVALID", tid, "kind %s is not a %s threat" % (kind, cat)))
        coverage.add((b, cat))
        kinds_cov.add((b, kind))
        mids = t.get("mitigations")
        if not unique_list(mids):
            findings.append(("MITIGATION_DANGLING", tid, "threat must list distinct mitigations"))
            mids = mids if isinstance(mids, list) else []
        cites[tid] = {mid for mid in mids if isinstance(mid, str)}
        dangling = sorted(mid for mid in cites[tid] if mid not in mitigations)
        if dangling:
            findings.append(("MITIGATION_DANGLING", tid, "unknown mitigations %s" % dangling))
        resolved = [mitigations[mid] for mid in sorted(cites[tid]) if mid in mitigations]
        controls = {m.get("control") for m in resolved}
        for control in sorted(KINDS[kind][1] - controls):
            findings.append(("MITIGATION_DANGLING", tid, "%s threat must cite a %s mitigation" % (kind, control)))
        for m in resolved:
            if m.get("control") not in CONTROL_FIELDS or not isinstance(m.get("evidence"), dict) or m["id"] in bad:
                continue
            if m.get("error_category") not in boundaries[b]["error_categories"]:
                findings.append(("EVIDENCE_MISSING", tid, "%s error category %r is not returned by %s"
                                 % (m["id"], m.get("error_category"), b)))
            if not evidence_fits(interfaces, b, m):
                findings.append(("EVIDENCE_MISSING", tid, "%s evidence %s does not specify %s on %s"
                                 % (m["id"], m["evidence"].get("contract_field"), m["control"], b)))
        if kind == "failure_row":
            row = t.get("failure_row")
            field = "failure-matrix.rows.%s.idempotency" % row
            if row not in rows:
                findings.append(("ROW_UNREFERENCED", tid, "failure_row %r is not a failure-matrix row" % (row,)))
            elif any(m.get("evidence", {}).get("contract_field") == field for m in resolved
                     if m.get("control") == "row_idempotency" and isinstance(m.get("evidence"), dict)):
                row_refs.add(row)
        findings.extend(check_status(root, boundaries, t, status, missing, resolved, stories, decisions, inventory))
    for mid, m in sorted(mitigations.items()):
        listed = set(m["threats"]) if unique_list(m.get("threats")) else set()
        citing = {tid for tid, ids in cites.items() if mid in ids}
        for tid in sorted(listed - citing):
            findings.append(("MITIGATION_DANGLING", mid, "lists %s, which does not cite it" % tid))
        for tid in sorted(citing - listed):
            findings.append(("MITIGATION_DANGLING", mid, "cited by %s but does not list it" % tid))
    for b in sorted(boundaries):
        for cat in STRIDE:
            if (b, cat) not in coverage:
                findings.append(("THREAT_MISSING", b, "no %s threat" % cat))
        for kind in REQUIRED_KINDS:
            if (b, kind) not in kinds_cov:
                findings.append(("THREAT_MISSING", b, "no %s threat" % kind))
    for row in sorted(set(rows) - row_refs):
        findings.append(("ROW_UNREFERENCED", row, "no DoS/tampering threat cites this row's idempotency responsibility"))
    return findings


def check_status(root, boundaries, t, status, missing, resolved, stories, decisions, inventory):
    tid, b = t["id"], t["boundary"]
    if status == "mitigated":
        if boundaries[b].get("implementation_status") == "not_implemented":
            return [("RUNTIME_CLAIM", tid, "%s is not implemented; the threat must be planned or accepted" % b)]
        prefixes = RUNTIME_PATHS.get(b, ())
        design = sorted(m["id"] for m in resolved if not (prefixes and isinstance(m.get("evidence"), dict)
                        and (runtime_test(root, m["evidence"].get("test_id"), inventory) or "").startswith(prefixes)))
        if design or not resolved:
            return [("RUNTIME_CLAIM", tid, "mitigated requires every mitigation to cite a runtime test of %s code %s; "
                                           "design-only: %s" % (b, list(prefixes), design))]
        return []
    if status == "planned":
        owner = t.get("owner_story")
        if "owner_story" in missing or not isinstance(owner, str) or not STORY_RE.fullmatch(owner) \
                or stories.get(owner) not in OPEN_STORY_STATUSES:
            return [("THREAT_UNOWNED", tid, "planned threat needs an existing, open owner_story (%s)" % "/".join(OPEN_STORY_STATUSES))]
        return []
    by, on, ref = t.get("accepted_by"), t.get("accepted_on"), t.get("acceptance_ref")
    try:
        date_ok = isinstance(on, str) and datetime.date.fromisoformat(on).isoformat() == on
    except ValueError:
        date_ok = False
    if missing or not isinstance(by, str) or len(by.strip()) < 2 or ai_name(by) or not date_ok \
            or ref not in decisions or not re.search(r"(?<![A-Z0-9-])%s(?![A-Z0-9-])" % re.escape(tid), decisions[ref]):
        return [("ACCEPTANCE_UNOWNED", tid, "accepted threat needs a human accepted_by, a valid accepted_on date "
                                            "and an acceptance_ref to an approved decision record")]
    return []


def ai_name(value):
    """True if any word (split on non-letters and camelCase; 0->o, 1->l) names an AI tool or vendor."""
    value = value.translate(str.maketrans("01", "ol"))
    words = re.findall(r"[A-Z]?[a-z]+|[A-Z]+(?![a-z])", value)
    return any(w.casefold() in AI_NAMES for w in words)


def normalise(key):
    return unicodedata.normalize("NFKC", key).casefold().replace("-", "_")


def check_data_classes(interfaces, doc):
    findings = []
    if set(doc) != {"schema", "description", "classes", "fields"}:
        findings.append(("CONTRACT_INVALID", "data-classes", "keys must be schema, description, classes, fields"))
    classes, fields = doc.get("classes"), doc.get("fields")
    if not isinstance(classes, dict) or set(classes) != set(CLASSES):
        return findings + [("CONTRACT_INVALID", "data-classes", "classes must be exactly %s" % list(CLASSES))]
    for name, rules in classes.items():
        if not isinstance(rules, dict) or set(rules) != set(RULE_KEYS) or not all(type(v) is bool for v in rules.values()):
            findings.append(("CONTRACT_INVALID", name, "rules must be booleans %s" % list(RULE_KEYS)))
        elif name in PROTECTED_CLASSES and (rules["loggable"] or rules["exportable"] or not rules["redacted"]
                                            or not rules["encrypted_at_rest"]):
            findings.append(("CREDENTIAL_LOGGABLE", name, "secret/credential classes must be redacted, encrypted at rest, "
                                                          "not loggable, not exportable"))
    if not isinstance(fields, dict):
        return findings + [("CONTRACT_INVALID", "data-classes", "fields must be an object")]
    required = {"operation.%s" % f for f in interfaces["resources"]["operation_persisted_fields"]}
    required |= {"request.envelope.%s" % k for k in ENVELOPE_KEYS}
    for cat, keys in interfaces["request-schemas"]["categories"].items():
        required |= {"request.%s.%s" % (cat, k) for k in keys}
    for field in sorted(required - set(fields)):
        findings.append(("FIELD_UNCLASSIFIED", field, "field has no data class"))
    subs = [normalise(s) for s in interfaces["prohibited"]["redaction"]["key_substrings"]]
    for field, cls in sorted(fields.items()):
        redacted = any(s in normalise(field.rsplit(".", 1)[-1]) for s in subs)
        if cls not in CLASSES:
            findings.append(("FIELD_UNCLASSIFIED", field, "unknown class %r" % (cls,)))
        elif field not in required:
            findings.append(("FIELD_UNCLASSIFIED", field, "classified field does not exist in the contracts"))
        elif cls in PROTECTED_CLASSES and not redacted:
            findings.append(("SECRET_UNREDACTED", field, "secret/credential field name not covered by redaction substrings"))
        elif cls not in PROTECTED_CLASSES and redacted:
            findings.append(("CREDENTIAL_LOGGABLE", field, "field is redacted by E01-S01 rules but classed %s" % cls))
    return findings


def main(argv=None, context=docs_context, inventory_fn=go_inventory):
    parser = argparse.ArgumentParser(description="Check threat model and data classes (M0-E01-S02).")
    parser.add_argument("--docs-repo", required=True)
    parser.add_argument("--contracts", default=str(ROOT / "contracts" / "threats"))
    parser.add_argument("--interfaces", default=str(ROOT / "contracts" / "interfaces"))
    parser.add_argument("--go", default="go", help="Go toolchain used for the authoritative test inventory")
    args = parser.parse_args(argv)
    stories, decisions = context(args.docs_repo)
    try:
        inventory = inventory_fn(ROOT, args.go)
    except GoInventoryError as exc:
        print("ERROR USAGE GO_INVENTORY_UNAVAILABLE: %s" % exc)
        return 2
    findings = check(ROOT, args.contracts, args.interfaces, stories, decisions, inventory)
    for code, subject, message in findings:
        print("ERROR %s %s: %s" % (code, subject, message))
    if findings:
        return 1
    print("OK threats: register, mitigations and data classes valid")
    return 0


if __name__ == "__main__":
    sys.exit(main())
