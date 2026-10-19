"""Shared definitions for test-evidence tooling (story M0-E02-S04; DR-006 D1/D2/D3 = A).

Used by tools/check_evidence.py (checker and report), tools/record_evidence.py
(host recorder), tools/replay_evidence.py and tools/evidence_runner.py (runs
inside the pinned container). Standard library only.

The canonical taxonomy lives in the docs repo (contracts/evidence-taxonomy.json)
and is read at the pinned docs commit through tools/check_linkage.py's
hardened git access (D2 = A).
"""
import hashlib
import importlib.util
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TAXONOMY_PATH = "contracts/evidence-taxonomy.json"
CLASSES_PATH = "contracts/evidence/test-classes.json"
RECORDS_DIR = "evidence/records"
LOGS_DIR = "evidence/logs"
MAX_LOG_BYTES = 8 * 1024 * 1024
RUNNER = ["toolchain/run-in-copy.sh", "python3", "tools/evidence_runner.py"]
GO_TEST_REF_RE = re.compile(r"(?P<path>backend/(?:[A-Za-z0-9_][A-Za-z0-9_.-]*/)*[A-Za-z0-9_][A-Za-z0-9_.-]*_test\.go)"
                            r"::(?P<name>Test[A-Z0-9_][A-Za-z0-9_]*)")
PY_TEST_REF_RE = re.compile(r"(?P<path>tests/[A-Za-z0-9_]+\.py)::(?P<cls>[A-Za-z_][A-Za-z0-9_]*)\."
                            r"(?P<name>test[A-Za-z0-9_]*)")
# The read-only production adapter (-tags libvirt) is exercised only together with the in-process test driver (libvirt_test).
TIER_TAGS = {"simulated_libvirt": ("libvirt_test", "libvirt")}
RESULTS = ("PASS", "FAIL", "NOT_RUN", "BLOCKED")


def reject_duplicates(pairs):
    keys = [k for k, _ in pairs]
    if len(keys) != len(set(keys)):
        raise ValueError("duplicate JSON key")
    return dict(pairs)


def loads(raw):
    return json.loads(raw, object_pairs_hook=reject_duplicates)


def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def record_id(record):
    """EV- + 16 hex of sha256 over the record without `id` and without `log.path` (erratum r2a, X1)."""
    body = {k: v for k, v in record.items() if k != "id"}
    if isinstance(body.get("log"), dict):
        body["log"] = {k: v for k, v in body["log"].items() if k != "path"}
    return "EV-" + hashlib.sha256(canonical(body)).hexdigest()[:16]


def test_ref(ref):
    """Return ("go", path, name) / ("py", path, "Class.test") or None."""
    if not isinstance(ref, str):
        return None
    m = GO_TEST_REF_RE.fullmatch(ref)
    if m:
        return ("go", m.group("path"), m.group("name"))
    m = PY_TEST_REF_RE.fullmatch(ref)
    if m:
        return ("py", m.group("path"), "%s.%s" % (m.group("cls"), m.group("name")))
    return None


def expected_command(subject, tier):
    """The only command a record may carry: generated from the tier runner and the subject (review M1)."""
    if "gate" in subject:
        return RUNNER + ["--gate", subject["gate"]]
    return RUNNER + ["--tier", tier, "--"] + sorted(set(subject["tests"]))


def glob_regex(pattern):
    """Translate a path glob (`**` any depth, `*` within a segment) to an anchored regex."""
    out, i = [], 0
    while i < len(pattern):
        if pattern.startswith("**/", i):
            out.append(r"(?:[^/]+/)*")
            i += 3
        elif pattern.startswith("**", i):
            out.append(r".*")
            i += 2
        elif pattern[i] == "*":
            out.append(r"[^/]*")
            i += 1
        else:
            out.append(re.escape(pattern[i]))
            i += 1
    return re.compile("".join(out))


def classify(classes, path):
    """Return the list of rules matching path (exclusions applied)."""
    hits = []
    for rule in classes.get("rules", []):
        if glob_regex(rule["glob"]).fullmatch(path) and not any(glob_regex(x).fullmatch(path)
                                                                   for x in rule.get("exclude", [])):
            hits.append(rule)
    return hits


def load_linkage():
    spec = importlib.util.spec_from_file_location("check_linkage", ROOT / "tools" / "check_linkage.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_check_threats():
    spec = importlib.util.spec_from_file_location("check_threats", ROOT / "tools" / "check_threats.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def parse_runner_log(text):
    """Return (env, {ref: outcome}, exit) from runner output; non-JSON lines are ignored."""
    env, outcomes, exit_code = None, {}, None
    for line in text.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            obj = json.loads(line)
        except ValueError:
            continue
        if not isinstance(obj, dict):
            continue
        if "evidence_env" in obj and isinstance(obj["evidence_env"], dict):
            env = env if env is not None else obj["evidence_env"]  # the runner prints it first; later ones are spoofs
        elif "evidence_test" in obj and isinstance(obj.get("outcome"), str):
            prev = outcomes.get(obj["evidence_test"])
            # any non-pass outcome for a ref wins (a test reported twice cannot launder a failure)
            outcomes[obj["evidence_test"]] = obj["outcome"] if prev in (None, "pass") else prev
        elif "evidence_exit" in obj and type(obj["evidence_exit"]) is int:
            exit_code = obj["evidence_exit"]
    return env, outcomes, exit_code


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()
