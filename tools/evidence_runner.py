#!/usr/bin/env python3
"""Evidence tier runner (story M0-E02-S04). Runs INSIDE the pinned dev container via
toolchain/run-in-copy.sh; the host recorder (tools/record_evidence.py) generates
its argv, so a record's command is never free-form (requirements review M1).

Output (stdout, line oriented; other lines are passed-through tool output):
  {"evidence_env": {...}}                       environment identification
  {"evidence_test": "<ref>", "outcome": "..."}  one per cited test: pass|fail|skip|missing
  {"evidence_exit": <int>}                      0 only if every cited test passed / gate succeeded

Usage: evidence_runner.py --tier TIER -- REF...   |   evidence_runner.py --gate GATE
"""
import argparse
import contextlib
import hashlib
import io
import importlib.util
import json
import os
import platform
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import evidence_common as ec  # noqa: E402

APT_VERSIONS = Path("/usr/local/share/apt-versions.txt")


def emit(obj):
    print(json.dumps(obj, sort_keys=True), flush=True)


@contextlib.contextmanager
def fd_capture():
    """Redirect fds 1 and 2 (and so child processes and os.write) to a temp file while test code runs, so test
    code cannot write result lines on the runner's stdout (review N2). Yields a function returning the text."""
    sys.stdout.flush()
    sys.stderr.flush()
    saved = os.dup(1), os.dup(2)
    tmp = tempfile.TemporaryFile()
    holder = {}
    os.dup2(tmp.fileno(), 1)
    os.dup2(tmp.fileno(), 2)
    try:
        with contextlib.redirect_stdout(io.TextIOWrapper(os.fdopen(os.dup(1), "wb"), write_through=True)) as out, \
                contextlib.redirect_stderr(out):
            yield lambda: holder.get("text", "")
            out.flush()
    finally:
        os.dup2(saved[0], 1)
        os.dup2(saved[1], 2)
        os.close(saved[0])
        os.close(saved[1])
        tmp.seek(0)
        holder["text"] = tmp.read().decode("utf-8", "replace")
        tmp.close()


def passthrough(text, prefix="| "):
    """Echo tool/test output with a prefix, so only this runner's own lines start with '{' (no spoofed results)."""
    for line in text.splitlines():
        sys.stdout.write(prefix + line + "\n")
    sys.stdout.flush()


def environment(tier):
    env = {"kernel": platform.release(), "arch": platform.machine(), "os": "unknown"}
    try:
        for line in Path("/etc/os-release").read_text().splitlines():
            if line.startswith("PRETTY_NAME="):
                env["os"] = line.split("=", 1)[1].strip().strip('"')
    except OSError:
        pass
    try:
        env["apt_versions_sha256"] = hashlib.sha256(APT_VERSIONS.read_bytes()).hexdigest()
    except OSError:
        env["apt_versions_sha256"] = None
    if tier == "simulated_libvirt":
        try:
            out = subprocess.run(["pkg-config", "--modversion", "libvirt"], capture_output=True, text=True, timeout=30,
                                 check=False)
            env["libvirt"] = out.stdout.strip() or None
        except (OSError, subprocess.TimeoutExpired):
            env["libvirt"] = None
    return env


def run_go(tier, refs):
    ct = ec.load_check_threats()
    env = dict(os.environ, **ct.GO_ENV)
    tags = ec.TIER_TAGS.get(tier, ())
    tag_args = ["-tags", ",".join(tags)] if tags else []
    by_dir = {}
    for ref in refs:
        _, path, name = ec.test_ref(ref)
        by_dir.setdefault(str(Path(path).parent), []).append((ref, name))
    outcomes = {}
    for rel_dir, items in sorted(by_dir.items()):
        pkg_dir = "./" + str(Path(rel_dir).relative_to("backend"))
        listing = subprocess.run(["go", "list", *ct.GO_BUILD_FLAGS, *tag_args, "-json=ImportPath", pkg_dir],
                                 cwd=ROOT / "backend", env=env, capture_output=True, text=True, check=False)
        try:
            import_path = json.loads(listing.stdout)["ImportPath"] if listing.returncode == 0 else None
        except ValueError:
            import_path = None
        names = sorted({n for _, n in items})
        argv = ["go", "test", *ct.GO_TEST_FLAGS, *tag_args, "-json", "-run", "^(%s)$" % "|".join(names), pkg_dir]
        proc = subprocess.run(argv, cwd=ROOT / "backend", env=env, capture_output=True, text=True, check=False)
        passthrough(proc.stdout, "go| ")
        passthrough(proc.stderr, "go! ")
        seen = {}
        for line in proc.stdout.splitlines():
            try:
                ev = json.loads(line)
            except ValueError:
                continue
            if isinstance(ev, dict) and ev.get("Package") == import_path and ev.get("Action") in ("pass", "fail", "skip") \
                    and isinstance(ev.get("Test"), str) and "/" not in ev["Test"]:
                prev = seen.get(ev["Test"])
                seen[ev["Test"]] = ev["Action"] if prev in (None, "pass") else prev
        for ref, name in items:
            outcomes[ref] = seen.get(name, "missing") if import_path else "missing"
    return outcomes


class _Result(unittest.TestResult):
    def __init__(self):
        super().__init__()
        self.outcomes = {}

    def addSuccess(self, test):
        self.outcomes.setdefault(test.id(), "pass")

    def addFailure(self, test, err):
        super().addFailure(test, err)
        self.outcomes[test.id()] = "fail"

    def addError(self, test, err):
        super().addError(test, err)
        self.outcomes[test.id()] = "fail"

    def addSkip(self, test, reason):
        self.outcomes[test.id()] = "skip"

    def addExpectedFailure(self, test, err):
        self.outcomes[test.id()] = "fail"

    def addUnexpectedSuccess(self, test):
        self.outcomes[test.id()] = "fail"

    def addSubTest(self, test, subtest, err):
        if err is not None:
            super().addSubTest(test, subtest, err)
            self.outcomes[test.id()] = "fail"


def run_py(refs, root=ROOT):
    outcomes = {}
    sys.path.insert(0, str(root / "tests"))
    for ref in refs:
        _, path, dotted = ec.test_ref(ref)
        module_name = Path(path).stem
        result = _Result()
        error = None
        with fd_capture() as captured:
            try:
                spec = importlib.util.spec_from_file_location(module_name, root / path)
                module = importlib.util.module_from_spec(spec)
                sys.modules[module_name] = module
                spec.loader.exec_module(module)
                suite = unittest.defaultTestLoader.loadTestsFromName(dotted, module)
                suite.run(result)
            except Exception as exc:  # noqa: BLE001 - any import/lookup failure means the test did not run
                error = exc
        passthrough(captured())
        if error is not None:
            passthrough("evidence_runner: cannot load %s: %s" % (ref, error.__class__.__name__))
            outcomes[ref] = "missing"
            continue
        for _, trace in result.failures + result.errors:
            passthrough(trace)
        own = [v for k, v in result.outcomes.items() if k.endswith("." + dotted)]
        outcomes[ref] = "missing" if not own else ("pass" if all(v == "pass" for v in own) else
                                                  next(v for v in own if v != "pass"))
    return outcomes


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--tier")
    parser.add_argument("--gate")
    parser.add_argument("refs", nargs="*")
    args = parser.parse_args(argv)
    if bool(args.gate) == bool(args.tier) or (args.gate and args.refs) or (args.tier and not args.refs):
        parser.error("use --gate GATE, or --tier TIER -- REF...")
    emit({"evidence_env": environment(args.tier)})
    if args.gate:
        if not re.fullmatch(r"[a-z][a-z0-9-]*", args.gate):
            parser.error("bad gate name")
        proc = subprocess.run(["make", args.gate], cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                              text=True, errors="replace", check=False)
        passthrough(proc.stdout)
        rc = proc.returncode
        emit({"evidence_exit": rc})
        return rc
    parsed = [ec.test_ref(r) for r in args.refs]
    if any(p is None for p in parsed) or len({p[0] for p in parsed}) != 1:
        parser.error("refs must all be valid Go refs or all valid Python refs")
    outcomes = run_go(args.tier, args.refs) if parsed[0][0] == "go" else run_py(args.refs)
    for ref in sorted(outcomes):
        emit({"evidence_test": ref, "outcome": outcomes[ref]})
    rc = 0 if outcomes and all(v == "pass" for v in outcomes.values()) else 1
    emit({"evidence_exit": rc})
    return rc


if __name__ == "__main__":
    sys.exit(main())
