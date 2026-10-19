#!/usr/bin/env python3
"""Read-only decision-dependency checker (story M0-E01-S03; DR-008 r3, review M1/N2).

Specification: cloud-product-docs/refinements/M0-E01-S03.md section 6.

contracts/decision-deps.json declares the docs-repo decisions (ADR/DR) that
cloud-platform relies on, each with the options it requires. This checker:
  - fails DECISION_DEP_UNDECLARED for any ADR-NNN / DR-NNN token in a tracked
    file that is not declared (files under tests/ are excluded: fixtures use
    unregistered example ids);
  - reads the docs decision register (decisions/index.json) at the docs
    commit pinned by docs-lock.json AND at the trusted docs tip
    (refs/heads/main), through tools/check_linkage.py's hardened git access;
  - fails DECISION_NOT_APPROVED_AT_TIP if a declared decision is not
    `approved` with the required options at either commit. Linkage does not
    enforce forward-only pins, so pinning an older docs commit cannot hide a
    later rejection or supersession.

What a pass means: the docs register records the decisions as approved. The
docs validator (validate_decisions.py) proves that each approval is traceable
to a recorded sponsor confirmation; neither tool proves the sponsor's
authenticity (DR-008 trust model).

Exit codes: 0 no findings, 1 findings, 2 usage or environment error.
Standard library only; writes nothing; never executes repository content.
"""
import argparse
import importlib.util
import json
import re
import sys
from pathlib import Path

sys.dont_write_bytecode = True

ROOT = Path(__file__).resolve().parents[1]
DEPS_FILE = "contracts/decision-deps.json"
INDEX_PATH = "decisions/index.json"
TRUSTED_REF = "refs/heads/main"
EXCLUDED_PREFIXES = ("tests/",)
TOKEN_RE = re.compile(r"(?<![A-Za-z0-9])(?:ADR|DR)-[0-9]{3}(?![0-9])")
ID_RE = re.compile(r"(?:ADR|DR)-[0-9]{3}")
OPT_KEY_RE = re.compile(r"[A-Za-z][A-Za-z0-9]{0,15}")
OPT_VAL_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9-]{0,31}")
MAX_DEPS_BYTES = 64 * 1024
MAX_INDEX_BYTES = 1 << 20
MAX_FILE_BYTES = 16 << 20


class EnvError(Exception):
    """Usage or environment failure; exit code 2."""


def load_linkage(root=ROOT):
    spec = importlib.util.spec_from_file_location("check_linkage", Path(root) / "tools" / "check_linkage.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_deps(raw):
    """Parse decision-deps.json bytes; return {id: {option: value}} or raise EnvError."""
    if len(raw) > MAX_DEPS_BYTES:
        raise EnvError("%s exceeds %d bytes" % (DEPS_FILE, MAX_DEPS_BYTES))
    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError):
        raise EnvError("%s is not valid UTF-8 JSON" % DEPS_FILE) from None
    if not isinstance(data, dict) or set(data) != {"schema", "decisions"} or data.get("schema") != 1 \
            or type(data["schema"]) is not int or not isinstance(data["decisions"], dict):
        raise EnvError("%s must be {schema: 1, decisions: {id: {option: value}}}" % DEPS_FILE)
    for rid, opts in data["decisions"].items():
        if not ID_RE.fullmatch(rid) or not isinstance(opts, dict) or not all(
                isinstance(k, str) and OPT_KEY_RE.fullmatch(k) and isinstance(v, str) and OPT_VAL_RE.fullmatch(v)
                for k, v in opts.items()):
            raise EnvError("%s: invalid entry %s" % (DEPS_FILE, rid[:40]))
    return data["decisions"]


def tracked_tokens(linkage, repo):
    """{token: sorted paths} for ADR/DR tokens in tracked files outside tests/."""
    listing = linkage.git(repo, "ls-files", "-z", "--cached", "--full-name")
    if listing is None:
        raise EnvError("cannot list tracked files")
    found = {}
    for name in listing.decode("utf-8", "replace").split("\0"):
        if not name or name.startswith(EXCLUDED_PREFIXES):
            continue
        path = Path(repo) / name
        if path.is_symlink() or not path.is_file():
            continue
        if path.stat().st_size > MAX_FILE_BYTES:
            raise EnvError("tracked file larger than %d bytes: %s" % (MAX_FILE_BYTES, linkage.echo(name)))
        text = path.read_bytes().decode("latin-1")
        for token in set(TOKEN_RE.findall(text)):
            found.setdefault(token, []).append(name)
    return {k: sorted(v) for k, v in found.items()}


def register_at(linkage, docs_repo, sha):
    """{id: record} from decisions/index.json at docs commit sha, or a problem string."""
    spec = "%s:%s" % (sha, INDEX_PATH)
    size = linkage.object_size(docs_repo, spec)
    if size is None:
        return "decision register %s missing" % INDEX_PATH
    if size > MAX_INDEX_BYTES:
        return "decision register larger than %d bytes" % MAX_INDEX_BYTES
    raw = linkage.git(docs_repo, "cat-file", "blob", spec)
    try:
        data = json.loads((raw or b"").decode("utf-8"))
        records = data["decisions"]
        out = {}
        for rec in records:
            rid = rec["id"]
            if not isinstance(rid, str) or rid in out:
                return "decision register malformed (duplicate or invalid id)"
            if not isinstance(rec["status"], str) or not isinstance(rec["options_chosen"], dict):
                return "decision register malformed (status/options_chosen)"
            out[rid] = rec
        return out
    except (UnicodeDecodeError, ValueError, TypeError, KeyError, RecursionError):
        return "decision register malformed"


def check(repo, docs_repo, deps_raw, lock_raw, trusted_ref=TRUSTED_REF):
    linkage = load_linkage()
    try:
        linkage.require_git_version()
        linkage.require_repo(docs_repo, "DOCS_REPO_UNAVAILABLE", "docs-repo")
        deps = load_deps(deps_raw)
        lock_findings, pinned = linkage.check_lock_bytes(lock_raw, "docs-lock.json")
        if lock_findings:
            raise EnvError("docs-lock.json invalid: %s" % lock_findings[0][2])
        docs = linkage.Docs(docs_repo, trusted_ref)
        if not docs.commit_exists(pinned) or not docs.is_trusted(pinned):
            raise EnvError("docs-lock.json does not pin a commit on trusted %s" % trusted_ref)
        tokens = tracked_tokens(linkage, repo)
    except linkage.EnvError as exc:
        raise EnvError("%s: %s" % (exc.code, exc.message)) from None
    findings = []
    for token, paths in sorted(tokens.items()):
        if token not in deps:
            shown = linkage.echo(", ".join(paths[:5]) + (" ..." if len(paths) > 5 else ""))
            findings.append(("DECISION_DEP_UNDECLARED", token, "referenced in %s but not declared in %s"
                             % (shown, DEPS_FILE)))
    commits = [("pinned", pinned), ("tip", docs.trusted_tip)]
    for label, sha in commits:
        register = register_at(linkage, docs_repo, sha)
        for rid, required in sorted(deps.items()):
            if isinstance(register, str):
                findings.append(("DECISION_NOT_APPROVED_AT_TIP", rid, "%s at %s docs commit %s" % (register, label, sha[:12])))
                continue
            rec = register.get(rid)
            if rec is None:
                problem = "not registered"
            elif rec["status"] != "approved":
                problem = "status %s" % linkage.echo(rec["status"])
            else:
                wrong = {k: v for k, v in required.items() if rec["options_chosen"].get(k) != v}
                problem = "required options %s not chosen (register has %s)" % (
                    json.dumps(wrong, sort_keys=True), linkage.echo(json.dumps(rec["options_chosen"], sort_keys=True))
                ) if wrong else None
            if problem:
                findings.append(("DECISION_NOT_APPROVED_AT_TIP", rid, "%s at %s docs commit %s" % (problem, label, sha[:12])))
    return findings


def main(argv=None):
    parser = argparse.ArgumentParser(description="Verify decision dependencies against the docs register (M0-E01-S03).")
    parser.add_argument("--docs-repo", required=True)
    parser.add_argument("--docs-ref", default=TRUSTED_REF, help="trusted docs ref (default refs/heads/main)")
    parser.add_argument("--repo", default=".")
    args = parser.parse_args(argv)
    try:
        deps_raw = (Path(args.repo) / DEPS_FILE).read_bytes()
        lock_raw = (Path(args.repo) / "docs-lock.json").read_bytes()
    except OSError as exc:
        print("ERROR USAGE decisions: cannot read %s: %s" % (exc.filename, exc.strerror))
        return 2
    try:
        findings = check(args.repo, args.docs_repo, deps_raw, lock_raw, args.docs_ref)
    except EnvError as exc:
        print("ERROR USAGE decisions: %s" % exc)
        return 2
    for code, subject, message in findings:
        print("ERROR %s %s: %s" % (code, subject, message))
    if findings:
        return 1
    print("OK decisions: %d declared decision dependencies approved at the pinned and trusted docs commits"
          % len(load_deps(deps_raw)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
