#!/usr/bin/env python3
"""Read-only traceability checker linking cloud-platform commits to an
immutable cloud-product-docs revision (story M0-E02-S01).

Specification: cloud-product-docs/refinements/M0-E02-S01.md

Exit codes: 0 no findings, 1 findings, 2 usage or environment error.
Standard library only. Never writes to either repository, never uses the
network and never passes untrusted text through a shell.
"""
import argparse
import json
import os
import re
import subprocess
import sys

SHA_RE = re.compile(r"[0-9a-f]{40}")
STORY_RE = re.compile(r"M[0-9]-E[0-9]{2}-S[0-9]{2}")
AC_RE = re.compile(r"M[0-9]-E[0-9]{2}-S[0-9]{2}-AC[0-9]{2}")
REV_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/~^-]{0,199}")
REF_RE = re.compile(r"refs/(?:heads|remotes|tags)/[A-Za-z0-9][A-Za-z0-9._/-]{0,199}")
TRAILER_LINE_RE = re.compile(r"([A-Za-z][A-Za-z0-9-]*):[ \t]?(.*)")

LOCK_FILE = "docs-lock.json"
BASELINES_FILE = "backlog/baselines.json"
PLATFORM_REPO_NAME = "cloud-platform"
LOCK_KEYS = {"schema", "docs_repo", "commit"}
DOCS_REPO_NAME = "cloud-product-docs"
LINKED_STATUSES = {"ready", "in-progress", "review"}
REQUIRED_TRAILERS = ("Story", "Docs-Commit", "Acceptance")

MAX_LOCK_BYTES = 4096
MAX_MESSAGE_BYTES = 65536
MAX_TRAILER_BYTES = 1024
MAX_BACKLOG_BYTES = 16 * 1024 * 1024
MAX_COMMIT_HEADER_BYTES = 16384
MAX_ECHO = 200
GIT_TIMEOUT_S = 30
ENV_PASSTHROUGH = ("PATH", "HOME", "SYSTEMROOT", "TMPDIR")
MIN_GIT = (2, 44)  # first release with --no-lazy-fetch / GIT_NO_LAZY_FETCH
# Command-line -c beats repository config, and per-protocol settings beat
# protocol.allow, so every transport is denied individually.
PROTOCOL_DENY = [arg for proto in ("ext", "file", "ssh", "git", "http", "https")
                 for arg in ("-c", "protocol.%s.allow=never" % proto)]


class EnvError(Exception):
    """Usage or environment failure; exit code 2."""

    def __init__(self, code, subject, message):
        super().__init__(message)
        self.code, self.subject, self.message = code, subject, message


def echo(value):
    """Render untrusted text safely: printable ASCII only, bounded length."""
    text = "".join(c if " " <= c <= "~" else "?" for c in str(value))
    return text if len(text) <= MAX_ECHO else text[: MAX_ECHO - 3] + "..."


def git(repo, *args):
    """Run git with an argument list (never a shell); return stdout bytes or None."""
    # Minimal environment: inherited GIT_* variables (GIT_DIR, GIT_OBJECT_DIRECTORY,
    # GIT_CONFIG_*, ...) could redirect queries to another repository.
    env = {k: os.environ[k] for k in ENV_PASSTHROUGH if k in os.environ}
    env.update(
        GIT_CONFIG_NOSYSTEM="1",
        GIT_CONFIG_GLOBAL=os.devnull,
        GIT_TERMINAL_PROMPT="0",
        GIT_OPTIONAL_LOCKS="0",
        GIT_NO_LAZY_FETCH="1",
        GIT_NO_REPLACE_OBJECTS="1",
        GIT_GRAFT_FILE=os.devnull,
        # Overrides every protocol.* config, including custom remote helpers (S01 review R4).
        GIT_ALLOW_PROTOCOL="none",
        GIT_PAGER="cat",
        LC_ALL="C",
    )
    cmd = ["git", "--no-lazy-fetch", "--no-replace-objects", "-C", repo, "-c", "core.fsmonitor=false",
           "-c", "protocol.allow=never", *PROTOCOL_DENY, "--no-pager", *args]
    try:
        proc = subprocess.run(
            cmd,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            timeout=GIT_TIMEOUT_S,
            check=False,
        )
    except subprocess.TimeoutExpired:
        raise EnvError("GIT_FAILED", "git", "timed out after %d s" % GIT_TIMEOUT_S)
    except OSError as exc:
        raise EnvError("GIT_FAILED", "git", "cannot execute git: %s" % exc.strerror)
    return proc.stdout if proc.returncode == 0 else None


def require_git_version():
    """Fail closed on git older than MIN_GIT, which ignores lazy-fetch guards."""
    out = git(".", "version") or b""
    match = re.match(rb"git version (\d+)\.(\d+)", out)
    if not match or (int(match.group(1)), int(match.group(2))) < MIN_GIT:
        raise EnvError("GIT_FAILED", "git", "git >= %d.%d required (found %s)"
                       % (MIN_GIT + (echo(out.decode("ascii", "replace").strip()) or "unknown",)))


def require_repo(path, code, label):
    """Require path to be the top level of a complete (non-shallow) git work tree."""
    top = git(path, "rev-parse", "--show-toplevel") if os.path.isdir(path) else None
    if top is None or os.path.realpath(top.decode("utf-8", "replace").rstrip("\n")) != os.path.realpath(path):
        raise EnvError(code, label, "not a git repository top level: %s" % echo(path))
    # Shallow boundaries hide history like grafts do (S01 review R1): refuse.
    if (git(path, "rev-parse", "--is-shallow-repository") or b"").strip() != b"false":
        raise EnvError("GIT_FAILED", label, "shallow or unreadable repository; full history required: %s" % echo(path))


def object_size(repo, spec):
    """Return the size in bytes of object spec, or None if it does not exist."""
    out = git(repo, "cat-file", "-s", spec)
    return int(out) if out is not None else None


class Docs:
    """Access to the docs repository strictly through objects at a pinned commit.

    Every pinned commit must also be an ancestor of (or equal to) the trusted
    docs ref, so dangling or unmerged docs commits cannot supply story status
    or baseline registrations (S01 review R3).
    """

    def __init__(self, repo, trusted_ref="refs/heads/main"):
        self.repo = repo
        if not REF_RE.fullmatch(trusted_ref) or ".." in trusted_ref:
            raise EnvError("DOCS_REPO_UNAVAILABLE", "docs-ref", "unsafe ref: %s" % echo(trusted_ref))
        tip = git(repo, "rev-parse", "--verify", "--quiet", "--end-of-options", trusted_ref + "^{commit}")
        if tip is None:
            raise EnvError("DOCS_REPO_UNAVAILABLE", "docs-ref", "trusted docs ref not found: %s" % echo(trusted_ref))
        self.trusted_ref = trusted_ref
        self.trusted_tip = tip.decode("ascii").strip()
        self._trusted = {}
        self._exists = {}
        self._backlog = {}
        self._baselines = {}

    def commit_exists(self, sha):
        if sha not in self._exists:
            out = git(self.repo, "cat-file", "-t", sha)
            self._exists[sha] = out is not None and out.strip() == b"commit"
        return self._exists[sha]

    def is_trusted(self, sha):
        if sha not in self._trusted:
            self._trusted[sha] = git(self.repo, "merge-base", "--is-ancestor", sha, self.trusted_tip) is not None
        return self._trusted[sha]

    def backlog(self, sha):
        """Return (stories{id: status}, acs{id: story_id}) or None when invalid."""
        if sha not in self._backlog:
            self._backlog[sha] = self._load(sha)
        return self._backlog[sha]

    def baselines(self, sha):
        """Return the registered cloud-platform baseline SHAs at docs commit sha.

        Missing registry -> empty set (nothing exempt); malformed -> None.
        """
        if sha not in self._baselines:
            self._baselines[sha] = self._load_baselines(sha)
        return self._baselines[sha]

    def _load_baselines(self, sha):
        spec = "%s:%s" % (sha, BASELINES_FILE)
        size = object_size(self.repo, spec)
        if size is None:
            return frozenset()
        if size > MAX_LOCK_BYTES:
            return None
        try:
            data = json.loads(git(self.repo, "cat-file", "blob", spec) or b"")
            listed = data["repos"][PLATFORM_REPO_NAME]
        except (ValueError, TypeError, KeyError, RecursionError):
            return None
        if (not isinstance(data, dict) or set(data) != {"schema", "repos"} or type(data["schema"]) is not int
                or data["schema"] != 1 or not isinstance(listed, list)
                or not all(isinstance(x, str) and SHA_RE.fullmatch(x) for x in listed)):
            return None
        return frozenset(listed)

    def _load(self, sha):
        blobs = []
        for name in ("backlog/stories.json", "backlog/acceptance.json"):
            spec = "%s:%s" % (sha, name)
            size = object_size(self.repo, spec)
            if size is None or size > MAX_BACKLOG_BYTES:
                return None
            blobs.append(git(self.repo, "cat-file", "blob", spec) or b"")
        try:
            stories, acs = (json.loads(b) for b in blobs)
            story_map = {s["id"]: s["status"] for s in stories}
            ac_map = {a["id"]: a["story_id"] for a in acs}
        except (ValueError, TypeError, KeyError, RecursionError):
            return None
        if not all(isinstance(v, str) for v in [*story_map, *story_map.values(), *ac_map, *ac_map.values()]):
            return None
        return story_map, ac_map


def check_lock_bytes(raw, subject):
    """Validate lock file content; return (findings, sha or None)."""
    if len(raw) > MAX_LOCK_BYTES:
        return [("INPUT_TOO_LARGE", subject, "lock file exceeds %d bytes" % MAX_LOCK_BYTES)], None
    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError):
        return [("LOCK_INVALID", subject, "not valid UTF-8 JSON")], None
    if not isinstance(data, dict) or set(data) != LOCK_KEYS:
        return [("LOCK_INVALID", subject, "keys must be exactly %s" % sorted(LOCK_KEYS))], None
    if type(data["schema"]) is not int or data["schema"] != 1:
        return [("LOCK_INVALID", subject, "schema must be 1")], None
    if data["docs_repo"] != DOCS_REPO_NAME:
        return [("LOCK_INVALID", subject, "docs_repo must be %s" % DOCS_REPO_NAME)], None
    sha = data["commit"]
    if not isinstance(sha, str) or not SHA_RE.fullmatch(sha):
        return [("SHA_INVALID", subject, "commit must be 40 lowercase hex characters: %s" % echo(sha))], None
    return [], sha


def check_docs_commit(docs, sha, subject):
    if not docs.commit_exists(sha):
        return [("DOCS_COMMIT_NOT_FOUND", subject, "docs commit object %s not found" % sha)]
    if not docs.is_trusted(sha):
        return [("DOCS_COMMIT_UNTRUSTED", subject, "docs commit %s is not on trusted %s" % (sha, docs.trusted_ref))]
    if docs.backlog(sha) is None:
        return [("BACKLOG_INVALID", subject, "backlog missing or malformed at %s" % sha)]
    return []


def parse_trailers(message):
    """Return {key: [values]} from the final paragraph if every line is a trailer."""
    paragraphs = [p for p in re.split(r"\n[ \t]*\n", message.strip("\n")) if p.strip()]
    if len(paragraphs) < 2:
        return {}
    trailers = {}
    for line in paragraphs[-1].split("\n"):
        match = TRAILER_LINE_RE.fullmatch(line.rstrip("\r"))
        if not match:
            return {}
        trailers.setdefault(match.group(1).lower(), []).append(match.group(2).strip())
    return trailers


def check_commit(platform, docs, sha, baselines=frozenset()):
    subject = sha[:12]
    size = object_size(platform, sha)
    if size is None:
        raise EnvError("GIT_FAILED", subject, "cannot read commit")
    if size > MAX_MESSAGE_BYTES + MAX_COMMIT_HEADER_BYTES:
        return [("INPUT_TOO_LARGE", subject, "commit object exceeds %d bytes" % (MAX_MESSAGE_BYTES + MAX_COMMIT_HEADER_BYTES))]
    raw = git(platform, "cat-file", "commit", sha)
    if raw is None:
        raise EnvError("GIT_FAILED", subject, "cannot read commit")
    header, _, body = raw.partition(b"\n\n")
    parents = [l for l in header.split(b"\n") if l.startswith(b"parent ")]
    if len(body) > MAX_MESSAGE_BYTES:
        return [("INPUT_TOO_LARGE", subject, "commit message exceeds %d bytes" % MAX_MESSAGE_BYTES)]
    message = body.decode("utf-8", errors="replace")
    # Exempt only established baselines: parentless, "Baseline:" subject AND the
    # exact SHA registered in the docs repo. Orphans introduced by a story
    # branch cannot match a registered SHA (decision D-01).
    if not parents and message.startswith("Baseline:") and sha in baselines:
        return []

    findings = []
    trailers = parse_trailers(message)
    values = {}
    for key in REQUIRED_TRAILERS:
        found = trailers.get(key.lower(), [])
        if len(found) > 1:
            findings.append(("TRAILER_DUPLICATE", subject, "%s trailer appears %d times" % (key, len(found))))
        elif not found or not found[0]:
            findings.append(("TRAILER_MISSING", subject, "missing %s trailer" % key))
        elif len(found[0].encode("utf-8")) > MAX_TRAILER_BYTES:
            findings.append(("INPUT_TOO_LARGE", subject, "%s trailer exceeds %d bytes" % (key, MAX_TRAILER_BYTES)))
        else:
            values[key] = found[0]

    story = values.get("Story")
    if story is not None and not STORY_RE.fullmatch(story):
        findings.append(("ID_INVALID", subject, "invalid story ID: %s" % echo(story)))
        story = None
    acs = []
    if "Acceptance" in values:
        for item in values["Acceptance"].split(","):
            item = item.strip()
            if AC_RE.fullmatch(item):
                acs.append(item)
            else:
                findings.append(("ID_INVALID", subject, "invalid acceptance ID: %s" % echo(item)))
    trailer_sha = values.get("Docs-Commit")
    if trailer_sha is not None and not SHA_RE.fullmatch(trailer_sha):
        findings.append(("SHA_INVALID", subject, "Docs-Commit must be 40 lowercase hex characters: %s" % echo(trailer_sha)))
        trailer_sha = None

    lock_spec = "%s:%s" % (sha, LOCK_FILE)
    lock_size = object_size(platform, lock_spec)
    if lock_size is None:
        findings.append(("LOCK_MISSING", subject, "%s absent from commit tree" % LOCK_FILE))
        return findings
    if lock_size > MAX_LOCK_BYTES:
        findings.append(("INPUT_TOO_LARGE", subject, "lock file exceeds %d bytes" % MAX_LOCK_BYTES))
        return findings
    lock_raw = git(platform, "cat-file", "blob", lock_spec)
    if lock_raw is None:
        findings.append(("LOCK_INVALID", subject, "%s is not a regular file" % LOCK_FILE))
        return findings
    lock_findings, lock_sha = check_lock_bytes(lock_raw, subject)
    findings.extend(lock_findings)
    if lock_sha is None:
        return findings
    if trailer_sha is not None and trailer_sha != lock_sha:
        findings.append(("DOCS_COMMIT_MISMATCH", subject, "Docs-Commit %s differs from lock %s" % (trailer_sha, lock_sha)))
    docs_findings = check_docs_commit(docs, lock_sha, subject)
    findings.extend(docs_findings)
    if docs_findings:
        return findings

    stories, ac_owner = docs.backlog(lock_sha)
    if story is not None:
        if story not in stories:
            findings.append(("STORY_UNKNOWN", subject, "story %s not in backlog" % story))
        elif stories[story] not in LINKED_STATUSES:
            findings.append(("STORY_NOT_READY", subject, "story %s has status %s" % (story, echo(stories[story]))))
    for ac in acs:
        if ac not in ac_owner:
            findings.append(("AC_UNKNOWN", subject, "acceptance criterion %s not in backlog" % ac))
        elif story is not None and ac_owner[ac] != story:
            findings.append(("AC_WRONG_STORY", subject, "%s belongs to %s, not %s" % (ac, echo(ac_owner[ac]), story)))
    return findings


def cmd_lock(args):
    require_repo(args.docs_repo, "DOCS_REPO_UNAVAILABLE", "docs-repo")
    path = args.lock
    if not os.path.isfile(path):
        return [("LOCK_MISSING", LOCK_FILE, "%s is missing or not a regular file" % echo(path))]
    try:
        with open(path, "rb") as handle:
            raw = handle.read(MAX_LOCK_BYTES + 1)
    except OSError as exc:
        return [("LOCK_MISSING", LOCK_FILE, "cannot read %s: %s" % (echo(path), exc.strerror))]
    findings, sha = check_lock_bytes(raw, LOCK_FILE)
    if sha is not None:
        findings.extend(check_docs_commit(Docs(args.docs_repo, args.docs_ref), sha, LOCK_FILE))
    return findings


def resolve_rev(repo, rev):
    if not REV_RE.fullmatch(rev) or ".." in rev:
        raise EnvError("RANGE_INVALID", "range", "unsafe revision: %s" % echo(rev))
    out = git(repo, "rev-parse", "--verify", "--quiet", "--end-of-options", rev + "^{commit}")
    if out is None:
        raise EnvError("RANGE_INVALID", "range", "cannot resolve revision: %s" % echo(rev))
    return out.decode("ascii").strip()


def cmd_commits(args):
    require_repo(args.docs_repo, "DOCS_REPO_UNAVAILABLE", "docs-repo")
    require_repo(args.repo, "GIT_FAILED", "repo")
    parts = args.range.split("..")
    if len(parts) != 2:
        raise EnvError("RANGE_INVALID", "range", "expected BASE..HEAD: %s" % echo(args.range))
    base, head = (resolve_rev(args.repo, p) for p in parts)
    listing = git(args.repo, "rev-list", "--reverse", "%s..%s" % (base, head))
    if listing is None:
        raise EnvError("GIT_FAILED", "range", "rev-list failed")
    docs = Docs(args.docs_repo, args.docs_ref)
    baselines, registry_findings = head_baselines(args.repo, docs, head)
    findings = []
    for sha in listing.decode("ascii").split():
        findings.extend(sorted(check_commit(args.repo, docs, sha, baselines), key=lambda f: (f[0], f[1], f[2])))
    # The registry belongs to the head commit, which is listed last.
    return findings + registry_findings


def head_baselines(platform, docs, head):
    """Baseline registry from the docs commit pinned by the range head's lock.

    Any problem with the head lock yields no exemptions (the head commit's own
    check reports the lock problem); a malformed registry is a finding.
    """
    spec = "%s:%s" % (head, LOCK_FILE)
    size = object_size(platform, spec)
    raw = git(platform, "cat-file", "blob", spec) if size is not None and size <= MAX_LOCK_BYTES else None
    if raw is None:
        return frozenset(), []
    lock_findings, lock_sha = check_lock_bytes(raw, head[:12])
    if lock_findings or not docs.commit_exists(lock_sha) or not docs.is_trusted(lock_sha):
        return frozenset(), []
    registry = docs.baselines(lock_sha)
    if registry is None:
        return frozenset(), [("BACKLOG_INVALID", head[:12], "%s malformed at %s" % (BASELINES_FILE, lock_sha))]
    return registry, []


def main(argv=None):
    parser = argparse.ArgumentParser(description="Verify docs/story linkage (M0-E02-S01).")
    sub = parser.add_subparsers(dest="command", required=True)
    lock = sub.add_parser("lock", help="validate docs-lock.json")
    lock.add_argument("--docs-repo", required=True)
    lock.add_argument("--docs-ref", default="refs/heads/main", help="trusted docs ref (default refs/heads/main)")
    lock.add_argument("--lock", default=LOCK_FILE)
    commits = sub.add_parser("commits", help="validate commit trailers in a range")
    commits.add_argument("--docs-repo", required=True)
    commits.add_argument("--docs-ref", default="refs/heads/main", help="trusted docs ref (default refs/heads/main)")
    commits.add_argument("--range", required=True)
    commits.add_argument("--repo", default=".")
    args = parser.parse_args(argv)

    try:
        require_git_version()
        findings = cmd_lock(args) if args.command == "lock" else cmd_commits(args)
    except EnvError as exc:
        print("ERROR %s %s: %s" % (exc.code, exc.subject, exc.message))
        return 2
    for code, subject, message in findings:
        print("ERROR %s %s: %s" % (code, subject, message))
    if findings:
        return 1
    print("OK %s: linkage verified" % args.command)
    return 0


if __name__ == "__main__":
    sys.exit(main())
