#!/usr/bin/env python3
"""GitHub Actions workflow policy check (story M0-E02-S02, AC03).

Parsing uses PyYAML (pinned with hashes in toolchain/requirements-ci-policy.txt),
not a hand-written parser. Fail-closed layers:

1. Raw text: printable ASCII, LF and CRLF only (no Unicode whitespace or
   control characters that a parser and a reviewer could read differently);
   no tabs; bounded size.
2. Event scan: no anchors, aliases, explicit tags or multiple documents.
3. Strict loader (BaseLoader: every scalar is a string, so `on`, `yes` and
   `true` stay text): mapping keys must be plain scalars, `<<` merge keys are
   rejected, and keys duplicated case-insensitively are rejected.
4. Policy on the parsed tree.

Exit codes: 0 compliant, 1 violations, 2 usage error.
"""
import argparse
import re
import sys
from pathlib import Path

import yaml

SHA_RE = re.compile(r"[0-9a-f]{40}")
PIN_ROW_RE = re.compile(r"^\|\s*`?([A-Za-z0-9_.-]+/[A-Za-z0-9_./-]+)`?\s*\|\s*`?([0-9a-f]{40})`?\s*\|")
TEXT_RE = re.compile(r"(?:[\x20-\x7e]|\r?\n)*")
TIMEOUT_RE = re.compile(r"[1-9][0-9]{0,3}")
SECRETS_RE = re.compile(r"\bsecrets\b|\bgithub\s*\.\s*token\b", re.I)
# Canonical action reference: owner/repo[/path]@<40-hex>; no empty, "." or ".." segments.
USES_RE = re.compile(r"([A-Za-z0-9_-][A-Za-z0-9_.-]*)/([A-Za-z0-9_-][A-Za-z0-9_.-]*)((?:/[A-Za-z0-9_.-]+)*)@([0-9a-f]{40})")
# Keys the policy reads; a case variant of one is rejected rather than ignored (review N21).
POLICY_KEYS = {"on", "permissions", "jobs", "steps", "uses", "with", "run", "timeout-minutes",
               "persist-credentials", "secrets", "env"}
MAX_DEPTH = 64
FORBIDDEN_TRIGGERS = {"pull_request_target", "workflow_run"}
MAX_BYTES = 1024 * 1024


class PolicyError(Exception):
    pass


class StrictLoader(yaml.BaseLoader):
    """BaseLoader that rejects complex, merge and case-insensitively duplicated keys."""

    def construct_mapping(self, node, deep=False):
        seen = set()
        for key_node, _ in node.value:
            if not isinstance(key_node, yaml.ScalarNode):
                raise PolicyError("line %d: complex mapping keys are not allowed" % (key_node.start_mark.line + 1))
            key = key_node.value
            if key in ("", "~") or key.casefold() == "null":
                raise PolicyError("line %d: empty or null mapping keys are not allowed" % (key_node.start_mark.line + 1))
            if key == "<<":
                raise PolicyError("line %d: merge keys are not allowed" % (key_node.start_mark.line + 1))
            folded = key.casefold()
            if folded in POLICY_KEYS and key != folded:
                raise PolicyError("line %d: key %s must be written in lower case" % (key_node.start_mark.line + 1, key))
            if folded in seen:
                raise PolicyError("line %d: duplicate key %s (keys are compared case-insensitively)"
                                  % (key_node.start_mark.line + 1, key))
            seen.add(folded)
        return super().construct_mapping(node, deep=True)


def parse(text):
    """Return the parsed workflow tree or raise PolicyError."""
    if len(text.encode("utf-8")) > MAX_BYTES:
        raise PolicyError("workflow exceeds %d bytes" % MAX_BYTES)
    if "\t" in text:
        raise PolicyError("tab characters are not allowed")
    allowed = TEXT_RE.match(text).end()
    if allowed != len(text):
        raise PolicyError("only printable ASCII with LF or CRLF line endings is allowed (found U+%04X at offset %d)"
                          % (ord(text[allowed]), allowed))
    try:
        documents = depth = 0
        for event in yaml.parse(text, Loader=StrictLoader):
            if isinstance(event, yaml.DocumentStartEvent):
                documents += 1
                if documents > 1:
                    raise PolicyError("multi-document YAML is not allowed")
                if event.version or event.tags:
                    raise PolicyError("YAML directives (%YAML, %TAG) are not allowed")
            if isinstance(event, (yaml.MappingStartEvent, yaml.SequenceStartEvent)):
                depth += 1
                if depth > MAX_DEPTH:
                    raise PolicyError("nesting deeper than %d levels is not allowed" % MAX_DEPTH)
            elif isinstance(event, (yaml.MappingEndEvent, yaml.SequenceEndEvent)):
                depth -= 1
            if isinstance(event, yaml.AliasEvent) or getattr(event, "anchor", None):
                raise PolicyError("line %d: anchors and aliases are not allowed" % (event.start_mark.line + 1))
            if getattr(event, "tag", None) is not None:
                raise PolicyError("line %d: explicit tags are not allowed" % (event.start_mark.line + 1))
        return yaml.load(text, Loader=StrictLoader)
    except yaml.YAMLError as exc:
        raise PolicyError("invalid YAML: %s" % str(exc).splitlines()[0])
    except RecursionError:
        raise PolicyError("nesting too deep")


def load_pins(path):
    pins = set()
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        match = PIN_ROW_RE.match(line)
        if match:
            pins.add((match.group(1), match.group(2)))
    return pins


def strings(node):
    """Yield every key and scalar value in the tree."""
    if isinstance(node, dict):
        for key, value in node.items():
            yield key
            yield from strings(value)
    elif isinstance(node, list):
        for value in node:
            yield from strings(value)
    elif isinstance(node, str):
        yield node


def uses_refs(node, where="workflow"):
    """Yield (location, ref) for every `uses` key at any depth."""
    if isinstance(node, dict):
        for key, value in node.items():
            if key == "uses":
                yield where, value
            yield from uses_refs(value, "%s.%s" % (where, key))
    elif isinstance(node, list):
        for index, value in enumerate(node, 1):
            yield from uses_refs(value, "%s[%d]" % (where, index))


def parse_uses(ref):
    """Return (owner/repo, path, sha) for a canonical action reference, else None (review P1)."""
    match = USES_RE.fullmatch(ref) if isinstance(ref, str) else None
    if not match:
        return None
    path = match.group(3)
    if any(seg in (".", "..") for seg in path.split("/")[1:]):
        return None
    return "%s/%s" % (match.group(1), match.group(2)), path, match.group(4)


def check_uses(ref, where, pins):
    if not isinstance(ref, str) or ref.startswith(("docker://", "./")):
        return ["%s: only pinned remote actions are allowed: %s" % (where, ref)]
    if not SHA_RE.fullmatch(ref.rpartition("@")[2]):
        return ["%s: action not pinned to a full commit SHA: %s" % (where, ref)]
    parsed = parse_uses(ref)
    if parsed is None:
        return ["%s: action reference is not in canonical owner/repo[/path]@sha form: %s" % (where, ref)]
    repo, _, sha = parsed
    if (repo, sha) not in pins:
        return ["%s: %s@%s is not recorded in CI-PINS.md" % (where, repo, sha)]
    return []


def is_checkout(ref):
    parsed = parse_uses(ref)
    return parsed is not None and parsed[0].casefold() == "actions/checkout"


def triggers(on):
    if isinstance(on, str):
        return {on}
    if isinstance(on, list):
        return set(map(str, on))
    if isinstance(on, dict):
        return set(on)
    return set()


def check_tree(tree, pins):
    if not isinstance(tree, dict):
        return ["workflow must be a mapping"]
    findings = []
    if any(SECRETS_RE.search(s) for s in strings(tree)):
        findings.append("secrets references are forbidden")
    if "on" not in tree:
        findings.append("workflow must declare its triggers under the key 'on'")
    for trigger in sorted(t for t in triggers(tree.get("on")) if t.casefold() in FORBIDDEN_TRIGGERS):
        findings.append("%s trigger is forbidden" % trigger)
    if tree.get("permissions") != {"contents": "read"}:
        findings.append("top-level permissions must be exactly 'contents: read'")
    for where, ref in uses_refs(tree):
        findings.extend(check_uses(ref, where, pins))
    jobs = tree.get("jobs")
    if not isinstance(jobs, dict) or not jobs:
        return findings + ["workflow must declare jobs as a mapping"]
    for job_name, job in jobs.items():
        where = "job %s" % job_name
        if not isinstance(job, dict):
            findings.append("%s must be a mapping" % where)
            continue
        timeout = job.get("timeout-minutes")
        if not isinstance(timeout, str) or not TIMEOUT_RE.fullmatch(timeout):
            findings.append("%s lacks a numeric timeout-minutes" % where)
        if "permissions" in job:
            perms = job["permissions"]
            if not isinstance(perms, dict) or not perms or any(v != "read" for v in perms.values()):
                findings.append("%s requests write or broad permissions" % where)
        steps = job.get("steps", [])
        if not isinstance(steps, list):
            findings.append("%s steps must be a sequence" % where)
            continue
        for index, step in enumerate(steps, 1):
            swhere = "%s step %d" % (where, index)
            if not isinstance(step, dict):
                findings.append("%s must be a mapping" % swhere)
                continue
            if is_checkout(step.get("uses")) or str(step.get("uses", "")).casefold().startswith("actions/checkout"):
                with_ = step.get("with") if isinstance(step.get("with"), dict) else {}
                if with_.get("persist-credentials") != "false":
                    findings.append("%s: checkout lacks with.persist-credentials: false" % swhere)
            if "${{" in str(step.get("run", "")):
                findings.append("%s: ${{ }} expressions in run: are forbidden; pass via env" % swhere)
    return findings


def check_workflow(path, pins):
    name = str(path)
    try:
        text = path.read_bytes().decode("utf-8")
    except UnicodeDecodeError:
        return [(name, "workflow is not valid UTF-8")]
    try:
        tree = parse(text)
    except PolicyError as exc:
        return [(name, str(exc))]
    return [(name, message) for message in check_tree(tree, pins)]


def main(argv=None):
    parser = argparse.ArgumentParser(description="Check GitHub Actions workflow policy (M0-E02-S02 AC03).")
    parser.add_argument("--pins", required=True, help="CI-PINS.md file listing verified action SHAs")
    parser.add_argument("paths", nargs="+", help="workflow files or directories")
    args = parser.parse_args(argv)
    try:
        pins = load_pins(args.pins)
    except OSError as exc:
        print("ERROR cannot read pins file: %s" % exc.strerror)
        return 2
    files = []
    for p in map(Path, args.paths):
        files.extend(sorted(p.glob("*.y*ml")) if p.is_dir() else [p])
    if not files:
        print("ERROR no workflow files found")
        return 1
    findings = []
    for f in files:
        findings.extend(check_workflow(f, pins))
    for path, message in findings:
        print("ERROR %s: %s" % (path, message))
    if findings:
        return 1
    print("OK ci-policy: %d workflow(s) compliant" % len(files))
    return 0


if __name__ == "__main__":
    sys.exit(main())
