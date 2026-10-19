#!/usr/bin/env python3
"""Public / private boundary check (M0-S08): every tracked file is classified by release/boundary.json, nothing private is tracked, and no tracked
file contains a private-key block (outside the places that legitimately talk about or test for them). Read-only. Usage: check_boundary.py [ROOT]"""
import fnmatch
import json
import re
import subprocess
import sys
from pathlib import Path

sys.dont_write_bytecode = True


def glob(pattern, path):
    """'**' crosses directories, '*' does not."""
    rx = ""
    i = 0
    while i < len(pattern):
        if pattern.startswith("**/", i):
            rx += "(?:.*/)?"
            i += 3
        elif pattern.startswith("**", i):
            rx += ".*"
            i += 2
        elif pattern[i] == "*":
            rx += "[^/]*"
            i += 1
        elif pattern[i] == "?":
            rx += "[^/]"
            i += 1
        else:
            rx += re.escape(pattern[i])
            i += 1
    return re.fullmatch(rx, path) is not None


def matches(patterns, path):
    return any(glob(p, path) for p in patterns)


def tracked(root):
    p = subprocess.run(["git", "ls-files", "-z"], cwd=root, capture_output=True, check=False)  # noqa: S603,S607
    if p.returncode != 0:
        raise SystemExit("ERROR boundary: not a git repository")
    return [x for x in p.stdout.decode().split("\0") if x]


def check(root):
    root = Path(root)
    cfg = json.loads((root / "release" / "boundary.json").read_text())
    findings = []
    for rel in tracked(root):
        pub, internal = matches(cfg["public"], rel), matches(cfg["internal"], rel)
        if pub and internal:
            findings.append(("BOUNDARY_AMBIGUOUS", rel, "matches both a public and an internal rule"))
        elif not pub and not internal:
            findings.append(("BOUNDARY_UNCLASSIFIED", rel, "add it to 'public' or 'internal' in release/boundary.json"))
        if matches(cfg["private"], rel) and not matches(cfg["private_exceptions"], rel):
            findings.append(("PRIVATE_TRACKED", rel, "matches a private pattern and is tracked"))
        if matches(cfg["content_marker_exceptions"], rel):
            continue
        try:
            text = (root / rel).read_text(errors="ignore")
        except OSError:
            continue
        for label in cfg["content_markers"]:
            armor = "-----" + "BEGIN " + label + "-----"
            if armor in text:
                findings.append(("PRIVATE_KEY_IN_TREE", rel, "contains a %s armor line" % label))
    return findings


def main(argv=None):
    root = (argv or sys.argv[1:] or ["."])[0]
    findings = check(root)
    for code, where, why in findings:
        print("ERROR %s %s: %s" % (code, where, why))
    if findings:
        return 1
    print("OK boundary: every tracked file is classified; nothing private is tracked")
    return 0


if __name__ == "__main__":
    sys.exit(main())
