#!/usr/bin/env python3
"""Compile every Python file under the given directories in memory (story M0-E02-S02).

Replaces `python3 -m compileall`, which writes .pyc files, so the gate works
on a read-only checkout. Exit 0 when all files compile, 1 otherwise.
"""
import sys
from pathlib import Path


def main(argv):
    failures = 0
    for directory in argv or ["."]:
        for path in sorted(Path(directory).rglob("*.py")):
            try:
                compile(path.read_bytes(), str(path), "exec", dont_inherit=True)
            except SyntaxError as exc:
                failures += 1
                print("SyntaxError: %s:%s: %s" % (path, exc.lineno, exc.msg))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
