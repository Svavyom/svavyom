#!/usr/bin/env python3
"""Support-matrix access at the pinned docs commit (story M0-E02-S05; DR-007 D2 = A).

The canonical matrix is the docs repo's contracts/support-matrix.json, read at
the commit pinned by docs-lock.json through tools/check_linkage.py's hardened
git access. cloud-platform cannot widen it: --check verifies that the test
copy (tests/fixtures/distribution/support-matrix.json) is byte-identical.

  support_matrix.py --docs-repo DIR --check FILE    exit 0 identical, 1 differs
  support_matrix.py --docs-repo DIR --out FILE      write the pinned matrix (new file only)
Exit 2: usage or environment error.
"""
import argparse
import importlib.util
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MATRIX_PATH = "contracts/support-matrix.json"
MAX_BYTES = 1 << 20


class EnvError(Exception):
    pass


def pinned_matrix(docs_repo, root=ROOT):
    spec = importlib.util.spec_from_file_location("check_linkage", ROOT / "tools" / "check_linkage.py")
    linkage = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(linkage)
    try:
        linkage.require_git_version()
        linkage.require_repo(docs_repo, "DOCS_REPO_UNAVAILABLE", "docs-repo")
        findings, sha = linkage.check_lock_bytes((Path(root) / "docs-lock.json").read_bytes(), "docs-lock.json")
        docs = linkage.Docs(docs_repo)
        if findings or not docs.commit_exists(sha) or not docs.is_trusted(sha):
            raise EnvError("docs-lock.json does not pin a trusted docs commit")
        size = linkage.object_size(docs_repo, "%s:%s" % (sha, MATRIX_PATH))
        if size is None or size > MAX_BYTES:
            raise EnvError("%s missing or too large at %s" % (MATRIX_PATH, sha[:12]))
        data = linkage.git(docs_repo, "cat-file", "blob", "%s:%s" % (sha, MATRIX_PATH))
        if data is None:
            raise EnvError("cannot read %s at %s" % (MATRIX_PATH, sha[:12]))
        return data
    except linkage.EnvError as exc:
        raise EnvError("%s: %s" % (exc.code, exc.message)) from None
    except OSError as exc:
        raise EnvError("cannot read docs-lock.json: %s" % exc.strerror) from None


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--docs-repo", required=True)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--check")
    group.add_argument("--out")
    args = parser.parse_args(argv)
    try:
        data = pinned_matrix(args.docs_repo)
    except EnvError as exc:
        print("ERROR USAGE %s" % exc)
        return 2
    if args.check:
        try:
            local = Path(args.check).read_bytes()
        except OSError as exc:
            print("ERROR USAGE cannot read %s: %s" % (args.check, exc.strerror))
            return 2
        if local != data:
            print("ERROR MATRIX_DRIFT %s differs from the docs-repo matrix at the pinned commit" % args.check)
            return 1
        print("OK support-matrix: %s matches the pinned docs commit" % args.check)
        return 0
    try:
        fd = os.open(args.out, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
    except OSError as exc:
        print("ERROR USAGE cannot create %s: %s" % (args.out, exc.strerror))
        return 2
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)
    return 0


if __name__ == "__main__":
    sys.exit(main())
