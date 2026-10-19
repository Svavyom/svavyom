#!/usr/bin/env python3
"""Assemble what is published. Two outputs, both fresh repositories without history, rules in release/open-core.json ("public_export"):
  --out DIR       the CODE repository: the tracked files that are needed to build, test and run (the documentation directory is left out except the few
                  data files the build reads: the bill of materials and the action pins), lab addresses and names redacted, a final scan for private strings;
  --docs-out DIR  the DOCUMENTATION repository: docs/ minus the internal and process documents, with a README, LICENSE and NOTICE.
Read-only on the repository; writes the given directories. Usage: make_public_tree.py [--root .] [--out DIR] [--docs-out DIR]"""
import argparse
import json
import os
import shutil
import sys
from pathlib import Path

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from check_boundary import glob, matches, tracked  # noqa: E402

TEXT = (".md", ".txt", ".json", ".yaml", ".yml", ".go", ".ts", ".tsx", ".py", ".sh", ".toml", ".in", ".html", ".css", ".mod", ".env", ".conf", ".service", ".cfg", ".example", ".js", ".mjs")
NAMED_TEXT = ("LICENSE", "NOTICE", "Makefile", "VERSION", ".gitignore", ".dockerignore", ".gitleaksignore")


def is_text(rel, data):
    return (rel.endswith(TEXT) or rel in NAMED_TEXT) and b"\0" not in data


def redact(rel, data, red, needles, leaks):
    if not is_text(rel, data):
        return data
    text = data.decode("utf-8", "replace")
    for a, b in red:
        text = text.replace(a, b)
    for bad in needles:
        if bad in text:
            leaks.append((rel, bad))
    return text.encode()


def prepare(root, out):
    root, out = Path(root), Path(out)
    cfg = json.loads((root / "release" / "open-core.json").read_text())["public_export"]
    if out.exists() and any(out.iterdir()):
        raise SystemExit("ERROR %s exists and is not empty" % out)
    out.mkdir(parents=True, exist_ok=True)
    return root, out, cfg, sorted(cfg["redactions"].items(), key=lambda kv: -len(kv[0]))


def put(src, dst, rel, red, needles, leaks, data=None):
    dst.parent.mkdir(parents=True, exist_ok=True)
    data = src.read_bytes() if data is None else data
    dst.write_bytes(redact(rel, data, red, needles, leaks))
    if src.exists():
        shutil.copymode(src, dst)


def build_code(root, out):
    root, out, cfg, red = prepare(root, out)
    copied, leaks = 0, []
    for rel in tracked(root):
        if matches(cfg["exclude"], rel) and not matches(cfg.get("keep", []), rel):
            continue
        src = root / rel
        if src.is_symlink():  # test fixtures include symlinks on purpose: keep them as links
            dst = out / rel
            dst.parent.mkdir(parents=True, exist_ok=True)
            dst.symlink_to(os.readlink(src))
            copied += 1
            continue
        if not src.is_file():
            continue
        data = src.read_bytes()
        if rel == "release/open-core.json":  # the export rules themselves name the private strings and are not published
            doc = json.loads(data)
            doc.pop("public_export", None)
            data = (json.dumps(doc, indent=2) + "\n").encode()
        put(src, out / rel, rel, red, cfg["must_not_contain"], leaks, data)
        copied += 1
    return copied, leaks


def build_docs(root, out):
    root, out, cfg, red = prepare(root, out)
    dr = cfg["docs_repo"]
    copied, leaks = 0, []
    for rel in tracked(root):
        if not rel.startswith("docs/") or matches(["docs/review/**"], rel):
            continue
        sub = rel[len("docs/"):]
        if matches(dr["exclude"], sub):
            continue
        put(root / rel, out / sub, sub, red, cfg["must_not_contain"], leaks)
        copied += 1
    for name, text in (("README.md", dr["readme"]), ("NOTICE", dr["notice"])):
        put(root / "README.md", out / name, name, red, cfg["must_not_contain"], leaks, text.encode())
        copied += 1
    put(root / "LICENSES/Apache-2.0.txt", out / "LICENSE", "LICENSE", red, cfg["must_not_contain"], leaks)
    return copied + 1, leaks


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default=".")
    ap.add_argument("--out")
    ap.add_argument("--docs-out")
    a = ap.parse_args()
    if not a.out and not a.docs_out:
        ap.error("give --out and/or --docs-out")
    bad = False
    for label, fn, target in (("code", build_code, a.out), ("docs", build_docs, a.docs_out)):
        if not target:
            continue
        n, leaks = fn(a.root, target)
        for rel, s in leaks:
            print("ERROR PUBLIC_LEAK %s: %s contains %r" % (label, rel, s))
        bad = bad or bool(leaks)
        if not leaks:
            print("OK public %s tree: %d files written to %s; no private string left" % (label, n, target))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
