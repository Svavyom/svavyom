#!/usr/bin/env python3
"""Frontend source and bundle rules (story M0-E02-S06; DR-010 D4 = A, r5 sections 2, 6, 9).

Standard library, token scan (no JavaScript parser, no lint dependency).

  check_frontend.py --source DIR      design-system and client rules over *.ts/*.tsx (tests excluded)
  check_frontend.py --bundle DIR      production-bundle rules over a built dist/

Exit codes: 0 no findings, 1 findings, 2 usage error. Read-only.

Source findings:
  RAW_HTML            dangerouslySetInnerHTML / innerHTML / outerHTML / insertAdjacentHTML / document.write
  DYNAMIC_CODE        eval( / new Function( / setTimeout or setInterval with a string
  STRING_HANDLER      an on*="..." string event handler attribute
  POSITIVE_TABINDEX   tabIndex / tabindex greater than 0
  INLINE_STYLE        a style={...} or style="..." attribute (blocked by the CSP, and colour-only risk)
  BROWSER_STORAGE     localStorage / sessionStorage / indexedDB / document.cookie (credentials never stored)
  CONSOLE             console.* (server text and credential fields are never logged)
  DIRECT_FETCH        fetch( / XMLHttpRequest / WebSocket / EventSource outside src/api/client.ts
  ABSOLUTE_URL        an http(s):// URL literal in source
Bundle findings:
  CSP_MISSING         index.html lacks the Content-Security-Policy meta with default-src 'self'
  GALLERY_IN_BUNDLE   gallery/test-only markers or fixture code in the production bundle
  EXTERNAL_URL        an absolute URL in the bundle that is not on the documented never-fetched list
  SOURCE_MAP          a source map in the production bundle
"""
import argparse
import re
import sys
from pathlib import Path

sys.dont_write_bytecode = True

SOURCE_RULES = [
    ("RAW_HTML", re.compile(r"dangerouslySetInnerHTML|\.innerHTML\s*=|\.outerHTML\s*=|insertAdjacentHTML|document\.write\s*\(")),
    ("DYNAMIC_CODE", re.compile(r"\beval\s*\(|new\s+Function\s*\(|set(?:Timeout|Interval)\s*\(\s*[\"'`]")),
    ("STRING_HANDLER", re.compile(r"\bon[A-Z][A-Za-z]*\s*=\s*[\"']|\bon[a-z]+\s*=\s*\"[^\"{]")),
    ("POSITIVE_TABINDEX", re.compile(r"tab[iI]ndex\s*=\s*(?:\{\s*|[\"'])\s*(?:[1-9]\d*)")),
    ("INLINE_STYLE", re.compile(r"\bstyle\s*=\s*[{\"']")),
    ("BROWSER_STORAGE", re.compile(r"\b(?:localStorage|sessionStorage|indexedDB)\b|document\.cookie")),
    ("CONSOLE", re.compile(r"\bconsole\s*\.\s*[a-z]+\s*\(")),
    ("ABSOLUTE_URL", re.compile(r"[\"'`]https?://")),
]
NETWORK = re.compile(r"\bfetch\s*\(|\bXMLHttpRequest\b|\bnew\s+WebSocket\b|\bnew\s+EventSource\b|navigator\.sendBeacon")
CLIENT = "api/client.ts"
TEST_FILE = re.compile(r"\.(?:test|spec)\.tsx?$")

# URLs that React's production build contains as identifiers or error-documentation links. They are never
# requested (and the CSP default-src 'self' would block them). EXACT strings only (review N6); anything else,
# including longer URLs that start with one of these, is a finding.
NEVER_FETCHED = (
    "https://react.dev/errors/",
    "http://www.w3.org/1999/xhtml",
    "http://www.w3.org/2000/svg",
    "http://www.w3.org/1998/Math/MathML",
    "http://www.w3.org/1999/xlink",
    "http://www.w3.org/XML/1998/namespace",
)
BUNDLE_MARKERS = re.compile(r"__GALLERY_MARKER__|data-gallery-state|PROVISIONAL|provisional fixtures|test-only fixtures|journeys/|J7Delete|RENDERERS")
URL_IN_BUNDLE = re.compile(r"(?:https?|wss?)://[^\s\"'`)<>\\]*|[\"'`]//[A-Za-z0-9.-]+\.[A-Za-z]{2,}[^\s\"'`)<>\\]*")
CSP_RE = re.compile(r"<meta\s+http-equiv=\"Content-Security-Policy\"\s+content=\"[^\"]*default-src 'self'")


def strip_comments(text):
    """Remove // and /* */ comments, keeping string and template literals intact (review N6: a "//" inside a
    string must not hide the rest of the line). Newlines are preserved so line numbers stay correct."""
    out, i, n = [], 0, len(text)
    while i < n:
        c = text[i]
        if c in "\"'`":
            j = i + 1
            while j < n and text[j] != c:
                j += 2 if text[j] == "\\" else 1
            out.append(text[i:j + 1])
            i = j + 1
        elif text.startswith("//", i):
            j = text.find("\n", i)
            i = n if j < 0 else j
        elif text.startswith("/*", i):
            j = text.find("*/", i + 2)
            j = n if j < 0 else j + 2
            out.append("\n" * text.count("\n", i, j))
            i = j
        else:
            out.append(c)
            i += 1
    return "".join(out)


def check_source(root):
    root = Path(root)
    findings = []
    files = sorted(p for p in root.rglob("*") if p.suffix in (".ts", ".tsx") and not TEST_FILE.search(p.name)
                   and p.name != "vite-env.d.ts")
    if not files:
        return [("USAGE", str(root), "no source files found")]
    for path in files:
        rel = path.relative_to(root).as_posix()
        lines = strip_comments(path.read_text(encoding="utf-8")).split("\n")
        for n, line in enumerate(lines, 1):
            for code, rx in SOURCE_RULES:
                if rx.search(line):
                    findings.append((code, "%s:%d" % (rel, n), line.strip()[:120]))
            if NETWORK.search(line) and rel != CLIENT:
                findings.append(("DIRECT_FETCH", "%s:%d" % (rel, n), line.strip()[:120]))
    return findings


def check_bundle(root):
    root = Path(root)
    index = root / "index.html"
    if not index.is_file():
        return [("USAGE", str(root), "index.html missing; build the production bundle first")]
    findings = []
    if not CSP_RE.search(index.read_text(encoding="utf-8")):
        findings.append(("CSP_MISSING", "index.html", "Content-Security-Policy meta with default-src 'self' is required"))
    for path in sorted(p for p in root.rglob("*") if p.is_file()):
        rel = path.relative_to(root).as_posix()
        if rel.endswith(".map"):
            findings.append(("SOURCE_MAP", rel, "source maps are not shipped"))
            continue
        if path.name == "gallery.html":
            findings.append(("GALLERY_IN_BUNDLE", rel, "the gallery entry is test-only"))
        text = path.read_text(encoding="utf-8", errors="replace")
        m = BUNDLE_MARKERS.search(text)
        if m:
            findings.append(("GALLERY_IN_BUNDLE", rel, "test-only marker %r" % m.group(0)))
        for url in sorted(set(URL_IN_BUNDLE.findall(text))):
            if url.lstrip("\"'`") not in NEVER_FETCHED:
                findings.append(("EXTERNAL_URL", rel, url[:120]))
    return findings


def main(argv=None):
    ap = argparse.ArgumentParser(description="Frontend source and bundle rules (M0-E02-S06).")
    ap.add_argument("--source")
    ap.add_argument("--bundle")
    a = ap.parse_args(argv)
    if not a.source and not a.bundle:
        ap.error("give --source DIR and/or --bundle DIR")
    findings = []
    for flag, fn in ((a.source, check_source), (a.bundle, check_bundle)):
        if flag:
            if not Path(flag).is_dir():
                print("ERROR USAGE %s is not a directory" % flag)
                return 2
            findings += fn(flag)
    if any(f[0] == "USAGE" for f in findings):
        for f in findings:
            print("ERROR %s %s: %s" % f)
        return 2
    for code, where, what in findings:
        print("ERROR %s %s: %s" % (code, where, what))
    if findings:
        return 1
    print("OK frontend: %s" % " and ".join(x for x in ("source rules" if a.source else "", "bundle rules" if a.bundle else "") if x))
    return 0


if __name__ == "__main__":
    sys.exit(main())
