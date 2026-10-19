#!/usr/bin/env python3
"""Release-classification guard (M0-S09): Svavyom is a **Development Preview / Pre-Alpha**.

Fails (exit 1) when a tracked document, source string or UI string makes a claim the classification forbids -- "Stable", "production-ready",
"HA-ready", "enterprise-ready", high availability, general availability, "zero-risk" -- unless the same line denies it ("not production-ready",
"is excluded", "no HA", ...). Also fails when README.md or the release notes do not state the classification. Quoting a forbidden word to forbid it is
allowed in docs/LAUNCH-CLAIMS.md and this tool's tests. Read-only. Usage: python3 tools/check_claims.py [ROOT]
"""
import re
import subprocess
import sys
from pathlib import Path

sys.dont_write_bytecode = True
CLASSIFICATION = "Development Preview / Pre-Alpha"
MUST_STATE = ("README.md", "docs/RELEASE-NOTES-DEVELOPMENT-PREVIEW.md")  # the release notes live in the documentation repository in a public checkout: checked only when present
OPTIONAL = ("docs/RELEASE-NOTES-DEVELOPMENT-PREVIEW.md",)
FORBIDDEN = [
    ("PRODUCTION_READY", re.compile(r"\bproduction[- ]ready\b|\bproduction[- ]grade\b|\bready for production\b", re.I)),
    ("STABLE", re.compile(r"\bstable (release|version|build|product|platform)\b|\bis stable\b|\bgeneral availability\b|\bGA release\b", re.I)),
    ("HA", re.compile(r"\bHA[- ]ready\b|\bhigh[- ]availability\b|\bhighly available\b|\bfault[- ]tolerant cluster\b", re.I)),
    ("ENTERPRISE", re.compile(r"\benterprise[- ](ready|grade|class)\b", re.I)),
    ("ZERO_RISK", re.compile(r"\bzero[- ]risk\b|\bguaranteed (backup|recovery|uptime)\b|\bnever (lose|loses) data\b", re.I)),
    ("LIVE_MIGRATION", re.compile(r"\blive[- ]migration\b", re.I)),
    ("MULTI_HOST", re.compile(r"\bmulti[- ]host (scheduling|scheduler|cluster)\b|\bmulti[- ]hypervisor\b", re.I)),
]
DENIAL = re.compile(r"\b(not|no|never|without|isn't|aren't|is not|are not|nor|neither|excluded|exclude|excludes|out of scope|non[- ]goal|non[- ]feature|not a|do not|does not|must not|"
                    r"don't|doesn't|cannot|can't|prohibited|forbidden|overclaim|not supported|NOT_SUPPORTED|M5|M6|roadmap|post-launch|anti-goal|do not chase|not claim|claims? (that|of))\b", re.I)
SCANNED = (".md", ".ts", ".tsx", ".html", ".go", ".py", ".yaml", ".yml", ".json", ".in", ".example", ".txt", ".sh")
SKIP_PREFIXES = ("research/", "frontend/node_modules/", "docs/review/", "tests/", "frontend/e2e/", "frontend/src/api/fixtures", "frontend/package-lock.json", "THIRD-PARTY-NOTICES.md",
                 "docs/sbom/", "backend/go.sum", "prompts/")
SKIP_FILES = ("docs/LAUNCH-CLAIMS.md", "tools/check_claims.py")


def tracked(root):
    out = subprocess.run(["git", "ls-files", "-z"], cwd=root, capture_output=True, check=False)  # noqa: S603,S607
    if out.returncode == 0 and out.stdout:
        return [p for p in out.stdout.decode().split("\0") if p]
    return [str(p.relative_to(root)) for p in Path(root).rglob("*") if p.is_file() and ".git" not in p.parts and "node_modules" not in p.parts]


def scan(root):
    root = Path(root)
    findings = []
    for rel in tracked(root):
        if not rel.endswith(SCANNED) or rel.startswith(SKIP_PREFIXES) or rel in SKIP_FILES:
            continue
        try:
            text = (root / rel).read_text(errors="replace")
        except OSError:
            continue
        for n, line in enumerate(text.splitlines(), 1):
            for code, rx in FORBIDDEN:
                if rx.search(line) and not DENIAL.search(line):
                    findings.append((code, "%s:%d" % (rel, n), line.strip()[:140]))
    for rel in MUST_STATE:
        p = root / rel
        if not p.is_file() and rel in OPTIONAL:
            continue
        if not p.is_file() or CLASSIFICATION not in p.read_text(errors="replace"):
            findings.append(("CLASSIFICATION_MISSING", rel, "must state '%s'" % CLASSIFICATION))
    return findings


def main(argv=None):
    root = (argv or sys.argv[1:] or ["."])[0]
    findings = scan(root)
    for code, where, text in findings:
        print("ERROR %s %s: %s" % (code, where, text))
    if findings:
        return 1
    print("OK claims: no forbidden launch claim; the classification is '%s'" % CLASSIFICATION)
    return 0


if __name__ == "__main__":
    sys.exit(main())
