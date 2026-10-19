#!/usr/bin/env python3
"""Verify the running toolchain matches toolchain/versions.env (story M0-E02-S02 AC01).

Go tool versions are read from embedded Go build info (`go version -m`), which
records the go.sum-verified module version, not from self-reported strings.
Exit 0 when every version matches, 1 on any mismatch or missing tool.
"""
import re
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
# Pins verified at image build time (digest-pinned FROM lines), not at runtime.
BUILD_TIME_KEYS = {"GO_IMAGE", "NODE_IMAGE", "PYTHON_IMAGE", "GIT_MIN_VERSION"}
GO_TOOLS = {
    "STATICCHECK_MODULE_VERSION": ("staticcheck", "honnef.co/go/tools"),
    "GOSEC_VERSION": ("gosec", "github.com/securego/gosec/v2"),
    "GOVULNCHECK_VERSION": ("govulncheck", "golang.org/x/vuln"),
    "GITLEAKS_VERSION": ("gitleaks", "github.com/zricethezav/gitleaks/v8"),
}


def pinned():
    values = {}
    for line in (ROOT / "toolchain/versions.env").read_text().splitlines():
        if line.strip() and not line.startswith("#"):
            key, _, value = line.partition("=")
            values[key.strip()] = value.strip()
    return values


def run(*cmd):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=60, check=True).stdout
    except (OSError, subprocess.SubprocessError):
        return ""


def module_version(tool, module):
    path = shutil.which(tool)
    if not path:
        return ""
    for line in run("go", "version", "-m", path).splitlines():
        parts = line.split()
        if len(parts) >= 3 and parts[0] in ("mod", "path") and parts[1] == module and parts[2].startswith("v"):
            return parts[2].lstrip("v")
    return ""


def pyyaml_version():
    try:
        from importlib.metadata import version
        return version("PyYAML")
    except Exception:
        return ""


def actual():
    found = {
        "GO_VERSION": re.sub(r"^go version go(\S+).*", r"\1", run("go", "version").strip()),
        "NODE_VERSION": run("node", "--version").strip().lstrip("v"),
        "NPM_VERSION": run("npm", "--version").strip(),
        "PYTHON_VERSION": sys.version.split()[0],
        "PYYAML_VERSION": pyyaml_version(),
        "STATICCHECK_VERSION": run("staticcheck", "-version").split(" ")[1:2][0].strip() if run("staticcheck", "-version") else "",
    }
    for key, (tool, module) in GO_TOOLS.items():
        if module:
            found[key] = module_version(tool, module)
    return found


def git_meets_minimum(minimum):
    match = re.match(r"git version (\d+)\.(\d+)", run("git", "--version"))
    need = tuple(int(x) for x in minimum.split("."))
    return bool(match) and (int(match.group(1)), int(match.group(2))) >= need, match.group(0) if match else ""


def main():
    want, have = pinned(), actual()
    failures = 0
    for key in sorted(set(want) - set(have) - BUILD_TIME_KEYS):
        failures += 1
        print("FAIL %-20s pinned=%-10s actual=<not verified: unknown key>" % (key, want[key]))
    ok, found = git_meets_minimum(want.get("GIT_MIN_VERSION", "99.0"))
    failures += not ok
    print("%-4s %-20s minimum=%-9s actual=%s" % ("OK" if ok else "FAIL", "GIT_VERSION", want.get("GIT_MIN_VERSION"), found or "<missing>"))
    for key in sorted(have):
        ok = have[key] == want.get(key)
        failures += not ok
        print("%-4s %-20s pinned=%-10s actual=%s" % ("OK" if ok else "FAIL", key, want.get(key), have[key] or "<missing>"))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
