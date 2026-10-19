#!/usr/bin/env python3
"""Open-core boundary check. Every tracked file belongs to exactly one tier of release/open-core.json; no scanned source imports a premium package; no scanned
source contains a licence-key, entitlement, trial, host-limit or call-home token. Read-only. Usage: check_open_core.py [ROOT]"""
import json
import re
import subprocess
import sys
from pathlib import Path

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from check_boundary import glob, matches, tracked  # noqa: E402


def expected_reuse(cfg):
    """REUSE.toml (https://reuse.software) generated from the tier map: one aggregate annotation per licensed tier. Licence texts carry no annotation."""
    out = ["# Generated from release/open-core.json by tools/check_open_core.py --write; do not edit by hand.", "version = 1", ""]
    for tier, lic in cfg["tier_licence"].items():
        out += ["[[annotations]]", "path = [%s]" % ", ".join('"%s"' % p for p in cfg["tiers"][tier]), 'precedence = "aggregate"',
                'SPDX-FileCopyrightText = "%s"' % cfg["copyright"], 'SPDX-License-Identifier = "%s"' % lic, ""]
    return "\n".join(out)


def check(root):
    root = Path(root)
    cfg = json.loads((root / "release" / "open-core.json").read_text())
    out = []
    files = tracked(root)
    for rel in files:
        tiers = [t for t, pats in cfg["tiers"].items() if matches(pats, rel)]
        if not tiers:
            out.append(("OPEN_CORE_UNCLASSIFIED", rel, "add it to a tier in release/open-core.json"))
        elif len(tiers) > 1:
            out.append(("OPEN_CORE_AMBIGUOUS", rel, "matches more than one tier: " + ", ".join(tiers)))
    reuse = root / "REUSE.toml"
    if not reuse.is_file() or reuse.read_text() != expected_reuse(cfg):
        out.append(("OPEN_CORE_LICENCE_MAP", "REUSE.toml", "missing or different from the tier map: run tools/check_open_core.py --write"))
    tok = re.compile("|".join(re.escape(t) for t in cfg["forbidden_tokens"]), re.IGNORECASE)
    imp = [p.lower() for p in cfg["forbidden_import_prefixes"]]
    for rel in files:
        if not matches(cfg["scanned_source"], rel) or not (root / rel).is_file():
            continue
        try:
            text = (root / rel).read_text(errors="replace")
        except OSError:
            continue
        low = text.lower()
        for p in imp:
            if p in low:
                out.append(("OPEN_CORE_PREMIUM_IMPORT", rel, "refers to premium package %s" % p))
        if not matches(cfg["token_exceptions"], rel):
            m = tok.search(text)
            if m:
                out.append(("OPEN_CORE_GATING_TOKEN", rel, "contains %r: no licence, trial, entitlement or host-limit logic belongs in the open product" % m.group(0)))
    return out


def main(argv):
    if len(argv) > 1 and argv[1] == "--write":
        root = Path(argv[2] if len(argv) > 2 else ".")
        (root / "REUSE.toml").write_text(expected_reuse(json.loads((root / "release" / "open-core.json").read_text())))
        print("wrote REUSE.toml")
        return 0
    root = argv[1] if len(argv) > 1 else "."
    try:
        findings = check(root)
    except (OSError, ValueError, KeyError) as exc:
        print("ERROR open-core: %s" % exc)
        return 2
    for code, where, msg in findings:
        print("ERROR %s %s: %s" % (code, where, msg))
    if findings:
        return 1
    print("OK open-core: every file has one tier; no premium import and no licence, trial, entitlement or host-limit logic in the open code")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
