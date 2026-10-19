#!/usr/bin/env python3
"""Generate the Software Bill of Materials and the licence inventory (M0-S05).

Outputs (committed; `make licenses` fails when they differ from the generator's output or a licence is unknown/unapproved):
  docs/sbom/sbom.cdx.json        CycloneDX 1.5 JSON: shipped Go modules (what the shipped binaries link), the frontend lockfile packages
                                 (production or development scope) and the host libraries the libvirt-linked binaries load dynamically
  docs/sbom/licenses.json        per component: licence (SPDX id), how it was determined, approval status
  THIRD-PARTY-NOTICES.md         attribution for every shipped component (notice texts are the licence files shipped with each module)

Run inside the pinned dev image (needs the Go module cache and `go`): `python3 tools/gen_sbom.py [--write]`. Default mode compares and
writes nothing (exit 1 on drift, 2 on a usage/environment error). The top-level Svavyom licence (AGPL-3.0-or-later, LICENSE) is not a dependency licence;
here: the root component carries the product licence (LICENSE, LICENSING.md).
"""
import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
SBOM = "docs/sbom/sbom.cdx.json"
LICENSES = "docs/sbom/licenses.json"
NOTICES = "THIRD-PARTY-NOTICES.md"
POLICY = "docs/sbom/license-policy.json"
TAGS = "libvirt"

# Matching is by distinctive phrases of the licence TEXT, never by a file name; anything not recognised is "UNKNOWN" and fails the gate.
SIGNATURES = [
    ("Apache-2.0", [r"Apache License", r"Version 2\.0"]),
    ("MPL-2.0", [r"Mozilla Public License Version 2\.0"]),
    ("LGPL-2.1-or-later", [r"GNU LESSER GENERAL PUBLIC LICENSE", r"Version 2\.1"]),
    ("BSD-3-Clause", [r"Redistribution and use in source and binary forms", r"[Nn]either the name"]),
    ("BSD-2-Clause", [r"Redistribution and use in source and binary forms"]),
    ("ISC", [r"Permission to use, copy, modify, and(/or)? distribute this software for any purpose with or without fee"]),
    ("MIT", [r"Permission is hereby granted, free of charge, to any person obtaining a copy"]),
    ("Unlicense", [r"This is free and unencumbered software released into the public domain"]),
    ("0BSD", [r"Permission to use, copy, modify, and/or distribute this software for any purpose with or without fee is hereby granted\."]),
]
LICENSE_FILES = ("LICENSE", "LICENSE.md", "LICENSE.txt", "LICENCE", "COPYING", "COPYING.md", "COPYING.txt", "UNLICENSE")


def run(argv, cwd):
    p = subprocess.run(argv, cwd=cwd, capture_output=True, text=True, check=False)  # noqa: S603
    if p.returncode != 0:
        raise SystemExit("ERROR %s failed: %s" % (" ".join(argv[:3]), p.stderr.strip()[:300]))
    return p.stdout


def detect(text):
    flat = re.sub(r"\s+", " ", text)
    for spdx, pats in SIGNATURES:
        if all(re.search(p, flat) for p in pats):
            return spdx
    return "UNKNOWN"


def go_components():
    backend = ROOT / "backend"
    mods = {}
    for tags in ("", TAGS):
        argv = ["go", "list"] + (["-tags", tags] if tags else []) + ["-deps", "-json=ImportPath,Module", "./..."]
        for chunk in re.findall(r"\{.*?\n\}", run(argv, backend), re.S):
            m = (json.loads(chunk) or {}).get("Module")
            if m and not m.get("Main"):
                mods[m["Path"]] = m
    out = []
    for path in sorted(mods):
        m = mods[path]
        d = m.get("Dir") or ""
        lic, src, text = "UNKNOWN", "no licence file found", ""
        for name in LICENSE_FILES:
            f = Path(d) / name
            if d and f.is_file():
                text = f.read_text(errors="replace")
                lic, src = detect(text), name
                break
        out.append({"ecosystem": "golang", "name": path, "version": m["Version"], "scope": "required", "license": lic, "determined_by": src,
                    "license_text_sha256": hashlib.sha256(text.encode()).hexdigest() if text else "",
                    "purl": "pkg:golang/%s@%s" % (path, m["Version"]), "_text": text})
    return out


def npm_components():
    lock = json.loads((ROOT / "frontend" / "package-lock.json").read_text())
    out = []
    for key, v in sorted(lock["packages"].items()):
        if not key:
            continue
        name = key.split("node_modules/")[-1]
        lic = v.get("license") or "UNKNOWN"
        if isinstance(lic, dict):
            lic = lic.get("type", "UNKNOWN")
        out.append({"ecosystem": "npm", "name": name, "version": v.get("version", ""), "scope": "optional" if v.get("dev") else "required", "license": lic,
                    "determined_by": "package-lock.json licence field", "integrity": v.get("integrity", ""),
                    "purl": "pkg:npm/%s@%s" % (name.replace("@", "%40", 1) if name.startswith("@") else name, v.get("version", "")), "_text": ""})
    return out


# Host libraries the libvirt-linked binaries (agent, mutation-helper, console-broker) load dynamically. Not vendored or redistributed by
# Svavyom: they are installed from the distribution (package prerequisites), so no notice text is shipped, but they are inventoried.
HOST_LIBS = [
    {"ecosystem": "deb", "name": "libvirt0", "version": "distribution", "scope": "required", "license": "LGPL-2.1-or-later", "determined_by": "libvirt project (dynamic linking through cgo)",
     "purl": "pkg:deb/ubuntu/libvirt0", "_text": ""},
    {"ecosystem": "deb", "name": "libvirt-daemon-system", "version": "distribution", "scope": "required", "license": "LGPL-2.1-or-later", "determined_by": "runtime prerequisite, not linked",
     "purl": "pkg:deb/ubuntu/libvirt-daemon-system", "_text": ""},
    {"ecosystem": "deb", "name": "qemu-system-x86", "version": "distribution", "scope": "required", "license": "GPL-2.0-only", "determined_by": "runtime prerequisite, run by libvirt, not linked",
     "purl": "pkg:deb/ubuntu/qemu-system-x86", "_text": ""},
]


def build():
    comps = go_components() + npm_components() + HOST_LIBS
    policy = json.loads((ROOT / POLICY).read_text())
    allowed = set(policy["approved"])
    exceptions = policy.get("exceptions", {})
    for c in comps:
        key = "%s:%s" % (c["ecosystem"], c["name"])
        c["status"] = "approved" if c["license"] in allowed else ("exception" if key in exceptions else "UNAPPROVED")
        if key in exceptions:
            c["exception"] = exceptions[key]
    return comps, policy


def sbom_doc(comps):
    root_version = (ROOT / "VERSION").read_text().strip() if (ROOT / "VERSION").is_file() else "0.0.0-unreleased"
    return {
        "bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
        "metadata": {"component": {"type": "application", "name": "svavyom", "version": root_version, "licenses": [{"license": {"id": "AGPL-3.0-or-later"}}],
                                   "description": "Svavyom Development Preview / Pre-Alpha (free software: AGPL-3.0-or-later for the server product; contracts, tools and documentation Apache-2.0; see LICENSING.md)"}},
        "components": [{"type": "library", "bom-ref": c["purl"], "name": c["name"], "version": c["version"], "scope": c["scope"], "purl": c["purl"],
                        "licenses": [{"license": {"id": c["license"]}}] if c["license"] not in ("UNKNOWN",) and re.fullmatch(r"[A-Za-z0-9.+-]+", c["license"]) else [{"license": {"name": c["license"]}}]}
                       for c in comps],
    }


def licenses_doc(comps):
    return {"schema": 1, "components": [{k: v for k, v in c.items() if not k.startswith("_") and k != "purl"} for c in comps]}


def notices_doc(comps):
    lines = ["# Third-party notices", "",
             "Svavyom Development Preview / Pre-Alpha. Svavyom itself is free software under AGPL-3.0-or-later (server product) and Apache-2.0 (contracts, tools, documentation) (`LICENSE`, `LICENSING.md`); the licences below govern only the third-party components and are not changed by it.",
             "This file lists the third-party components Svavyom's shipped binaries and web assets include, with the licence text each project ships.",
             "Generated by `tools/gen_sbom.py`; do not edit. Development-only tools (compilers, linters, test runners) are inventoried in `docs/sbom/licenses.json` but not listed here.", ""]
    for c in comps:
        if c["scope"] != "required" or c["ecosystem"] == "deb":
            continue
        lines.append("## %s %s — %s" % (c["name"], c["version"], c["license"]))
        if c["ecosystem"] == "golang":
            lines += ["", "```", c["_text"].strip() or "(no licence file found)", "```", ""]
        else:
            lines += ["", "Licence: %s (see the package's own LICENSE file in its npm distribution)." % c["license"], ""]
    lines += ["## System libraries (not redistributed)", "",
              "The libvirt-linked services (`agent`, `mutation-helper`, `console-broker`) load `libvirt0` (LGPL-2.1-or-later) dynamically from the distribution; QEMU (GPL-2.0-only) is run by libvirtd. Neither is bundled.", ""]
    return "\n".join(lines)


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--write", action="store_true")
    a = ap.parse_args(argv)
    comps, policy = build()
    outputs = {SBOM: json.dumps(sbom_doc(comps), indent=1, sort_keys=True) + "\n", LICENSES: json.dumps(licenses_doc(comps), indent=1, sort_keys=True) + "\n",
               NOTICES: notices_doc(comps)}
    bad = [c for c in comps if c["status"] == "UNAPPROVED"]
    for c in bad:
        print("ERROR LICENSE_UNAPPROVED %s %s %s: %s" % (c["ecosystem"], c["name"], c["version"], c["license"]))
    drift = []
    for rel, body in outputs.items():
        p = ROOT / rel
        if a.write:
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(body)
        elif not p.is_file() or p.read_text() != body:
            drift.append(rel)
    for rel in drift:
        print("ERROR SBOM_DRIFT %s differs from the generator's output (run tools/gen_sbom.py --write in the dev image)" % rel)
    if bad or drift:
        return 1
    print("OK licenses: %d components, every licence approved or explained; SBOM and notices are current" % len(comps))
    return 0


if __name__ == "__main__":
    sys.exit(main())
