#!/usr/bin/env python3
"""Assemble the Development Preview release artifact (M4-S11). It builds nothing public and publishes nothing: the result is a directory on this host.

    python3 tools/make_release.py [--out release-out] [--skip-build]

1. Builds the Ubuntu 24.04 builder image (toolchain/release/Dockerfile) and the six binaries in it (the libvirt-linked ones must link the target's libvirt).
2. Builds the production web bundle in the no-network development container.
3. Assembles <out>/svavyom-<version>/ from TRACKED files only, with MANIFEST.json (every file: sha256, size, mode, audience public|private) and SHA256SUMS,
   then verifies the result with the built svavyom-ctl (verify-artifact).

Docker runs unprivileged: all capabilities dropped, no-new-privileges, read-only root, the checkout mounted read-only, and only the output directory writable.
No secret is read or written. Nothing here signs the artifact: signing keys are an operator decision (docs/OPERATIONS.md).
"""
import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
CLASSIFICATION = "Development Preview / Pre-Alpha"
LICENSE_CLASSIFICATION = "AGPL-3.0-or-later (server product); Apache-2.0 (contracts, tools, documentation); see LICENSING.md"
BUILDER = "dedicatedcloud-release-build:local"
DEV = "dedicatedcloud-dev:local"

# Tracked source files that go into the artifact, and who may see them.
PUBLIC_DIRS = ["packages/ubuntu"]
PUBLIC_DOCS = ["sbom/sbom.cdx.json", "sbom/licenses.json"]  # the rest of the documentation is a separate repository; the artifact carries the top-level documents and the bill of materials
PRIVATE_DOCS = []  # nothing in the artifact is private any more: the qualification records are public documents (host addresses and names are redacted in the public tree)
TOP = ["VERSION", "LICENSE", "NOTICE", "LICENSING.md", "SOURCE-OFFER.md", "THIRD-PARTY-NOTICES.md", "README.md", "INSTALLING.md", "USING.md", "BUILDING.md", "SECURITY.md", "CONTRIBUTING.md",
       "LICENSES/AGPL-3.0-or-later.txt", "LICENSES/Apache-2.0.txt"]


def sh(cmd, **kw):
    print("+", " ".join(str(c) for c in cmd), flush=True)
    subprocess.run(cmd, check=True, **kw)


def tracked(path: str) -> bool:
    r = subprocess.run(["git", "ls-files", "--error-unmatch", "--", path], cwd=ROOT, capture_output=True)
    return r.returncode == 0


def docker_run(image, out_dir, argv, network="none"):
    uid, gid = os.getuid(), os.getgid()
    cmd = ["docker", "run", "--rm", "-u", f"{uid}:{gid}", "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true", "--read-only",
           "--network", network, "--tmpfs", "/tmp:exec,mode=1777,size=4g",
           "-v", f"{ROOT}:/workspace/cloud-platform:ro", "-v", f"{ROOT}/.git:/workspace/cloud-platform/.git:ro",
           "-v", f"{out_dir}:/out", "-w", "/workspace/cloud-platform", image] + argv
    sh(cmd)


def sha256(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="release-out")
    ap.add_argument("--skip-build", action="store_true", help="reuse <out>/stage from a previous run")
    a = ap.parse_args()
    version = (ROOT / "VERSION").read_text().strip()
    out = (ROOT / a.out).resolve() if not os.path.isabs(a.out) else Path(a.out)
    stage, art = out / "stage", out / f"svavyom-{version}"
    if art.exists():
        sys.exit(f"ERROR {art} exists; refusing to overwrite a release directory (remove it deliberately)")
    dirty = subprocess.run(["git", "status", "--porcelain"], cwd=ROOT, capture_output=True, text=True).stdout.strip()
    head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True, text=True, check=True).stdout.strip()
    built_from = head + ("-dirty" if dirty else "")
    if not a.skip_build:
        shutil.rmtree(stage, ignore_errors=True)
        stage.mkdir(parents=True, mode=0o755)
        sh(["docker", "build", "-q", "-f", "toolchain/release/Dockerfile", "-t", BUILDER, "."], cwd=ROOT)
        docker_run(BUILDER, stage, ["sh", "toolchain/release/build-binaries.sh"])
        docker_run(DEV, stage, ["toolchain/run-in-copy.sh", "sh", "toolchain/release/build-web.sh"])
    for need in ("bin/svavyom-ctl", "web/index.html", "BUILD-LINKAGE.txt"):
        if not (stage / need).exists():
            sys.exit(f"ERROR the build stage lacks {need}")
    ver = json.loads(subprocess.run([str(stage / "bin/svavyom-ctl"), "version", "--json"], capture_output=True, text=True, check=True).stdout)
    if ver["version"] != version:
        sys.exit(f"ERROR the built svavyom-ctl reports {ver['version']}, VERSION says {version}")

    entries = {}  # artifact path -> (source path, audience)

    def add_file(rel, src, audience="public"):
        entries[rel] = (src, audience)

    for p in sorted((stage / "bin").iterdir()):
        add_file(f"bin/{p.name}", p)
    for p in sorted((stage / "web").rglob("*")):
        if p.is_file():
            add_file("web/" + p.relative_to(stage / "web").as_posix(), p)
    add_file("BUILD-LINKAGE.txt", stage / "BUILD-LINKAGE.txt")
    add_file("BUILDER-PACKAGES.txt", stage / "BUILDER-PACKAGES.txt")
    for d in PUBLIC_DIRS:
        for p in sorted((ROOT / d).rglob("*")):
            if p.is_file():
                rel = p.relative_to(ROOT).as_posix()
                if not tracked(rel):
                    sys.exit(f"ERROR {rel} is not tracked in git; the release uses tracked files only")
                add_file(rel, p)
    for name in PUBLIC_DOCS:
        add_file(f"docs/{name}", ROOT / "docs" / name)
    for name in PRIVATE_DOCS:
        if (ROOT / "docs" / name).exists():
            add_file(f"docs/{name}", ROOT / "docs" / name, "private")
    for name in TOP:
        add_file(name, ROOT / name)
    leaked = [rel for rel in entries if rel.split("/")[0] == "certification" or "certify" in rel]
    if leaked:
        sys.exit(f"ERROR the certification tooling is a development and release tool and never part of an artifact: {leaked[:3]}")
    for rel, (src, _) in entries.items():
        if not src.is_file():
            sys.exit(f"ERROR missing release input {src}")
        if not str(src).startswith(str(stage)) and not tracked(src.relative_to(ROOT).as_posix()):
            sys.exit(f"ERROR {src.relative_to(ROOT)} is not tracked in git; the release uses tracked files only")

    # Nothing private may be in an artifact: the strings named by the export rules (the owner's address, the lab's addresses and host names) are searched
    # for in every input, binaries included.
    oc = json.loads((ROOT / "release" / "open-core.json").read_text()).get("public_export", {})
    needles = [n.encode() for n in oc.get("must_not_contain", [])]
    for rel, (src, _) in entries.items():
        data = src.read_bytes()
        for n in needles:
            if n in data:
                sys.exit(f"ERROR {rel} contains a private string ({n.decode()!r}); fix the source, the artifact is built from tracked files as they are")

    files = []
    art.mkdir(parents=True, mode=0o755)
    for rel in sorted(entries):
        src, audience = entries[rel]
        dst = art / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(src, dst)
        mode = 0o755 if rel.startswith("bin/") or rel.endswith(".sh") else 0o644
        os.chmod(dst, mode)
        files.append({"path": rel, "sha256": sha256(dst), "size": dst.stat().st_size, "mode": mode, "audience": audience})
    # The SBOM attestation (M4-E02-S02): an in-toto style statement naming the shipped programs by digest and binding them to the SBOM and the licence
    # inventory. It is listed in the manifest, so SHA256SUMS and its signature cover it; `svavyom-ctl verify-artifact` checks it against the manifest.
    by_path = {f["path"]: f for f in files}
    for need in ("docs/sbom/sbom.cdx.json", "docs/sbom/licenses.json"):
        if need not in by_path:
            sys.exit(f"ERROR the release lacks {need}, which the attestation names")
    statement = {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [{"name": p, "digest": {"sha256": by_path[p]["sha256"]}} for p in sorted(by_path) if p.startswith("bin/")],
        "predicateType": "https://svavyom.invalid/attestation/sbom/v1",
        "predicate": {
            "version": version, "built_from": built_from,
            "sbom": {"path": "docs/sbom/sbom.cdx.json", "sha256": by_path["docs/sbom/sbom.cdx.json"]["sha256"]},
            "licenses": {"path": "docs/sbom/licenses.json", "sha256": by_path["docs/sbom/licenses.json"]["sha256"]},
            "note": "Statement made by tools/make_release.py on the build machine. It binds these programs to this SBOM; it is evidence only once SHA256SUMS is signed (docs/SIGNING-OPTIONS.md).",
        },
    }
    att = art / "ATTESTATION.json"
    att.write_text(json.dumps(statement, indent=2) + "\n")
    os.chmod(att, 0o644)
    files.append({"path": "ATTESTATION.json", "sha256": sha256(att), "size": att.stat().st_size, "mode": 0o644, "audience": "public"})
    files.sort(key=lambda f: f["path"])
    manifest = {"schema": 1, "product": "svavyom", "version": version, "classification": CLASSIFICATION, "license": LICENSE_CLASSIFICATION, "built_from": built_from,
                "schema_versions": ver["schema_versions"], "files": files}
    (art / "MANIFEST.json").write_text(json.dumps(manifest, indent=2) + "\n")
    sums = "".join(f"{f['sha256']}  {f['path']}\n" for f in files) + f"{sha256(art / 'MANIFEST.json')}  MANIFEST.json\n"
    (art / "SHA256SUMS").write_text(sums)
    for p in (art / "MANIFEST.json", art / "SHA256SUMS"):
        os.chmod(p, 0o644)
    r = subprocess.run([str(art / "bin/svavyom-ctl"), "verify-artifact", str(art)], capture_output=True, text=True)
    print(r.stdout.strip() or r.stderr.strip())
    if r.returncode != 0:
        sys.exit("ERROR the assembled artifact does not verify")
    pub = sum(1 for f in files if f["audience"] == "public")
    print(f"OK release artifact {art} ({len(files)} files: {pub} public, {len(files) - pub} private; built from {built_from}); nothing was published or signed")


if __name__ == "__main__":
    main()
