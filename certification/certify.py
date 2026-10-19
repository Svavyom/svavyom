#!/usr/bin/env python3
"""Svavyom certification run (stdlib only; M4-E02-S01, M4-E01-S03). DEVELOPMENT AND RELEASE TOOL: it is not part of any release artifact and the
product never runs or mentions it (tools/make_release.py refuses to package this directory).

It turns the hand-run qualification scripts in tools/ into one repeatable run on a real host and one tamper-evident record:

    run      run the qualification suites in order against an installed system, one log and one result file per suite
    collect  bind the results of a run to the release artifact under test and the host facts, and write the certification record
    sign     sign the record (Ed25519 with OpenSSL: the same key type ci/sign uses)
    verify   check a record: its signature, every evidence file's digest, and (with --artifact) the artifact it names
    matrix   render certification/MATRIX.md from the regression matrix and the records

Nothing here prints or records a password, a key or a cookie: the suites take paths, and only digests of their logs go into the record.
Exit 0 on success (run: when every suite passed), 1 on a failed check, 2 on a usage error.
"""
import argparse
import base64
import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
HERE = Path(__file__).resolve().parent
RUN_ID = re.compile(r"^qr-[0-9]{8}-[0-9a-f]{6}$")
SUITE_SCRIPTS = {
    "preflight": "tools/qualify_preflight.py", "install": "tools/qualify_install.py", "create": "tools/qualify_create.py",
    "lifecycle": "tools/qualify_lifecycle.py", "console": "tools/qualify_console.py", "storage": "tools/qualify_storage.py", "network": "tools/qualify_network.py",
}
SCHEMA = 1


def sha256_file(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def load_matrix(path=None):
    return json.loads(Path(path or HERE / "matrix.json").read_text())


def suite_argv(suite, a):
    """The command line of one suite, or None when the run was not given what the suite needs (the suite is then NOT_RUN, never silently passed)."""
    py = sys.executable
    script = str(ROOT / SUITE_SCRIPTS[suite])
    need = {
        "preflight": [a.config],
        "install": [a.base, a.password_file, a.pubkey, a.ssh_key, a.image],
        "create": [a.config, a.pubkey, a.image, a.ssh_key],
        "lifecycle": [a.config, a.ssh_key],
        "console": [],
        "storage": [a.config, a.pubkey, a.image, a.ssh_key],
        "network": [a.config, a.pubkey, a.image, a.ssh_key],
    }[suite]
    if not all(need):
        return None
    out = str(Path(a.out))
    if suite == "preflight":
        return [py, script, "--config", a.config, "--json", str(Path(a.out) / f"{a.run_id}-preflight.json")]
    if suite == "install":
        return [py, script, "--base", a.base, "--password-file", a.password_file, "--pubkey", a.pubkey, "--ssh-key", a.ssh_key, "--image", a.image, "--run-id", a.run_id, "--out", out]
    common = ["--run-id", a.run_id, "--out", out, "--repo", str(ROOT)]
    if suite == "console":
        return [py, script] + common
    return [py, script, "--config", a.config, "--pubkey", a.pubkey, "--image", a.image, "--ssh-key", a.ssh_key] + common if suite != "lifecycle" \
        else [py, script, "--config", a.config, "--ssh-key", a.ssh_key] + common


def cmd_run(a):
    if not RUN_ID.match(a.run_id):
        print("ERROR run id must look like qr-YYYYMMDD-xxxxxx", file=sys.stderr)
        return 2
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    wanted = [s for s in (a.suites.split(",") if a.suites else load_matrix()["suites"]) if s]
    bad = [s for s in wanted if s not in SUITE_SCRIPTS]
    if bad:
        print("ERROR unknown suite", bad, file=sys.stderr)
        return 2
    failed = False
    for s in wanted:
        argv = suite_argv(s, a)
        res = {"suite": s, "status": "NOT_RUN", "exit": None, "seconds": 0, "log": f"{a.run_id}-{s}.log"}
        if argv is None:
            print(f"NOT_RUN  {s} (missing arguments)")
        elif a.dry_run:
            print("PLAN    ", s, "->", os.path.basename(argv[1]))
        else:
            t0 = time.time()
            with open(out / res["log"], "wb") as log:
                r = subprocess.run(argv, stdout=log, stderr=subprocess.STDOUT, cwd=ROOT, check=False)
            res.update(exit=r.returncode, status="PASS" if r.returncode == 0 else "FAIL", seconds=int(time.time() - t0))
            print(f"{res['status']:8} {s} ({res['seconds']}s)")
            failed = failed or r.returncode != 0
        if not a.dry_run:
            (out / f"{a.run_id}-{s}.result.json").write_text(json.dumps(res, indent=2) + "\n")
    return 1 if failed else 0


def host_facts(os_release="/etc/os-release"):
    kv = {}
    try:
        for line in Path(os_release).read_text().splitlines():
            if "=" in line and not line.startswith("#"):
                k, v = line.split("=", 1)
                kv[k] = v.strip().strip("\"'")
    except OSError:
        pass

    def first_line(cmd):
        try:
            return subprocess.run(cmd, capture_output=True, text=True, timeout=10).stdout.strip().splitlines()[0]
        except (OSError, IndexError, subprocess.SubprocessError):
            return ""
    return {"os_id": kv.get("ID", ""), "version_id": kv.get("VERSION_ID", ""), "pretty": kv.get("PRETTY_NAME", "")[:80], "kernel": platform.release(), "arch": platform.machine(),
            "libvirt": first_line(["virsh", "--version"]), "qemu": first_line(["qemu-system-x86_64", "--version"])[:80]}


def artifact_facts(art):
    art = Path(art)
    m = json.loads((art / "MANIFEST.json").read_text())
    return {"version": m["version"], "built_from": m["built_from"], "manifest_sha256": sha256_file(art / "MANIFEST.json"),
            "sha256sums_sha256": sha256_file(art / "SHA256SUMS"), "signed": (art.parent / "signed").is_dir()}


def tool_digest():
    h = hashlib.sha256()
    for rel in sorted(SUITE_SCRIPTS.values()) + ["certification/certify.py", "certification/matrix.json"]:
        h.update(rel.encode() + b"\0" + (ROOT / rel).read_bytes() + b"\0")
    return h.hexdigest()


def cmd_collect(a):
    out = Path(a.out)
    results = []
    suites = load_matrix()["suites"]
    for s in suites:
        p = out / f"{a.run_id}-{s}.result.json"
        r = json.loads(p.read_text()) if p.is_file() else {"suite": s, "status": "NOT_RUN", "exit": None, "seconds": 0, "log": ""}
        files = []
        for name in sorted(os.listdir(out)):
            if name.startswith(f"{a.run_id}-{s}") and (out / name).is_file():
                files.append({"name": name, "sha256": sha256_file(out / name)})
        results.append({"suite": s, "status": r["status"], "exit": r["exit"], "seconds": r["seconds"], "files": files})
    verdict = "PASS" if all(r["status"] == "PASS" for r in results) else "FAIL" if any(r["status"] == "FAIL" for r in results) else "INCOMPLETE"
    rec = {"schema": SCHEMA, "run_id": a.run_id, "collected_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "artifact": artifact_facts(a.artifact),
           "host": host_facts(a.os_release), "tools_sha256": tool_digest(), "suites": results, "verdict": verdict}
    dest = Path(a.records)
    dest.mkdir(parents=True, exist_ok=True)
    p = dest / f"{a.run_id}.json"
    if p.exists():
        print("ERROR a record for this run already exists; a record is never overwritten", file=sys.stderr)
        return 2
    p.write_text(json.dumps(rec, indent=2) + "\n")
    print(f"record {p} verdict {verdict}")
    return 0


def openssl(*args, data=None):
    r = subprocess.run(["openssl", *args], input=data, capture_output=True, check=False)
    return r.returncode, r.stdout


def cmd_sign(a):
    p = Path(a.record)
    env = dict(os.environ)
    code, sig = openssl("pkeyutl", "-sign", "-rawin", "-inkey", a.key, "-in", str(p), *(["-passin", "env:CERT_KEY_PASS"] if env.get("CERT_KEY_PASS") else []))
    if code != 0:
        print("ERROR could not sign (is the key an Ed25519 key?)", file=sys.stderr)
        return 1
    Path(str(p) + ".sig").write_text(base64.b64encode(sig).decode() + "\n")
    print("signed", p)
    return 0


def check_record(rec, evidence=None, artifact=None):
    """Return a list of problems with a parsed record (empty when it holds together)."""
    bad = []
    if rec.get("schema") != SCHEMA or not RUN_ID.match(str(rec.get("run_id", ""))):
        bad.append("malformed record")
        return bad
    if rec.get("verdict") not in ("PASS", "FAIL", "INCOMPLETE"):
        bad.append("unknown verdict")
    expect = "PASS" if all(s["status"] == "PASS" for s in rec["suites"]) else "FAIL" if any(s["status"] == "FAIL" for s in rec["suites"]) else "INCOMPLETE"
    if rec["verdict"] != expect:
        bad.append("the verdict does not follow from the suites")
    names = [s["suite"] for s in rec["suites"]]
    if names != load_matrix()["suites"]:
        bad.append("the suites are not the required ones in the required order")
    if evidence:
        for s in rec["suites"]:
            for f in s["files"]:
                p = Path(evidence) / f["name"]
                if not p.is_file() or sha256_file(p) != f["sha256"]:
                    bad.append(f"evidence file {f['name']} is missing or changed")
    if artifact:
        now = artifact_facts(artifact)
        for k in ("version", "built_from", "manifest_sha256", "sha256sums_sha256"):
            if now[k] != rec["artifact"][k]:
                bad.append(f"the artifact differs from the one certified ({k})")
    return bad


def cmd_verify(a):
    p = Path(a.record)
    rec = json.loads(p.read_text())
    problems = check_record(rec, a.evidence, a.artifact)
    sigp = Path(str(p) + ".sig")
    if a.pubkey:
        if not sigp.is_file():
            problems.append("no signature")
        else:
            with tempfile.TemporaryDirectory() as d:
                raw = Path(d) / "sig"
                raw.write_bytes(base64.b64decode(sigp.read_text().strip()))
                code, _ = openssl("pkeyutl", "-verify", "-rawin", "-pubin", "-inkey", a.pubkey, "-in", str(p), "-sigfile", str(raw))
                if code != 0:
                    problems.append("the signature does not match the record under this key")
    for x in problems:
        print("FAIL", x)
    if not problems:
        print(f"OK record {rec['run_id']} verdict {rec['verdict']}" + (" (signature valid)" if a.pubkey else " (unsigned check)"))
    return 1 if problems else 0


def cmd_matrix(a):
    m = load_matrix(a.matrix)
    recs = []
    for p in sorted(Path(a.records).glob("*.json")):
        try:
            r = json.loads(p.read_text())
        except ValueError:
            continue
        if not check_record(r):
            r["_signed"] = Path(str(p) + ".sig").is_file()
            recs.append(r)
    lines = ["# Certification matrix", "", "Generated by `certification/certify.py matrix`. A development and release document: it is not shipped.", "",
             "| System | Expected | Last PASS record | Signed | Version certified |", "|---|---|---|---|---|"]
    for row in m["rows"]:
        hit = [r for r in recs if r["host"]["os_id"] == row["os_id"] and r["host"]["version_id"] == row["version_id"] and r["verdict"] == "PASS"]
        hit.sort(key=lambda r: r["collected_at"])
        last = hit[-1] if hit else None
        lines.append(f"| {row['id']} | {row['expect']} | {last['run_id'] if last else 'none'} | {('yes' if last['_signed'] else 'no') if last else '-'} | {last['artifact']['version'] if last else '-'} |")
    lines += ["", "A row is certified only by a PASS record made on a real host of that system. 'refused' rows are evidenced by the preflight verdict, which must be FAIL with OS_UNSUPPORTED."]
    Path(a.out).write_text("\n".join(lines) + "\n")
    print("wrote", a.out)
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run")
    r.add_argument("--run-id", required=True)
    r.add_argument("--out", required=True)
    r.add_argument("--suites", default="")
    r.add_argument("--dry-run", action="store_true")
    for n in ("config", "base", "password-file", "pubkey", "ssh-key", "image"):
        r.add_argument("--" + n, default="")
    c = sub.add_parser("collect")
    c.add_argument("--run-id", required=True)
    c.add_argument("--out", required=True)
    c.add_argument("--artifact", required=True)
    c.add_argument("--records", default=str(HERE / "records"))
    c.add_argument("--os-release", default="/etc/os-release")
    s = sub.add_parser("sign")
    s.add_argument("record")
    s.add_argument("--key", required=True)
    v = sub.add_parser("verify")
    v.add_argument("record")
    v.add_argument("--pubkey", default="")
    v.add_argument("--evidence", default="")
    v.add_argument("--artifact", default="")
    mx = sub.add_parser("matrix")
    mx.add_argument("--records", default=str(HERE / "records"))
    mx.add_argument("--matrix", default=str(HERE / "matrix.json"))
    mx.add_argument("--out", default=str(HERE / "MATRIX.md"))
    a = ap.parse_args(argv)
    return {"run": cmd_run, "collect": cmd_collect, "sign": cmd_sign, "verify": cmd_verify, "matrix": cmd_matrix}[a.cmd](a)


if __name__ == "__main__":
    sys.exit(main())
