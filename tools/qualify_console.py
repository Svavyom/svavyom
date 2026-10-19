#!/usr/bin/env python3
"""Real-host serial-console qualification (canonical entry: `make docker-qualify-libvirt-console`).

Continues a run whose create stage left the run's VM Running. One Go stage in a container with NO network (so SSH is impossible: the
console is reached by construction without it), mounting only the libvirt sockets and one output directory. It stops the VM gracefully
and starts it again while the production console broker follows it, reads the boot output through the API, drives an interactive serial
session through ticket -> WebSocket -> broker -> libvirt, proves the ticket negatives (replay, expiry, another VM, tampered), reconnects
with a fresh ticket, and proves a clean disconnect and that signing out closes an open console. See docs/QUALIFICATION-CONSOLE.md.

Criteria are PASS / FAIL / NOT_RUN; the verdict is PASS only if every required criterion is PASS. Missing prerequisites are NOT_RUN
(exit 0), never PASS. Nothing is deleted; the VM is left Running for the lifecycle stage / cleanup.
"""
import argparse
import json
import os
import subprocess
import sys

sys.dont_write_bytecode = True
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import qualify_create as qc  # noqa: E402

PASS, FAIL, NOT_RUN = qc.PASS, qc.FAIL, qc.NOT_RUN
REQUIRED = ["console-serial-device", "console-broker", "serial-boot-output", "console-interactive", "ticket-replay-refused", "ticket-expiry-refused",
            "ticket-wrong-vm-refused", "ticket-tampered-refused", "console-reconnect", "console-disconnect-clean", "console-session-end", "console-vm-unchanged",
            "console-audit-clean"]


def go_argv(a, gid, out_dir):
    return ["docker", "run", "--rm", "-u", "%d:%d" % (os.getuid(), os.getgid()), "--group-add", str(gid), "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges:true", "--read-only", "--network", "none", "--tmpfs", "/tmp:exec,mode=1777,size=2g",
            "-v", "%s:/workspace/cloud-platform:ro" % a.repo, "-v", "%s:%s" % (qc.LIBVIRT_RW_SOCK, qc.LIBVIRT_RW_SOCK),
            "-v", "%s:%s" % (qc.LIBVIRT_RO_SOCK, qc.LIBVIRT_RO_SOCK), "-v", "%s:/qualify/out" % out_dir,
            "-e", "SVAVYOM_QUALIFY_CREATE=1", "-e", "SVAVYOM_QUALIFY_STAGE=console", "-e", "SVAVYOM_QUALIFY_RUN_ID=" + a.run_id, "-e", "SVAVYOM_QUALIFY_OUT=/qualify/out",
            "-e", "GOMODCACHE=/opt/go-mod-cache", "-e", "GOPROXY=off", "-e", "HOME=/tmp", "-e", "GOCACHE=/tmp/go-cache",
            "-w", "/workspace/cloud-platform/backend", qc.DEV_IMAGE, "go", "test", "-tags", qc.GO_TAGS, "-count=1", "-v", "-timeout", "20m", "-run",
            "TestSystemConsoleQualification", "./internal/console/qualify/"]


def verdict(criteria):
    status = {}
    for cid, st, _ in criteria:
        status[cid] = FAIL if (st == FAIL or status.get(cid) == FAIL) else st
    if any(st == FAIL for st in status.values()):
        return FAIL
    return PASS if all(status.get(c) == PASS for c in REQUIRED) else NOT_RUN


def render(run_id, criteria, result):
    lines = ["Svavyom serial console qualification  run %s" % run_id]
    seen = set()
    for cid, st, detail in criteria:
        seen.add(cid)
        lines.append("  %-7s %-30s %s" % (st, cid, detail))
    failed = any(st == FAIL for _, st, _ in criteria)
    for cid in REQUIRED:
        if cid not in seen:
            lines.append("  %-7s %-30s %s" % (NOT_RUN, cid, "not run (blocked by an earlier FAIL)" if failed else "not run"))
    lines.append("RESULT: %s" % result)
    return "\n".join(lines)


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--run-id", default=os.environ.get("QUALIFY_RUN_ID", ""))
    ap.add_argument("--out", default=os.environ.get("QUALIFY_OUT", "qualification-out"))
    ap.add_argument("--repo", default=os.getcwd())
    a = ap.parse_args(argv)
    miss = [n for n, ok in (("libvirt read-write socket", os.path.exists(qc.LIBVIRT_RW_SOCK)), ("libvirt read-only socket", os.path.exists(qc.LIBVIRT_RO_SOCK)),
                            ("/dev/kvm", os.path.exists("/dev/kvm")), ("QUALIFY_RUN_ID", bool(a.run_id))) if not ok]
    if miss:
        print("NOT_RUN: missing prerequisites: %s (see docs/QUALIFICATION-CONSOLE.md); real-KVM console qualification pending" % ", ".join(miss))
        return 0
    if not qc.RUN_ID_RE.match(a.run_id):
        print("ERROR run id must look like qr-YYYYMMDD-xxxxxx", file=sys.stderr)
        return 2
    a.repo = os.path.abspath(a.repo)
    out_dir = os.path.abspath(os.path.join(a.out, a.run_id))
    if not os.path.isdir(out_dir):
        print("ERROR no output directory for this run: run the create stage first", file=sys.stderr)
        return 2
    rc = subprocess.run(go_argv(a, qc.sock_gid(qc.LIBVIRT_RW_SOCK), out_dir), check=False).returncode  # noqa: S603
    try:
        res = json.load(open(os.path.join(out_dir, "console-result.json")))
        criteria = [(c["id"], c["status"], c.get("detail", "")) for c in res.get("criteria", []) if c.get("id")]
    except (OSError, ValueError):
        criteria = [("console-broker", FAIL, "the container produced no result (exit %d)" % rc)]
    if rc != 0 and not any(st == FAIL for _, st, _ in criteria):
        criteria.append(("qualification-stage", FAIL, "Go qualification stage exited %d" % rc))
    result = verdict(criteria)
    text = render(a.run_id, criteria, result)
    if not qc.scrub_check(text):
        print("ERROR the report contains private key material; refusing to write it", file=sys.stderr)
        return 2
    print(text)
    for name, body in (("report-console.txt", text + "\n"), ("report-console.json", json.dumps({"run_id": a.run_id, "stage": "console", "result": result,
                       "criteria": [{"id": c, "status": s, "detail": d} for c, s, d in criteria]}, indent=2) + "\n")):
        with open(os.path.join(out_dir, name), "w") as f:
            f.write(body)
    return 0 if result in (PASS, NOT_RUN) else 1


if __name__ == "__main__":
    sys.exit(main())
