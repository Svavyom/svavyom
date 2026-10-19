#!/usr/bin/env python3
"""Real-host VM lifecycle qualification orchestrator (canonical entry: `make docker-qualify-libvirt-lifecycle`).

It continues a run whose create stage left the run's VM Running (docs/QUALIFICATION-LIBVIRT-CREATE.md), and walks it through the
M1-E lifecycle on the real qemu:///system, one Go step per container (no capabilities, no network, read-only root) with the guest-side
checks on the HOST over SSH using the same disposable private key as the create stage (only its PATH is used):

  baseline -> [ssh: boot id, write marker] -> reboot -> [ssh: new boot id] -> delete refused while Running -> stop -> start
  -> [ssh: marker survived the graceful stop] -> force off -> delete interrupted after the seed volume (unknown outcome)
  -> delete resumed to completion -> VM, root and seed gone, base image unchanged, every other libvirt object unchanged.

Every criterion is PASS / FAIL / NOT_RUN; the verdict is PASS only if all required criteria PASS. Missing prerequisites are NOT_RUN
(exit 0), never PASS. The report is console output for the qualification record, not an evidence-format record. Destructive steps act
only on the run's own, provably Svavyom-owned VM (identity derived from the run id by the Go stage); a failed step stops the walk and
leaves whatever remains for `docker-qualify-libvirt-cleanup`, which has its own ownership proof.
"""
import argparse
import json
import os
import subprocess
import sys
import time

sys.dont_write_bytecode = True
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import qualify_create as qc  # noqa: E402

PASS, FAIL, NOT_RUN = qc.PASS, qc.FAIL, qc.NOT_RUN
STEPS = ["baseline", "reboot", "delete-refused-running", "stop", "start", "force-off", "delete-crash", "delete-resume"]
REQUIRED = [
    "lifecycle-precondition", "inventory-baseline", "lifecycle-reboot", "guest-reboot-observed", "delete-refused-while-running",
    "lifecycle-stop", "lifecycle-start", "guest-data-survived-stop", "lifecycle-force-off", "delete-interrupted", "lifecycle-delete",
    "delete-idempotent", "unrelated-resources-unchanged", "image-immutable-after",
]
MARKER = "/var/tmp/svavyom-lifecycle-marker"
BOOT_ID = "cat /proc/sys/kernel/random/boot_id"


def go_argv(step, a, catalog_dir, gid, out_dir, pool_dir):
    """The Go stage of one step. Same confinement as the create stage; the RO socket is mounted because the step reads state through
    the read-only adapter exactly as the product does."""
    run = ["docker", "run", "--rm", "-u", "%d:%d" % (os.getuid(), os.getgid()), "--group-add", str(gid), "--cap-drop", "ALL",
           "--security-opt", "no-new-privileges:true", "--read-only", "--network", "none", "--tmpfs", "/tmp:exec,mode=1777,size=2g",
           "-v", "%s:/workspace/cloud-platform:ro" % a.repo, "-v", "%s:%s" % (qc.LIBVIRT_RW_SOCK, qc.LIBVIRT_RW_SOCK),
           "-v", "%s:%s" % (qc.LIBVIRT_RO_SOCK, qc.LIBVIRT_RO_SOCK), "-v", "%s:/qualify/config.json:ro" % a.config,
           "-v", "%s:%s:ro" % (catalog_dir, catalog_dir), "-v", "%s:/qualify/out" % out_dir]
    if pool_dir:
        run += ["-v", "%s:%s:ro" % (pool_dir, pool_dir)]
    run += ["-e", "SVAVYOM_QUALIFY_CREATE=1", "-e", "SVAVYOM_QUALIFY_STEP=" + step, "-e", "SVAVYOM_QUALIFY_RUN_ID=" + a.run_id,
            "-e", "SVAVYOM_QUALIFY_CONFIG=/qualify/config.json", "-e", "SVAVYOM_QUALIFY_OUT=/qualify/out",
            "-e", "GOMODCACHE=/opt/go-mod-cache", "-e", "GOPROXY=off", "-e", "HOME=/tmp", "-e", "GOCACHE=/tmp/go-cache",
            "-w", "/workspace/cloud-platform/backend", qc.DEV_IMAGE, "go", "test", "-tags", qc.GO_TAGS, "-count=1", "-v", "-run",
            "TestSystemLifecycleQualification", "./internal/hypervisor/libvirtmut/"]
    return run


def ssh(a, ip, user, known, remote, timeout=60):
    p = subprocess.run(qc.ssh_argv(a, ip, user, known, remote), capture_output=True, text=True, timeout=timeout, check=False)  # noqa: S603
    return p.returncode, p.stdout.strip(), (p.stderr.strip().splitlines() or [""])[-1][:200]


def wait_ssh(a, ip, user, known, remote, ok, seconds):
    """Retry the remote command until ok(stdout) holds or the time is up. Returns (success, last stdout or error)."""
    end, last = time.time() + seconds, ""
    while time.time() < end:
        try:
            rc, out, err = ssh(a, ip, user, known, remote, timeout=30)
        except subprocess.TimeoutExpired:
            rc, out, err = 255, "", "timeout"
        last = out if rc == 0 else err
        if rc == 0 and ok(out):
            return True, out
        time.sleep(5)
    return False, last


def read_result(out_dir, step):
    try:
        return json.load(open(os.path.join(out_dir, "lifecycle-%s-result.json" % step)))
    except (OSError, ValueError):
        return {}


def verdict(criteria):
    status = {}
    for cid, st, _ in criteria:
        status[cid] = FAIL if (st == FAIL or status.get(cid) == FAIL) else st
    if any(st == FAIL for st in status.values()):
        return FAIL
    return PASS if all(status.get(c) == PASS for c in REQUIRED) else NOT_RUN


def render(run_id, criteria, result):
    lines = ["Svavyom VM lifecycle qualification  run %s" % run_id]
    seen = set()
    for cid, st, detail in criteria:
        seen.add(cid)
        lines.append("  %-7s %-34s %s" % (st, cid, detail))
    failed = any(st == FAIL for _, st, _ in criteria)
    for cid in REQUIRED:
        if cid not in seen:
            lines.append("  %-7s %-34s %s" % (NOT_RUN, cid, "not run (blocked by an earlier FAIL)" if failed else "not run"))
    lines.append("RESULT: %s" % result)
    return "\n".join(lines)


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default=os.environ.get("QUALIFY_CONFIG", ""))
    ap.add_argument("--ssh-key", default=os.environ.get("QUALIFY_SSH_KEY", ""), help="path of the disposable PRIVATE key (path only is used)")
    ap.add_argument("--run-id", default=os.environ.get("QUALIFY_RUN_ID", ""))
    ap.add_argument("--out", default=os.environ.get("QUALIFY_OUT", "qualification-out"))
    ap.add_argument("--repo", default=os.getcwd())
    a = ap.parse_args(argv)
    miss = [n for n, ok in (("libvirt read-write socket", os.path.exists(qc.LIBVIRT_RW_SOCK)), ("libvirt read-only socket", os.path.exists(qc.LIBVIRT_RO_SOCK)),
                            ("/dev/kvm", os.path.exists("/dev/kvm")), ("QUALIFY_CONFIG", bool(a.config)), ("QUALIFY_SSH_KEY", bool(a.ssh_key)),
                            ("QUALIFY_RUN_ID", bool(a.run_id))) if not ok]
    if miss:
        print("NOT_RUN: missing prerequisites: %s (see docs/QUALIFICATION-LIFECYCLE.md); real-KVM lifecycle qualification pending" % ", ".join(miss))
        return 0
    if not qc.RUN_ID_RE.match(a.run_id) or not os.path.isabs(a.config) or not os.path.isfile(a.config):
        print("ERROR run id must look like qr-YYYYMMDD-xxxxxx and QUALIFY_CONFIG must be an absolute file", file=sys.stderr)
        return 2
    a.config, a.repo = os.path.abspath(a.config), os.path.abspath(a.repo)
    out_dir = os.path.abspath(os.path.join(a.out, a.run_id))
    k = os.path.realpath(a.ssh_key)
    for forbidden in (a.repo, out_dir):
        if k == forbidden or k.startswith(forbidden + os.sep):
            print("ERROR the SSH private key must live outside the repository and the output directory", file=sys.stderr)
            return 2
    try:
        cfg = json.load(open(a.config))
        created = json.load(open(os.path.join(out_dir, "create-result.json")))
    except (OSError, ValueError):
        print("ERROR the provisioning config or the create stage result (create-result.json for this run) is not readable", file=sys.stderr)
        return 2
    catalog_dir = cfg.get("catalog_dir", "")
    ip, user, uuid = created.get("ipv4", ""), created.get("login_user", ""), created.get("uuid", "")
    if not os.path.isdir(catalog_dir) or not ip or not user:
        print("ERROR the create stage did not leave a running VM with an address and login user", file=sys.stderr)
        return 2
    gid, pool_dir = qc.sock_gid(qc.LIBVIRT_RW_SOCK), qc.pool_target_dir(cfg.get("pool", ""))
    known = os.path.join(out_dir, "known_hosts")
    criteria = []

    def go(step):
        rc = subprocess.run(go_argv(step, a, catalog_dir, gid, out_dir, pool_dir), check=False).returncode  # noqa: S603
        res = read_result(out_dir, step)
        criteria.extend((c["id"], c["status"], c.get("detail", "")) for c in res.get("criteria", []))
        if not res:
            criteria.append(("lifecycle-" + step, FAIL, "the container produced no result (exit %d)" % rc))
        return rc == 0 and not any(c["status"] == FAIL for c in res.get("criteria", [])) and bool(res), res

    def stop(why):
        criteria.append(("lifecycle-walk", FAIL, why))
        return finish()

    def finish():
        result = verdict(criteria)
        text = render(a.run_id, criteria, result)
        if not qc.scrub_check(text):
            print("ERROR the report contains private key material; refusing to write it", file=sys.stderr)
            return 2
        print(text)
        for name, body in (("report-lifecycle.txt", text + "\n"), ("report-lifecycle.json", json.dumps({"run_id": a.run_id, "stage": "lifecycle", "result": result,
                           "criteria": [{"id": c, "status": s, "detail": d} for c, s, d in criteria]}, indent=2) + "\n")):
            with open(os.path.join(out_dir, name), "w") as f:
                f.write(body)
        return 0 if result in (PASS, NOT_RUN) else 1

    ok, _ = go("baseline")
    if not ok:
        return stop("baseline step failed; nothing was changed")
    rc, boot1, err = ssh(a, ip, user, known, BOOT_ID + " && sync && echo %s > %s && sync" % (a.run_id, MARKER))
    if rc != 0:
        return stop("cannot reach the guest over SSH before the walk (%s)" % err)
    boot1 = boot1.splitlines()[0]
    ok, _ = go("reboot")
    if not ok:
        return stop("reboot step failed")
    seen, last = wait_ssh(a, ip, user, known, BOOT_ID, lambda o: o.strip() != "" and o.strip() != boot1, 300)
    criteria.append(("guest-reboot-observed", PASS if seen else FAIL, "guest answered SSH with a new boot id after the reboot" if seen else "no new boot id over SSH within 5 minutes (%s)" % last))
    if not seen:
        return stop("the reboot was not observed in the guest")
    for step in ("delete-refused-running", "stop"):
        if not go(step)[0]:
            return stop("%s step failed" % step)
    ok, res = go("start")
    if not ok:
        return stop("start step failed")
    ip = res.get("ipv4") or ip
    kept, last = wait_ssh(a, ip, user, known, "cat %s" % MARKER, lambda o: o.strip() == a.run_id, 300)
    criteria.append(("guest-data-survived-stop", PASS if kept else FAIL, "a file written before the graceful stop was intact after start" if kept else "marker not found after stop/start (%s)" % last))
    if not kept:
        return stop("guest data did not survive the stop")
    for step in ("force-off", "delete-crash", "delete-resume"):
        if not go(step)[0]:
            return stop("%s step failed" % step)
    return finish()


if __name__ == "__main__":
    sys.exit(main())
