#!/usr/bin/env python3
"""Real-host storage and recovery qualification orchestrator (canonical entry: `make docker-qualify-libvirt-storage`).

Continues a run whose create stage left the run's VM Running (docs/QUALIFICATION-LIBVIRT-CREATE.md). One Go step per container (no capabilities, no
network, read-only root; the libvirt sockets, the read-only config/catalog, the PUBLIC key and two writable directories are mounted) and the guest-side
checks on the HOST over SSH with the same disposable private key (only its PATH is used):

  baseline -> [ssh: write marker A] -> stop -> grow the root disk 10 -> 12 GiB -> stopped snapshot -> start -> [ssh: disk is 12 GiB, marker A,
  write marker B] -> stop -> restore snapshot -> start -> [ssh: marker A again, B undone] -> stop -> stopped backup -> delete the VM -> restore the
  backup as a NEW VM (interrupted after the upload and resumed) -> start -> [ssh: marker A, new hostname, key works] -> stop -> reinstall from the
  qualified image -> start -> [ssh: key works, marker gone] -> stop -> delete the restored VM and the backup; base image and every unrelated libvirt
  object unchanged.

Every criterion is PASS / FAIL / NOT_RUN; the verdict is PASS only if all required criteria PASS. Missing prerequisites are NOT_RUN (exit 0), never PASS.
Destructive steps act only on the two identities derived from the run id, proven by the Go stage before each step. See docs/QUALIFICATION-STORAGE.md.
"""
import argparse
import json
import os
import re
import subprocess
import sys
import time

sys.dont_write_bytecode = True
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import qualify_create as qc  # noqa: E402
import qualify_lifecycle as ql  # noqa: E402

PASS, FAIL, NOT_RUN = qc.PASS, qc.FAIL, qc.NOT_RUN
REQUIRED = [
    "inventory-baseline", "storage-visibility", "image-qualified", "disk-grow", "shrink-refused", "guest-disk-grown", "snapshot-created", "resize-blocked-by-snapshot",
    "guest-snapshot-state", "snapshot-restored", "snapshot-deleted", "backup-created", "backup-checksum", "backup-idempotent", "backup-no-key", "source-deleted",
    "restore-unknown-refused", "restore-interrupted", "restore-completed", "restore-no-duplicates", "restore-collision-refused", "guest-restored-state", "guest-restored-access",
    "reinstall-wrong-digest-refused", "reinstall-completed", "reinstall-no-leftovers", "guest-reinstalled-access", "guest-reinstalled-clean", "restored-deleted", "backup-deleted",
    "image-immutable-after", "unrelated-resources-unchanged",
]
MARKER = "/var/tmp/svavyom-storage-marker"


def newest_lease_ip(vm, network):
    """The IPv4 address of the newest DHCP lease for the VM's MAC (read-only virsh). A restored or reinstalled guest keeps its MAC but may present
    a new DHCP client id, so the lease table can hold an old lease beside the live one: the newest expiry is the live one."""
    mac = None
    out = qc.run_diag(["virsh", "-r", "-c", "qemu:///system", "domiflist", "--", vm])
    for line in out.splitlines():
        m = re.search(r"([0-9a-f]{2}(?::[0-9a-f]{2}){5})", line)
        if m:
            mac = m.group(1)
    if not mac:
        return None
    best = None
    for line in qc.run_diag(["virsh", "-r", "-c", "qemu:///system", "net-dhcp-leases", "--", network]).splitlines():
        m = re.search(r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\s+(\S+)\s+ipv4\s+(\d+\.\d+\.\d+\.\d+)/", line)
        if m and m.group(2).lower() == mac.lower() and (best is None or m.group(1) > best[0]):
            best = (m.group(1), m.group(3))
    return best[1] if best else None


def forget_host_key(path):
    try:
        os.remove(path)
    except FileNotFoundError:
        pass


def go_argv(step, a, catalog_dir, gid, out_dir, backup_dir, pool_dir):
    argv = ["docker", "run", "--rm", "-u", "%d:%d" % (os.getuid(), os.getgid()), "--group-add", str(gid), "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges:true", "--read-only", "--network", "none", "--tmpfs", "/tmp:exec,mode=1777,size=2g",
            "-v", "%s:/workspace/cloud-platform:ro" % a.repo, "-v", "%s:%s" % (qc.LIBVIRT_RW_SOCK, qc.LIBVIRT_RW_SOCK),
            "-v", "%s:%s" % (qc.LIBVIRT_RO_SOCK, qc.LIBVIRT_RO_SOCK), "-v", "%s:/qualify/config.json:ro" % a.config,
            "-v", "%s:%s:ro" % (catalog_dir, catalog_dir), "-v", "%s:/qualify/out" % out_dir, "-v", "%s:%s" % (backup_dir, backup_dir),
            "-v", "%s:/qualify/key.pub:ro" % a.pubkey,
            "-e", "SVAVYOM_QUALIFY_CREATE=1", "-e", "SVAVYOM_QUALIFY_STEP=" + step, "-e", "SVAVYOM_QUALIFY_RUN_ID=" + a.run_id,
            "-e", "SVAVYOM_QUALIFY_CONFIG=/qualify/config.json", "-e", "SVAVYOM_QUALIFY_OUT=/qualify/out", "-e", "SVAVYOM_QUALIFY_IMAGE_ID=" + a.image,
            "-e", "SVAVYOM_QUALIFY_SSH_PUBKEY_FILE=/qualify/key.pub", "-e", "SVAVYOM_QUALIFY_BACKUP_DIR=" + backup_dir,
            "-e", "GOMODCACHE=/opt/go-mod-cache", "-e", "GOPROXY=off", "-e", "HOME=/tmp", "-e", "GOCACHE=/tmp/go-cache",
            "-w", "/workspace/cloud-platform/backend", qc.DEV_IMAGE, "go", "test", "-tags", qc.GO_TAGS, "-count=1", "-v", "-timeout", "30m", "-run",
            "TestSystemStorageQualification", "./internal/hypervisor/libvirtmut/"]
    if pool_dir:  # the pool directory, read-only, so the volume inspection (regular file, no symlink) is possible, as in the lifecycle stage
        argv[argv.index("-e"):argv.index("-e")] = ["-v", "%s:%s:ro" % (pool_dir, pool_dir)]
    return argv


def read_result(out_dir, step):
    try:
        return json.load(open(os.path.join(out_dir, "storage-%s-result.json" % step)))
    except (OSError, ValueError):
        return {}


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default=os.environ.get("QUALIFY_CONFIG", ""))
    ap.add_argument("--pubkey", default=os.environ.get("QUALIFY_PUBKEY", ""))
    ap.add_argument("--image", default=os.environ.get("QUALIFY_IMAGE", ""))
    ap.add_argument("--ssh-key", default=os.environ.get("QUALIFY_SSH_KEY", ""), help="path of the disposable PRIVATE key (path only is used)")
    ap.add_argument("--run-id", default=os.environ.get("QUALIFY_RUN_ID", ""))
    ap.add_argument("--out", default=os.environ.get("QUALIFY_OUT", "qualification-out"))
    ap.add_argument("--repo", default=os.getcwd())
    a = ap.parse_args(argv)
    miss = [n for n, ok in (("libvirt read-write socket", os.path.exists(qc.LIBVIRT_RW_SOCK)), ("libvirt read-only socket", os.path.exists(qc.LIBVIRT_RO_SOCK)),
                            ("/dev/kvm", os.path.exists("/dev/kvm")), ("QUALIFY_CONFIG", bool(a.config)), ("QUALIFY_SSH_KEY", bool(a.ssh_key)), ("QUALIFY_PUBKEY", bool(a.pubkey)),
                            ("QUALIFY_IMAGE", bool(a.image)), ("QUALIFY_RUN_ID", bool(a.run_id))) if not ok]
    if miss:
        print("NOT_RUN: missing prerequisites: %s (see docs/QUALIFICATION-STORAGE.md); real-KVM storage qualification pending" % ", ".join(miss))
        return 0
    if not qc.RUN_ID_RE.match(a.run_id) or not qc.IMAGE_ID_RE.match(a.image) or not os.path.isabs(a.config) or not os.path.isfile(a.config) or not os.path.isfile(a.pubkey):
        print("ERROR run id, image id, config and public key must be valid", file=sys.stderr)
        return 2
    a.config, a.repo, a.pubkey = os.path.abspath(a.config), os.path.abspath(a.repo), os.path.abspath(a.pubkey)
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
    ip, user = created.get("ipv4", ""), created.get("login_user", "")
    if not os.path.isdir(catalog_dir) or not ip or not user:
        print("ERROR the create stage did not leave a running VM with an address and login user", file=sys.stderr)
        return 2
    backup_dir = os.path.join(out_dir, "backups")
    os.makedirs(backup_dir, mode=0o700, exist_ok=True)
    os.chmod(backup_dir, 0o700)
    backup_dir = os.path.realpath(backup_dir)
    if not re.fullmatch(r"/[A-Za-z0-9._/-]{1,198}", backup_dir):
        print("ERROR the backup directory path has characters the product refuses", file=sys.stderr)
        return 2
    gid, pool_dir = qc.sock_gid(qc.LIBVIRT_RW_SOCK), qc.pool_target_dir(cfg.get("pool", ""))
    known = os.path.join(out_dir, "known_hosts")
    criteria = []

    def go(step):
        rc = subprocess.run(go_argv(step, a, catalog_dir, gid, out_dir, backup_dir, pool_dir), check=False).returncode  # noqa: S603
        res = read_result(out_dir, step)
        criteria.extend((c["id"], c["status"], c.get("detail", "")) for c in res.get("criteria", []))
        if not res:
            criteria.append(("storage-" + step, FAIL, "the container produced no result (exit %d)" % rc))
        return rc == 0 and bool(res) and not any(c["status"] == FAIL for c in res.get("criteria", [])), res

    def ssh(host, remote, timeout=60):
        return ql.ssh(a, host, user, known, remote, timeout)

    def finish(why=None):
        if why:
            criteria.append(("storage-walk", FAIL, why))
        status = {}
        for cid, st, _ in criteria:
            status[cid] = FAIL if (st == FAIL or status.get(cid) == FAIL) else st
        result = FAIL if any(s == FAIL for s in status.values()) else (PASS if all(status.get(c) == PASS for c in REQUIRED) else NOT_RUN)
        lines = ["Svavyom storage and recovery qualification  run %s" % a.run_id]
        seen = set()
        for cid, st, detail in criteria:
            seen.add(cid)
            lines.append("  %-7s %-34s %s" % (st, cid, detail))
        for cid in REQUIRED:
            if cid not in seen:
                lines.append("  %-7s %-34s %s" % (NOT_RUN, cid, "not run (blocked by an earlier FAIL)" if any(s == FAIL for s in status.values()) else "not run"))
        lines.append("RESULT: %s" % result)
        text = "\n".join(lines)
        if not qc.scrub_check(text):
            print("ERROR the report contains private key material; refusing to write it", file=sys.stderr)
            return 2
        print(text)
        for name, body in (("report-storage.txt", text + "\n"), ("report-storage.json", json.dumps({"run_id": a.run_id, "stage": "storage", "result": result,
                           "criteria": [{"id": c, "status": s, "detail": d} for c, s, d in criteria]}, indent=2) + "\n")):
            with open(os.path.join(out_dir, name), "w") as f:
                f.write(body)
        return 0 if result in (PASS, NOT_RUN) else 1

    def follow(label, vm, check, ok_detail, bad_detail, seconds=300):
        """Like guest(), but re-resolves the VM's address from the newest lease on every round (a new guest instance may get a new address)."""
        end, last = time.time() + seconds, "no address"
        while time.time() < end:
            ip = newest_lease_ip(vm, cfg.get("network", "default"))
            if ip:
                good, last = ql.wait_ssh(a, ip, user, known, check[0], check[1], 20)
                if good:
                    criteria.append((label, PASS, ok_detail))
                    return True
            else:
                time.sleep(5)
        criteria.append((label, FAIL, "%s (%s)" % (bad_detail, last)))
        return False

    def guest(label, host, check, ok_detail, bad_detail, seconds=300):
        good, last = ql.wait_ssh(a, host, user, known, check[0], check[1], seconds)
        criteria.append((label, PASS if good else FAIL, ok_detail if good else "%s (%s)" % (bad_detail, last)))
        return good

    ok, _ = go("baseline")
    if not ok:
        return finish("baseline failed; nothing was changed")
    criteria.append(("image-qualified", PASS, "the catalog image is real-host qualified (a reinstall needs one); the baseline step fails otherwise"))
    run_marker = "A-" + a.run_id
    rc, out, err = ssh(ip, "echo %s > %s && sync" % (run_marker, MARKER))
    if rc != 0:
        return finish("cannot reach the guest over SSH before the walk (%s)" % err)
    for step in ("stop", "resize", "snapshot"):
        if not go(step)[0]:
            return finish("%s step failed" % step)
    ok, res = go("start-primary")
    if not ok:
        return finish("start step failed")
    ip = res.get("ipv4") or ip
    guest("guest-disk-grown", ip, ("lsblk -b -n -d -o SIZE /dev/vda", lambda o: o.strip() == str(12 << 30)), "the guest sees a 12 GiB virtual disk (the partition/filesystem is the guest administrator's step)",
          "the guest does not see the grown disk")
    if not guest("guest-marker-before-snapshot-restore", ip, ("cat %s" % MARKER, lambda o: o.strip() == run_marker), "marker A present after the grow", "marker A missing after the grow"):
        return finish("guest state not as expected after the resize")
    ssh(ip, "echo B-%s > %s && sync" % (a.run_id, MARKER))
    for step in ("stop",):
        if not go(step)[0]:
            return finish("stop step failed")
    if not go("restore-snapshot")[0]:
        return finish("restore-snapshot step failed")
    ok, res = go("start-primary")
    if not ok:
        return finish("start step failed")
    ip = res.get("ipv4") or ip
    guest("guest-snapshot-state", ip, ("cat %s" % MARKER, lambda o: o.strip() == run_marker), "after the snapshot restore the guest has marker A again; the later write B is gone",
          "marker A not restored")
    for step in ("stop", "backup", "delete-source", "restore"):
        if not go(step)[0]:
            return finish("%s step failed" % step)
    ok, res = go("start-restored")
    if not ok:
        return finish("start-restored failed")
    rip, rvm = res.get("ipv4"), res.get("vm_name")
    forget_host_key(known)  # a new VM identity (cloud-init regenerates the SSH host keys) is a different host from the source VM
    follow("guest-restored-access", rvm, ("echo $(hostname) $(cat /var/lib/cloud/data/instance-id)", lambda o: o.split()[0].startswith("svr-") if o.split() else False),
          "the restored VM answers over SSH with the supplied key and its NEW hostname (cloud-init ran again for the new instance)", "the restored VM is not reachable with the supplied key")
    follow("guest-restored-state", rvm, ("cat %s" % MARKER, lambda o: o.strip() == run_marker), "the restored VM carries the backed-up data (marker A)", "the backed-up data is not in the restored VM")
    for step in ("stop-restored", "reinstall"):
        if not go(step)[0]:
            return finish("%s step failed" % step)
    ok, res = go("start-restored")
    if not ok:
        return finish("start after reinstall failed")
    rip = res.get("ipv4")
    forget_host_key(known)  # a fresh install has fresh SSH host keys
    follow("guest-reinstalled-access", rvm, ("echo ok", lambda o: o.strip() == "ok"), "the reinstalled VM answers over SSH with the supplied key", "the reinstalled VM is not reachable")
    rip = newest_lease_ip(rvm, cfg.get("network", "default")) or rip
    good, last = ql.wait_ssh(a, rip, user, known, "test -e %s && echo present || echo absent" % MARKER, lambda o: o.strip() == "absent", 60)
    criteria.append(("guest-reinstalled-clean", PASS if good else FAIL, "a fresh install: the previous data (marker A) is gone" if good else "the old data survived the reinstall (%s)" % last))
    for step in ("stop-restored", "cleanup"):
        if not go(step)[0]:
            return finish("%s step failed" % step)
    return finish()


if __name__ == "__main__":
    sys.exit(main())
