#!/usr/bin/env python3
"""A running Windows VM across an upgrade and a rollback of Svavyom (finding N10 of the 2026-11-14 findings plan). Stdlib only. Run ON the host, in three phases:

    python3 tools/qualify_winkeep.py --base https://127.0.0.1:8443 --user admin --password-file PW --image windowsserver2019-iso --run-id qr-YYYYMMDD-xxxxxx --out DIR --phase start
    ... the upgrade and the rollback happen here (tools/qualify_clean_host.py, stage winupgrade) ...
    python3 tools/qualify_winkeep.py ... --phase check     (as often as wanted)
    python3 tools/qualify_winkeep.py ... --phase stop

start creates ONE Windows VM from installation media through the API, starts it and records its QEMU process id in a state file outside the harness directory. check
proves the VM is still running **in the same QEMU process** (the services restarting must not restart a guest) and that libvirt and the API still report it. stop removes
it (through the API when it knows the VM, with virsh when a restored database no longer does). No password, cookie or ticket is printed.
"""
import argparse
import importlib.util
import json
import os
import re
import secrets
import subprocess
import sys
import time

sys.dont_write_bytecode = True
HERE = os.path.dirname(os.path.abspath(__file__))
STATE_DIR = "/var/tmp"


def load_graphics():
    spec = importlib.util.spec_from_file_location("qualify_graphics", os.path.join(HERE, "qualify_graphics.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def state_path(run_id):
    return os.path.join(STATE_DIR, "svq-winkeep-%s.json" % run_id)


def vm_name(run_id):
    return "wk-" + run_id[-6:]


def pid_from_pgrep(text):
    """The QEMU process id from `pgrep -f` output: exactly one number, else None (no process, or an ambiguous answer)."""
    ids = re.findall(r"^[0-9]+$", text, re.M)
    return int(ids[0]) if len(ids) == 1 else None


def judge_keep(state, pid_now, libvirt_state, api_vm):
    """[(criterion, ok, detail)]: the VM is running in the very process it was started in, and libvirt and the API both say so. api_vm is the API's VM object or None;
    managed is reported, not judged (a database restored by a rollback may no longer know the VM)."""
    o = (api_vm or {}).get("observed", {})
    return [
        ("keep-libvirt-running", libvirt_state == "running", "libvirt says %s" % libvirt_state),
        ("keep-same-process", pid_now is not None and pid_now == state.get("pid"), "QEMU process %s now, %s when it was started" % (pid_now, state.get("pid"))),
        ("keep-listed-by-api", api_vm is not None and o.get("power") == "running" and o.get("guest_profile") == "windows",
         "the API lists it: power=%s guest_profile=%s managed=%s" % (o.get("power"), o.get("guest_profile"), o.get("managed")) if api_vm else "the API does not list it"),
    ]


def removable_disks(domblklist_text, root="/var/lib/svavyom/"):
    """The root disk files of a domain that may be deleted with it, from `virsh domblklist --details`: type disk (never a CD), a file under Svavyom's own directory and never in
    the image store, where the registered installation media live."""
    out = []
    for ln in domblklist_text.splitlines()[2:]:
        p = ln.split()
        if len(p) >= 4 and p[0] == "file" and p[1] == "disk" and p[3].startswith(root) and "/images/store/" not in p[3] and ".." not in p[3]:
            out.append(p[3])
    return out


def virsh(*args, sudo=False, timeout=60):
    cmd = ["sudo", "-n", "virsh", "-c", "qemu:///system", *args] if sudo else ["virsh", "-r", "-c", "qemu:///system", *args]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)  # noqa: S603,S607
    return r.returncode, r.stdout.strip()


def qemu_pid(name):
    r = subprocess.run(["pgrep", "-f", "guest=%s," % name], capture_output=True, text=True, check=False)  # noqa: S603,S607
    return pid_from_pgrep(r.stdout)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--base", required=True)
    ap.add_argument("--user", required=True)
    ap.add_argument("--password-file", required=True)
    ap.add_argument("--image", required=True)
    ap.add_argument("--run-id", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--phase", required=True, choices=["start", "check", "stop"])
    a = ap.parse_args(argv)
    if not re.fullmatch(r"qr-\d{8}-[0-9a-f]{6}", a.run_id):
        print("ERROR the run id must look like qr-YYYYMMDD-xxxxxx")
        return 2
    g = load_graphics()
    g.R.clear()
    rec = g.rec
    name, sp = vm_name(a.run_id), state_path(a.run_id)
    api = g.Api(a.base, a.password_file, a.user)
    signed = False
    for _ in range(40):  # the API may still be coming back after an upgrade or a rollback
        try:
            signed = api.sign_in()
        except OSError:
            signed = False
        if signed:
            break
        time.sleep(3)
    pre = a.phase
    rec(pre + ":sign-in", signed, "an operator session")
    if signed and a.phase == "start":
        ok, m = api.op_run("create", "VM", name, create={"vcpus": 4, "memory_mib": 4096, "image_id": a.image, "disk_gib": 40, "guest_profile": "windows"})
        rec("start:create-windows", ok, m)
        if ok:
            ok, m = api.op_run("start", "VM", name)
            v = api.wait_vm(name, "running")
            rec("start:start", ok and bool(v), m)
            time.sleep(5)
            pid = qemu_pid(name)
            rec("start:qemu-process", pid is not None, "QEMU process %s" % pid)
            if pid is not None:
                with open(sp, "w") as f:
                    json.dump({"name": name, "pid": pid, "started": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}, f)
    elif signed and a.phase == "check":
        try:
            state = json.load(open(sp))
        except (OSError, ValueError):
            state = {}
            rec("check:state", False, "no state file: the start phase did not finish")
        if state:
            rc, st = virsh("domstate", name)
            for cid, ok, detail in judge_keep(state, qemu_pid(name), st if rc == 0 else "missing", api.vm(name)):
                rec("check:" + cid, ok, detail)
    elif signed and a.phase == "stop":
        known = api.vm(name) is not None
        if known:
            api.op_run("force_off", "VM", name, timeout=120)
            api.wait_vm(name, "stopped", timeout=120)
            api.op_run("delete", "VM", name)
        rc, st = virsh("domstate", name)
        if rc == 0:  # a restored database may not know the VM: remove it as root. Only its own root disk is deleted: --remove-all-storage could take an installation medium too.
            _, blk = virsh("domblklist", name, "--details")
            disks = removable_disks(blk)
            virsh("destroy", name, sudo=True)
            virsh("undefine", name, sudo=True)
            for d in disks:
                subprocess.run(["sudo", "-n", "rm", "-f", "--", d], capture_output=True, check=False)  # noqa: S603,S607
        rc, _ = virsh("domstate", name)
        rec("stop:cleanup", rc != 0, "the domain %s is gone from libvirt" % name if rc != 0 else "THE DOMAIN %s IS STILL IN LIBVIRT" % name)
        try:
            os.remove(sp)
        except OSError:
            pass
    bad = [r for r in g.R if r["status"] == "FAIL"]
    with open(os.path.join(a.out, "%s-winkeep-%s.json" % (a.run_id, a.phase)), "w") as f:
        json.dump({"run_id": a.run_id, "phase": a.phase, "results": g.R}, f, indent=1)
    print("RESULT", "FAIL" if bad else "PASS")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
