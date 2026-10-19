#!/usr/bin/env python3
"""Real-host network qualification orchestrator (canonical entry: `make docker-qualify-libvirt-network`).

Creates ONE uniquely named Svavyom-managed NAT network (derived from the run id) in a private /24 that conflicts with nothing on the host, attaches ONE
VM to it, and walks: baseline -> network create (and its refusals) -> VM create -> start -> [ssh: 1 vCPU] -> stop -> change vCPU/memory -> start ->
[ssh: 2 vCPU, ~2 GiB] -> stop -> reserve an address -> start -> [ssh on the RESERVED address] -> stop -> release -> delete the VM -> stop/start/delete the
network. One Go step per container (no capabilities, no network, read-only root); guest checks on the HOST over SSH with the same disposable key (only its
PATH is used). The host's routes, interface addresses and every pre-existing libvirt network definition are recorded before and compared after.

Every criterion is PASS / FAIL / NOT_RUN; the verdict is PASS only if all required criteria PASS. Missing prerequisites are NOT_RUN (exit 0), never PASS.
Destructive steps act only on the network and the VM derived from the run id, proven by the Go stage before each step. See docs/QUALIFICATION-NETWORKS.md.
"""
import argparse
import ipaddress
import json
import os
import re
import subprocess
import sys

sys.dont_write_bytecode = True
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import qualify_create as qc  # noqa: E402
import qualify_lifecycle as ql  # noqa: E402

PASS, FAIL, NOT_RUN = qc.PASS, qc.FAIL, qc.NOT_RUN
REQUIRED = [
    "networks-recorded", "subnet-free", "image-immutable-before", "network-created", "network-create-idempotent", "overlap-refused", "foreign-network-untouched",
    "refusals-change-nothing", "vm-created", "vm-attached", "delete-with-vm-refused", "default-name-refused", "vm-start", "dhcp-lease", "stop-with-running-vm-refused",
    "compute-running-refused", "guest-before-compute", "vm-stop", "compute-bounds", "compute-set", "guest-after-compute", "reserve-refusals", "ip-reserved",
    "guest-on-reserved-address", "ip-released", "vm-deleted", "image-immutable-after-delete", "network-lifecycle", "network-deleted", "networks-unchanged",
    "host-routes-unchanged", "host-interfaces-unchanged", "preexisting-network-definitions-unchanged", "image-immutable-after",
]


def run(argv, timeout=30):
    try:
        p = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, check=False)  # noqa: S603
        return p.stdout
    except (OSError, subprocess.SubprocessError):
        return ""


def host_prefixes():
    """The host's own IPv4 prefixes: every non-default route and every interface address, as canonical CIDRs."""
    out = set()
    for line in run(["ip", "-4", "route"]).splitlines():
        tok = line.split()
        if tok and tok[0] != "default" and "/" in tok[0]:
            try:
                out.add(str(ipaddress.ip_network(tok[0], strict=False)))
            except ValueError:
                pass
    for line in run(["ip", "-4", "-o", "addr"]).splitlines():
        m = re.search(r"inet (\d+\.\d+\.\d+\.\d+/\d+)", line)
        if m:
            out.add(str(ipaddress.ip_interface(m.group(1)).network))
    return sorted(out)


def libvirt_net_names():
    return [n for n in run(["virsh", "-r", "-c", "qemu:///system", "net-list", "--all", "--name"]).split() if n]


def libvirt_prefixes():
    out = set()
    for n in libvirt_net_names():
        x = run(["virsh", "-r", "-c", "qemu:///system", "net-dumpxml", "--", n])
        for m in re.finditer(r"<ip address='([\d.]+)'(?: netmask='([\d.]+)'| prefix='(\d+)')", x):
            mask = m.group(2) or m.group(3)
            try:
                out.add(str(ipaddress.ip_network("%s/%s" % (m.group(1), mask), strict=False)))
            except ValueError:
                pass
    return sorted(out)


def choose_subnet(busy):
    nets = [ipaddress.ip_network(b) for b in busy]
    for second in range(201, 251):
        for third in (7, 8, 9):
            cand = ipaddress.ip_network("10.%d.%d.0/24" % (second, third))
            if not any(cand.overlaps(n) for n in nets):
                return str(cand)
    return None


def snapshot_host(ours):
    """Routes, interface addresses and pre-existing libvirt network definitions, without anything that belongs to the run's own network."""
    def clean(text):
        return "\n".join(sorted(re.sub(r"\s+", " ", l).strip() for l in text.splitlines() if l.strip() and ours not in l))
    nets = {}
    for n in libvirt_net_names():
        if n != ours:
            nets[n] = run(["virsh", "-r", "-c", "qemu:///system", "net-dumpxml", "--", n])
    return {"routes": clean(run(["ip", "-4", "route"])), "addresses": clean(run(["ip", "-4", "-o", "addr"])),
            "links": clean(run(["ip", "-o", "link"])).replace(" ", ""), "networks": nets}


def go_argv(step, a, catalog_dir, gid, out_dir, pool_dir, subnet, expect_ip):
    argv = ["docker", "run", "--rm", "-u", "%d:%d" % (os.getuid(), os.getgid()), "--group-add", str(gid), "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges:true", "--read-only", "--network", "none", "--tmpfs", "/tmp:exec,mode=1777,size=2g",
            "-v", "%s:/workspace/cloud-platform:ro" % a.repo, "-v", "%s:%s" % (qc.LIBVIRT_RW_SOCK, qc.LIBVIRT_RW_SOCK),
            "-v", "%s:%s" % (qc.LIBVIRT_RO_SOCK, qc.LIBVIRT_RO_SOCK), "-v", "%s:/qualify/config.json:ro" % a.config,
            "-v", "%s:%s:ro" % (catalog_dir, catalog_dir), "-v", "%s:/qualify/out" % out_dir, "-v", "%s:/qualify/key.pub:ro" % a.pubkey,
            "-e", "SVAVYOM_QUALIFY_CREATE=1", "-e", "SVAVYOM_QUALIFY_STEP=" + step, "-e", "SVAVYOM_QUALIFY_RUN_ID=" + a.run_id,
            "-e", "SVAVYOM_QUALIFY_CONFIG=/qualify/config.json", "-e", "SVAVYOM_QUALIFY_OUT=/qualify/out", "-e", "SVAVYOM_QUALIFY_IMAGE_ID=" + a.image,
            "-e", "SVAVYOM_QUALIFY_SSH_PUBKEY_FILE=/qualify/key.pub", "-e", "SVAVYOM_QUALIFY_NET_SUBNET=" + subnet,
            "-e", "SVAVYOM_QUALIFY_HOST_ROUTES=/qualify/out/host-prefixes.txt", "-e", "SVAVYOM_QUALIFY_EXPECT_IP=" + expect_ip,
            "-e", "GOMODCACHE=/opt/go-mod-cache", "-e", "GOPROXY=off", "-e", "HOME=/tmp", "-e", "GOCACHE=/tmp/go-cache",
            "-w", "/workspace/cloud-platform/backend", qc.DEV_IMAGE, "go", "test", "-tags", qc.GO_TAGS, "-count=1", "-v", "-timeout", "30m", "-run",
            "TestSystemNetworkQualification", "./internal/hypervisor/libvirtmut/"]
    if pool_dir:
        argv[argv.index("-e"):argv.index("-e")] = ["-v", "%s:%s:ro" % (pool_dir, pool_dir)]
    return argv


def read_result(out_dir, step):
    try:
        return json.load(open(os.path.join(out_dir, "network-%s-result.json" % step)))
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
        print("NOT_RUN: missing prerequisites: %s (see docs/QUALIFICATION-NETWORKS.md); real-KVM network qualification pending" % ", ".join(miss))
        return 0
    if not qc.RUN_ID_RE.match(a.run_id) or not qc.IMAGE_ID_RE.match(a.image) or not os.path.isabs(a.config) or not os.path.isfile(a.config) or not os.path.isfile(a.pubkey):
        print("ERROR run id, image id, config and public key must be valid", file=sys.stderr)
        return 2
    a.config, a.repo, a.pubkey = os.path.abspath(a.config), os.path.abspath(a.repo), os.path.abspath(a.pubkey)
    out_dir = os.path.abspath(os.path.join(a.out, a.run_id))
    os.makedirs(out_dir, mode=0o700, exist_ok=True)
    k = os.path.realpath(a.ssh_key)
    for forbidden in (a.repo, out_dir):
        if k == forbidden or k.startswith(forbidden + os.sep):
            print("ERROR the SSH private key must live outside the repository and the output directory", file=sys.stderr)
            return 2
    try:
        cfg = json.load(open(a.config))
    except (OSError, ValueError):
        print("ERROR the provisioning config is not readable", file=sys.stderr)
        return 2
    catalog_dir = cfg.get("catalog_dir", "")
    if not os.path.isdir(catalog_dir):
        print("ERROR the catalog directory of the provisioning config does not exist", file=sys.stderr)
        return 2
    suffix = a.run_id[3:]
    net_name, bridge_hint = "svqn-" + suffix, "svbr"
    prefixes = sorted(set(host_prefixes()) | set(libvirt_prefixes()))
    subnet = choose_subnet(prefixes)
    if not subnet:
        print("ERROR no free private /24 was found for the qualification network", file=sys.stderr)
        return 2
    with open(os.path.join(out_dir, "host-prefixes.txt"), "w") as f:
        f.write("\n".join(host_prefixes()) + "\n")
    base = ipaddress.ip_network(subnet)
    reserved = str(base.network_address + 50)
    gid, pool_dir = qc.sock_gid(qc.LIBVIRT_RW_SOCK), qc.pool_target_dir(cfg.get("pool", ""))
    known = os.path.join(out_dir, "known_hosts")
    criteria, state = [], {"user": ""}
    before = snapshot_host(bridge_hint)

    def go(step, expect_ip=""):
        rc = subprocess.run(go_argv(step, a, catalog_dir, gid, out_dir, pool_dir, subnet, expect_ip), check=False).returncode  # noqa: S603
        res = read_result(out_dir, step)
        criteria.extend((c["id"], c["status"], c.get("detail", "")) for c in res.get("criteria", []))
        if not res:
            criteria.append(("network-" + step, FAIL, "the container produced no result (exit %d)" % rc))
        if res.get("login_user"):
            state["user"] = res["login_user"]
        return rc == 0 and bool(res) and not any(c["status"] == FAIL for c in res.get("criteria", [])), res

    def finish(why=None):
        if why:
            criteria.append(("network-walk", FAIL, why))
        status = {}
        for cid, st, _ in criteria:
            status[cid] = FAIL if (st == FAIL or status.get(cid) == FAIL) else st
        result = FAIL if any(s == FAIL for s in status.values()) else (PASS if all(status.get(c) == PASS for c in REQUIRED) else NOT_RUN)
        lines = ["Svavyom network qualification  run %s  (network %s, subnet %s)" % (a.run_id, net_name, subnet)]
        seen = set()
        for cid, st, detail in criteria:
            seen.add(cid)
            lines.append("  %-7s %-40s %s" % (st, cid, detail))
        for cid in REQUIRED:
            if cid not in seen:
                lines.append("  %-7s %-40s %s" % (NOT_RUN, cid, "not run (blocked by an earlier FAIL)" if any(s == FAIL for s in status.values()) else "not run"))
        lines.append("RESULT: %s" % result)
        text = "\n".join(lines)
        if not qc.scrub_check(text):
            print("ERROR the report contains private key material; refusing to write it", file=sys.stderr)
            return 2
        print(text)
        for name, body in (("report-network.txt", text + "\n"), ("report-network.json", json.dumps({"run_id": a.run_id, "stage": "network", "result": result, "subnet": subnet,
                           "criteria": [{"id": c, "status": s, "detail": d} for c, s, d in criteria]}, indent=2) + "\n")):
            with open(os.path.join(out_dir, name), "w") as f:
                f.write(body)
        return 0 if result in (PASS, NOT_RUN) else 1

    def guest(label, ip, check, ok_detail, bad_detail, seconds=300):
        good, last = ql.wait_ssh(argparse.Namespace(**vars(a)), ip, state["user"], known, check[0], check[1], seconds)
        criteria.append((label, PASS if good else FAIL, ok_detail if good else "%s (%s)" % (bad_detail, last)))
        return good

    # SSH needs the login user, which the baseline step learns from the catalog.
    ok, _ = go("baseline")
    if not ok:
        return finish("baseline failed; nothing was changed")
    for step in ("net-create", "vm-create", "reserve"):
        if not go(step)[0]:
            return finish("%s step failed" % step)
    # The reservation was made BEFORE the VM ever asked for an address: a guest that already holds a lease keeps it until it expires (found on the real
    # host), so this is the order in which a reservation takes effect at once.
    ok, res = go("vm-start", expect_ip=reserved)
    if not ok:
        return finish("the VM did not come up on the reserved address")
    ip = res.get("ipv4", "")
    guest("guest-on-reserved-address", ip, ("echo $(nproc) $(awk '/MemTotal/{print int($2/1024)}' /proc/meminfo)", lambda o: o.split()[:1] == ["1"]),
          "the guest answers over SSH on the reserved address %s on the new network and reports 1 vCPU" % reserved, "the guest is not reachable on the reserved address")
    criteria.append(("guest-before-compute", PASS if ip == reserved else FAIL, "the VM runs with 1 vCPU on the reserved address" if ip == reserved else "wrong address %s" % ip))
    for step in ("vm-stop", "compute"):
        if not go(step)[0]:
            return finish("%s step failed" % step)
    ok, res = go("vm-start", expect_ip=reserved)
    if not ok:
        return finish("vm-start after the compute change failed")
    ip = res.get("ipv4", "")
    guest("guest-after-compute", ip, ("echo $(nproc) $(awk '/MemTotal/{print int($2/1024)}' /proc/meminfo)", lambda o: len(o.split()) == 2 and o.split()[0] == "2" and 1700 <= int(o.split()[1]) <= 2100),
          "after the change the guest reports 2 vCPU and about 2 GiB, still on the reserved address", "the guest does not report the new size")
    for step in ("vm-stop", "release", "vm-delete", "net-delete", "final"):
        if not go(step)[0]:
            return finish("%s step failed" % step)
    after = snapshot_host(bridge_hint)
    for cid, key, what in (("host-routes-unchanged", "routes", "the host's IPv4 routes"), ("host-interfaces-unchanged", "addresses", "the host's interface addresses")):
        same = before[key] == after[key] and (key != "addresses" or before["links"] == after["links"])
        criteria.append((cid, PASS if same else FAIL, "%s are identical before and after (the run's own bridge excluded)" % what if same else "%s changed" % what))
    same = before["networks"] == after["networks"]
    criteria.append(("preexisting-network-definitions-unchanged", PASS if same else FAIL, "every pre-existing libvirt network definition (%s) is byte-identical to before" % ", ".join(sorted(before["networks"]))
                     if same else "a pre-existing libvirt network definition changed"))
    return finish()


if __name__ == "__main__":
    sys.exit(main())
