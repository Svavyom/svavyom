#!/usr/bin/env python3
"""Real-host qualification of the bridge-mode network (DR-028) on the INSTALLED Svavyom, without touching the host's network. Stdlib only.

It creates a throwaway Linux bridge with no uplink and no address (so no route and no traffic changes), has svavyom-ctl ADOPT it (adoption changes nothing
on the host), then checks through the public API: the host summary shows the bridge, a bridge-mode network can be created only on it, a VM created on that
network gets its NIC on the bridge, and everything is removed again. The bridge of the host's real uplink is never planned for apply here.

    python3 tools/qualify_bridge_host.py --base http://127.0.0.1:8443 --user certify --password-file PW --image ubuntu-24.04 --ctl /usr/libexec/svavyom/svavyom-ctl
"""
import argparse, json, os, secrets, subprocess, sys, time

sys.dont_write_bytecode = True
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from qualify_graphics import Api, rec, R, sh  # noqa: E402

BR = "svqtest0"


def sudo(*a):
    return sh(["sudo", *a], timeout=120)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", required=True)
    ap.add_argument("--user", required=True)
    ap.add_argument("--password-file", required=True)
    ap.add_argument("--image", required=True)
    ap.add_argument("--ctl", required=True)
    ap.add_argument("--key", required=True, help="a disposable SSH key pair (private file, .pub beside it); the VM is never logged into")
    a = ap.parse_args()
    api = Api(a.base, a.password_file, a.user)
    if not rec("sign-in", api.sign_in()):
        return 1
    vm, net = "bq-" + secrets.token_hex(3), "bnet-" + secrets.token_hex(2)

    def host_bridge():
        s, h = api.call("GET", "/api/v1/hosts/local")
        return (h or {}).get("observed", {}).get("bridge") if s == 200 else "error"

    def submit(typ, kind, rid, params=None):
        s, o = api.call("POST", "/api/v1/operations", {"type": typ, "kind": kind, "id": rid, "idempotency_key": "b" + secrets.token_hex(12), **({"params": params} if params else {})})
        return s

    try:
        rec("the host shows no bridge before", host_bridge() is None, str(host_bridge()))
        # a bridge network is refused while no host bridge is recorded
        rec("bridge network refused with no recorded bridge", submit("network_create", "VirtualNetwork", net, {"bridge": BR}) == 422)
        # planning on the real host (as root) records a plan; the API shows it as planned; nothing changes
        rc, out = sudo(a.ctl, "bridge", "plan")
        rec("plan as root on the real host (read-only, recorded)", rc == 0 and "svbr0" in out, out.splitlines()[0][:100])
        b = host_bridge()
        rec("the API shows the plan as planned", bool(b) and b["state"] == "planned" and b["bridge"] == "svbr0", str(b))
        rec("a planned bridge is not usable for a network", submit("network_create", "VirtualNetwork", net, {"bridge": "svbr0"}) == 422)
        rc, out = sudo(a.ctl, "bridge", "rollback")
        rec("forgetting the plan clears the state", rc == 0 and host_bridge() is None, out.strip()[:80])
        rc, route_before = sh(["ip", "-o", "route", "show", "default"])
        rc, links_before = sh(["ip", "-o", "link", "show"])

        # a throwaway bridge with no uplink and no address, adopted as it is
        rc, out = sudo("ip", "link", "add", BR, "type", "bridge")
        rec("create a throwaway bridge", rc == 0, out.strip()[:80])
        sudo("ip", "link", "set", BR, "up")
        rc, out = sudo(a.ctl, "bridge", "adopt", "--name", "virbr0", "--confirm-bridge", "virbr0")
        rec("adopting libvirt's own bridge is refused", "BR_NOT_A_BRIDGE" in out, out.strip()[:80])
        rc, out = sudo(a.ctl, "bridge", "adopt", "--name", BR, "--confirm-bridge", BR)
        rec("adopt the throwaway bridge", rc == 0 and "Adopted" in out, out.strip()[:100])
        b = host_bridge()
        rec("the API shows it as active", bool(b) and b["state"] == "active" and b["bridge"] == BR, str(b))

        rec("a bridge network on another name is refused", submit("network_create", "VirtualNetwork", net, {"bridge": "svbr0"}) == 422)
        rec("libvirt's bridge is refused", submit("network_create", "VirtualNetwork", net, {"bridge": "virbr0"}) == 400)
        ok, m = api.op_run("network_create", "VirtualNetwork", net, params={"bridge": BR})
        rec("create a bridge-mode network on the adopted bridge", ok, m)
        s, n = api.call("GET", f"/api/v1/virtual-networks/{net}")
        o = (n or {}).get("observed", {})
        rec("it is managed, active, mode bridge, no subnet", s == 200 and o.get("managed") and o.get("state") == "active" and n["desired"]["mode"] == "bridge" and o.get("subnet") is None and o.get("bridge") == BR, json.dumps(o)[:160])
        rc, x = sudo("virsh", "-c", "qemu:///system", "net-dumpxml", net)
        rec("libvirt holds <forward mode='bridge'/> and the host bridge", "<forward mode='bridge'/>" in x and f"<bridge name='{BR}'/>" in x, x.replace("\n", "")[:200])
        rec("a second network on the same bridge is refused", submit("network_create", "VirtualNetwork", net + "x", {"bridge": BR}) == 409)

        # a VM on it: its NIC joins the bridge
        s, v = api.call("POST", "/api/v1/operations", {"type": "create", "kind": "VM", "id": vm, "idempotency_key": "b" + secrets.token_hex(12),
                                                        "create": {"vcpus": 1, "memory_mib": 1024, "image_id": a.image, "disk_gib": 10, "network": net, "ssh_public_key": open(a.key + ".pub").read().strip()}})
        ok = False
        if s == 202:
            end = time.time() + 300
            while time.time() < end:
                _, o2 = api.call("GET", f"/api/v1/operations/{v['id']}")
                if o2 and o2["status"] in ("succeeded", "failed", "cancelled"):
                    ok = o2["status"] == "succeeded"
                    break
                time.sleep(3)
        rec("create a VM on the bridge network", ok, f"HTTP {s}")
        ok, m = api.op_run("start", "VM", vm)
        rec("start it", ok, m)
        time.sleep(8)
        rc, ifs = sh(["ip", "-o", "link", "show", "master", BR])
        rec("the VM's interface is a port of the bridge", rc == 0 and "vnet" in ifs, ifs.strip()[:100])
        vmj = api.vm(vm)
        rec("Svavyom reports the network and no address it cannot know", bool(vmj) and vmj["observed"]["power"] == "running" and (vmj["observed"].get("network") or {}).get("name") == net and not vmj["observed"].get("ip_address"), json.dumps((vmj or {}).get("observed", {}).get("network"))[:100])
        rec("the running VM stops its network from being stopped", submit("network_stop", "VirtualNetwork", net) == 409)
        rec("the running VM stops its network from being deleted", submit("network_delete", "VirtualNetwork", net) == 409)
        rc, out = sudo(a.ctl, "bridge", "rollback", "--confirm-bridge", BR)
        rec("forgetting the bridge is refused while a network uses it", "BR_IN_USE" in out, out.strip()[:100])
        ok, m = api.op_run("stop", "VM", vm)
        if not ok:
            ok, m = api.op_run("force_off", "VM", vm)
        api.wait_vm(vm, "stopped", timeout=90)
        rec("network cannot be deleted under the VM", submit("network_delete", "VirtualNetwork", net) == 409)
    finally:
        if api.vm(vm):
            api.op_run("force_off", "VM", vm)
            api.wait_vm(vm, "stopped", timeout=60)
            ok, m = api.op_run("delete", "VM", vm)
            rec("cleanup: delete the VM", ok, m)
        s, _ = api.call("GET", f"/api/v1/virtual-networks/{net}")
        if s == 200:
            ok, m = api.op_run("network_delete", "VirtualNetwork", net)
            rec("cleanup: delete the network", ok, m)
        rc, out = sudo(a.ctl, "bridge", "rollback", "--confirm-bridge", BR)
        rec("forget the adopted bridge", rc == 0 and host_bridge() is None, out.strip()[:80])
        sudo("ip", "link", "del", BR)
        rc, route_after = sh(["ip", "-o", "route", "show", "default"])
        rc, links_after = sh(["ip", "-o", "link", "show"])
        rec("the host's default route is exactly as before", route_after == route_before)
        rec("no device was added or removed, the throwaway bridge is gone", sorted(l.split(":")[1].split("@")[0].strip() for l in links_before.splitlines() if "vnet" not in l) == sorted(l.split(":")[1].split("@")[0].strip() for l in links_after.splitlines() if "vnet" not in l))
        rc, doms = sudo("virsh", "-c", "qemu:///system", "list", "--all", "--name")
        rec("no VM left", not doms.strip(), doms.strip()[:60])
    bad = [r["id"] for r in R if r["status"] != "PASS"]
    print("RESULT", "PASS" if not bad else f"FAIL {bad}")
    return 0 if not bad else 1


if __name__ == "__main__":
    sys.exit(main())
