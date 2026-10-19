#!/usr/bin/env python3
"""Real-host qualification of the host bridge safe-adoption engine (M1-E03-S02, DR-024 D5), run in a NESTED guest. Stdlib only.

The bridge is never applied on the qualification host itself: this script creates one disposable Ubuntu VM through the installed Svavyom API, gives it a
static netplan configuration (the planner refuses DHCP uplinks), copies the svavyom-ctl binary in and exercises plan, apply, confirm, the countdown rollback,
a deliberately broken apply, a reboot during the countdown, and a manual rollback, checking from OUTSIDE the guest (ssh from the host) after each.

    python3 tools/qualify_bridge.py --base http://127.0.0.1:8443 --user certify --password-file PW --image ubuntu-24.04 --key KEY --ctl PATH_TO_SVAVYOM_CTL
"""
import argparse, os, re, secrets, subprocess, sys, time

sys.dont_write_bytecode = True
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from qualify_graphics import Api, rec, R, sh  # noqa: E402
import qualify_graphics as _qg  # noqa: E402


def ssh(key, ip, cmd, user="ubuntu", timeout=40):
    """A guest that does not answer is an answer here (the broken apply cuts it off), not a crash."""
    try:
        return _qg.ssh(key, ip, cmd, user=user, timeout=timeout)
    except subprocess.TimeoutExpired:
        return 255, "timeout"


CTL = "/usr/libexec/svavyom/svavyom-ctl"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", required=True)
    ap.add_argument("--user", required=True)
    ap.add_argument("--password-file", required=True)
    ap.add_argument("--image", required=True)
    ap.add_argument("--key", required=True)
    ap.add_argument("--ctl", required=True)
    ap.add_argument("--keep", action="store_true", help="do not delete the VM at the end")
    a = ap.parse_args()
    name = "brg-" + secrets.token_hex(3)
    api = Api(a.base, a.password_file, a.user)
    if not rec("sign-in", api.sign_in()):
        return 1
    pub = open(a.key + ".pub").read().strip()
    ip = ""

    def g(cmd, t=60):
        return ssh(a.key, ip, cmd, timeout=t)

    def up(timeout=90):
        end = time.time() + timeout
        while time.time() < end:
            if "up" in g("echo up", 15)[1]:
                return True
            time.sleep(3)
        return False

    def down(timeout=40):
        end = time.time() + timeout
        while time.time() < end:
            if "up" not in ssh(a.key, ip, "echo up", timeout=8)[1]:
                return True
            time.sleep(2)
        return False

    try:
        ok, m = api.op_run("create", "VM", name, create={"vcpus": 1, "memory_mib": 1024, "image_id": a.image, "disk_gib": 10, "ssh_public_key": pub})
        rec("create the nested guest", ok, m)
        ok, m = api.op_run("start", "VM", name)
        v = api.wait_vm(name, "running", ip=True)
        ip = v["observed"]["ip_address"] if v else ""
        rec("start and address", ok and bool(ip), ip)
        time.sleep(35)
        rec("SSH into the guest", up(120))

        # ---- give the guest a static configuration equal to its lease (the planner refuses DHCP uplinks on purpose)
        rc, out = g("ip -o -4 route show default; ip -o -4 addr show scope global")
        nic = re.search(r"default via (\S+) dev (\S+)", out)
        cidr = re.search(r"inet (\d+\.\d+\.\d+\.\d+/\d+)", out)
        if not rec("read the guest's uplink", bool(nic and cidr), out.strip()[:120]):
            return 1
        gw, dev, addr = nic.group(1), nic.group(2), cidr.group(1)
        static = f"network:\n version: 2\n ethernets:\n  {dev}:\n   dhcp4: false\n   addresses:\n    - {addr}\n   routes:\n   - to: default\n     via: {gw}\n   nameservers:\n    addresses:\n     - {gw}\n"
        rc, out = g("sudo sh -c 'echo network: {config: disabled} > /etc/cloud/cloud.cfg.d/99-disable-network-config.cfg; rm -f /etc/netplan/*.yaml'")
        p = subprocess.run(["ssh", "-i", a.key, "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null", "-o", "IdentitiesOnly=yes", f"ubuntu@{ip}",
                            "sudo tee /etc/netplan/01-static.yaml >/dev/null && sudo chmod 600 /etc/netplan/01-static.yaml && sudo netplan apply"], input=static, text=True, capture_output=True, timeout=60)
        time.sleep(5)
        rec("static netplan configuration in the guest", p.returncode == 0 and up(60), p.stderr.strip()[-100:])
        rc, original = g("sudo cat /etc/netplan/01-static.yaml")
        subprocess.run(["scp", "-i", a.key, "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null", "-o", "IdentitiesOnly=yes", a.ctl, f"ubuntu@{ip}:/tmp/svavyom-ctl"], capture_output=True, timeout=60)
        rc, out = g(f"sudo mkdir -p /usr/libexec/svavyom && sudo install -m 755 /tmp/svavyom-ctl {CTL} && {CTL} version")
        rec("svavyom-ctl in the guest", rc == 0, out.strip()[:80])

        def plan():
            rc, out = g(f"sudo {CTL} bridge plan")
            m = re.search(r"Plan ([0-9a-f]{12})", out)
            return (m.group(1) if m else None), out

        def apply_bg(pid, countdown, extra=""):
            g(f"sudo sh -c 'nohup sh -c \"{CTL} bridge apply --plan {pid} --confirm-bridge svbr0 --countdown {countdown}; {extra}\" >/tmp/apply.log 2>&1 &'", 20)

        def at_original():
            rc, out = g(f"ip -o -4 addr show dev {dev} scope global; ip -o link show svbr0 2>&1; sudo cat /etc/netplan/01-static.yaml")
            return addr in out and "does not exist" in out and out.rstrip().endswith(original.rstrip())

        # ---- 1. plan only reads
        pid, out = plan()
        rec("plan proposes svbr0 and shows the change", bool(pid) and "svbr0" in out and "+" in out, out.splitlines()[0][:100] if out else "")
        rc, st = g(f"sudo {CTL} bridge status")
        rec("plan is recorded (state planned)", "planned" in st, st.strip())
        rec("plan changed nothing", at_original())

        # ---- 2. refusals
        rc, out = g(f"sudo {CTL} bridge apply --plan {pid} --confirm-bridge wrong")
        rec("apply without the typed name is refused", "BR_NEEDS_CONFIRMATION" in out and at_original(), out.strip()[:100])
        rc, out = g(f"sudo {CTL} bridge apply --plan deadbeef0000 --confirm-bridge svbr0")
        rec("apply of an unknown plan is refused", "BR_NO_PLAN" in out and at_original(), out.strip()[:100])

        # ---- 3. apply and confirm
        apply_bg(pid, 120)
        time.sleep(12)
        rec("the guest is reachable on the same address through the bridge", up(60))
        rc, out = g(f"ip -o -4 addr show dev svbr0; ip -o link show {dev}; sudo {CTL} bridge status")
        rec("svbr0 carries the address, the uplink is its port, state pending", addr in out and "master svbr0" in out and "pending confirmation" in out, out.strip().replace("\n", " | ")[:200])
        rc, out = g(f"sudo {CTL} bridge apply --plan {pid} --confirm-bridge svbr0")
        rec("a second apply during the countdown is refused", "BR_BUSY" in out, out.strip()[:100])
        rc, out = g(f"sudo {CTL} bridge confirm")
        rec("confirm from a session on the new setup", rc == 0 and "Confirmed" in out, out.strip()[:100])
        rc, out = g("systemctl list-timers --all 2>&1 | grep -c svavyom-bridge-rollback; test -e /etc/systemd/system/svavyom-bridge-recover.service && echo unit-left")
        rec("confirm removed the rollback timer and the recovery unit", "unit-left" not in out and out.strip().startswith("0"), out.strip().replace("\n", " ")[:80])
        time.sleep(40)
        rec("a confirmed bridge stays after the countdown would have ended", up(30) and "svbr0" in g("ip -o link show svbr0")[1])
        g("sudo reboot", 10)
        time.sleep(8)
        rec("a confirmed bridge survives a reboot", up(150) and addr in g("ip -o -4 addr show dev svbr0")[1])

        # ---- 4. manual rollback of the confirmed bridge
        rc, out = g(f"sudo {CTL} bridge rollback")
        rec("rollback of a confirmed bridge needs the typed name", "BR_NEEDS_CONFIRMATION" in out, out.strip()[:100])
        g(f"sudo sh -c 'nohup {CTL} bridge rollback --confirm-bridge svbr0 >/tmp/rb.log 2>&1 &'", 20)
        time.sleep(10)
        rec("manual rollback returns exactly the original configuration", up(60) and at_original())

        # ---- 5. countdown rollback: nobody confirms
        pid, _ = plan()
        apply_bg(pid, 30)
        time.sleep(10)
        rec("bridge is up during the countdown", "svbr0" in g("ip -o link show svbr0")[1] if up(40) else False)
        time.sleep(40)
        rec("no confirmation: the old configuration returned by itself", up(60) and at_original())
        rc, out = g(f"sudo {CTL} bridge status")
        rec("state is back to none", "no bridge" in out, out.strip())

        # ---- 6. a broken apply: the new bridge loses connectivity, the timer must restore it
        pid, _ = plan()
        brk = "sleep 3\nnft add table inet brk\nnft add chain inet brk i '{ type filter hook input priority -100 ; policy accept ; }'\nnft add rule inet brk i iifname svbr0 drop\n"
        subprocess.run(["ssh", "-i", a.key, "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null", "-o", "IdentitiesOnly=yes", f"ubuntu@{ip}", "sudo tee /tmp/break.sh >/dev/null"],
                       input=brk, text=True, capture_output=True, timeout=30)
        apply_bg(pid, 40, extra="sh /tmp/break.sh")
        rec("the broken apply cut the guest off", down(40))
        t0 = time.time()
        rec("the guest came back by itself within the countdown", up(120) and at_original(), f"{int(time.time() - t0)} s after it went dark")

        # ---- 7. a reboot during the countdown (the cut-off rule of step 6 is removed first: it would block the bridge)
        g("sudo nft delete table inet brk")
        pid, _ = plan()
        boot0 = g("cat /proc/sys/kernel/random/boot_id")[1].strip()[:36]
        apply_bg(pid, 300)
        time.sleep(8)
        for _ in range(4):
            if "svbr0" in g("ip -o link show svbr0", 15)[1]:
                break
            time.sleep(3)
        for _ in range(3):
            g("sudo systemctl reboot", 10)
            if down(25):
                break
        time.sleep(8)
        came_back = up(180)
        boot1 = g("cat /proc/sys/kernel/random/boot_id")[1].strip()[:36] if came_back else ""
        rec("the guest really rebooted during the countdown", bool(boot1) and boot1 != boot0)
        rec("reboot during the countdown: the old configuration is back", came_back and at_original())
        rc, out = g(f"sudo {CTL} bridge status; test -e /etc/systemd/system/svavyom-bridge-recover.service && echo unit-left; ls /var/lib/svavyom/bridge 2>&1")
        rec("nothing left after the boot-time recovery", "no bridge" in out and "unit-left" not in out and "state.json" not in out, out.strip().replace("\n", " ")[:120])
    finally:
        if not a.keep:
            ok, m = api.op_run("force_off", "VM", name)
            api.wait_vm(name, "stopped", timeout=60)
            ok, m = api.op_run("delete", "VM", name)
            rec("cleanup: delete the guest", ok, m)
    bad = [r["id"] for r in R if r["status"] != "PASS"]
    print("RESULT", "PASS" if not bad else f"FAIL {bad}")
    return 0 if not bad else 1


if __name__ == "__main__":
    sys.exit(main())
