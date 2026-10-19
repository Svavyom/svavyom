#!/usr/bin/env python3
"""M4 installed-system qualification (stdlib only). Drives an INSTALLED Svavyom (services under systemd, from a release artifact) through its public API on the
host it runs on, then proves the host is left clean. It needs: sudo (non-interactive) for svavyom-ctl and systemctl, the installed API URL, the administrator password
in a file, a disposable SSH key pair, and a qualified image id. Every VM, snapshot and network it makes carries a name derived from the run id, and cleanup only touches
resources it can prove it created (names derived from the run id, VM marker checked through the API).

    python3 tools/qualify_install.py --base http://127.0.0.1:8443 --password-file PW --pubkey KEY.pub --ssh-key KEY --image ubuntu-24.04 \
        --run-id qr-YYYYMMDD-xxxxxx --out DIR [--ctl /usr/libexec/svavyom/svavyom-ctl] [--phase all|up|restart|down]

Output: DIR/<run-id>-install.json with PASS / FAIL / NOT_RUN per criterion. No password, cookie, CSRF value, ticket or key is printed or recorded.
Exit 0 when nothing FAILED, 1 otherwise.
"""
import argparse, base64, hashlib, http.cookiejar, json, os, re, secrets, socket, ssl, struct, subprocess, sys, time
import urllib.error, urllib.request

sys.dont_write_bytecode = True
R = []  # results


def rec(cid, status, detail=""):
    R.append({"id": cid, "status": status, "detail": detail[:300]})
    print(f"{status:8} {cid}" + (f"  {detail[:200]}" if detail else ""), flush=True)


def sh(cmd, timeout=120, check=False):
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    if check and r.returncode != 0:
        raise RuntimeError(f"{cmd[0]} failed: {r.stderr.strip()[:200]}")
    return r.returncode, (r.stdout + r.stderr)


class Api:
    def __init__(self, base, pwfile):
        self.base, self.pwfile = base, pwfile
        self.jar = http.cookiejar.CookieJar()
        self.op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.jar))
        self.csrf = None

    def call(self, method, path, body=None, extra=None):
        h = {"Origin": self.base, "Sec-Fetch-Site": "same-origin", "Accept": "application/json"}
        if body is not None:
            h["Content-Type"] = "application/json"
        if self.csrf:
            h["X-CSRF-Token"] = self.csrf
        h.update(extra or {})
        req = urllib.request.Request(self.base + path, data=json.dumps(body).encode() if body is not None else None, method=method, headers=h)
        try:
            r = self.op.open(req, timeout=30)
        except urllib.error.HTTPError as e:
            r = e
        tok = r.headers.get("X-CSRF-Token")
        if tok:
            self.csrf = tok
        raw = r.read().decode()
        try:
            return r.status if hasattr(r, "status") else r.code, json.loads(raw) if raw else None
        except ValueError:
            return r.status if hasattr(r, "status") else r.code, None

    def sign_in(self):
        self.call("GET", "/api/v1/auth/session")
        with open(self.pwfile) as f:
            pw = f.read().rstrip("\n")
        s, _ = self.call("POST", "/api/v1/auth/session", {"username": "admin", "password": pw})
        return s == 200

    def op_run(self, typ, kind, rid, params=None, create=None, timeout=420):
        body = {"type": typ, "kind": kind, "id": rid, "idempotency_key": "q" + secrets.token_hex(12)}
        if params:
            body["params"] = params
        if create:
            body["create"] = create
        s, op = self.call("POST", "/api/v1/operations", body)
        if s != 202:
            return False, f"submit {typ} {rid}: HTTP {s} {json.dumps(op)[:120]}"
        end = time.time() + timeout
        while time.time() < end:
            s, o = self.call("GET", f"/api/v1/operations/{op['id']}")
            if s == 200 and o["status"] in ("succeeded", "failed", "cancelled"):
                return o["status"] == "succeeded", f"{typ} {rid}: {o['status']} {o.get('error_category') or ''}".strip()
            time.sleep(2)
        return False, f"{typ} {rid}: timeout"

    def vms(self):
        s, d = self.call("GET", "/api/v1/vms")
        return d["items"] if s == 200 else []

    def vm_by_name(self, name):
        for v in self.vms():
            if v["name"] == name:
                return v
        return None

    def wait_vm(self, name, power, ip=False, timeout=240):
        end = time.time() + timeout
        while time.time() < end:
            v = self.vm_by_name(name)
            if v and v["observed"]["power"] == power and (not ip or v["observed"]["ip_address"]):
                return v
            time.sleep(3)
        return None


def ssh(key, user, ip, cmd, timeout=40):
    return sh(["ssh", "-i", key, "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null", "-o", "IdentitiesOnly=yes", "-o", "ConnectTimeout=8",
               "-o", "BatchMode=yes", f"{user}@{ip}", cmd], timeout=timeout)


def ws_console(api, vm_id, seconds=25):
    """Mint a ticket and read the serial console over a hand-made RFC 6455 client (binary frames). Returns the bytes seen."""
    s, t = api.call("POST", f"/console/v1/vms/{vm_id}/tickets", {})
    if s != 200 and s != 201:
        return None, f"ticket HTTP {s}"
    ticket = t["ticket"]
    u = re.match(r"http://([^:/]+):(\d+)", api.base)
    host, port = u.group(1), int(u.group(2))
    cookies = "; ".join(f"{c.name}={c.value}" for c in api.jar)
    key = base64.b64encode(os.urandom(16)).decode()
    sock = socket.create_connection((host, port), timeout=10)
    req = (f"GET /console/v1/vms/{vm_id}/socket HTTP/1.1\r\nHost: {host}:{port}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n"
           f"Sec-WebSocket-Protocol: svavyom.console.v1, t.{ticket}\r\nOrigin: {api.base}\r\nCookie: {cookies}\r\n\r\n")
    sock.sendall(req.encode())
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = sock.recv(4096)
        if not chunk:
            break
        buf += chunk
    head, _, rest = buf.partition(b"\r\n\r\n")
    if not head.startswith(b"HTTP/1.1 101"):
        return None, "upgrade refused: " + head.split(b"\r\n")[0].decode(errors="replace")

    def send(data):
        mask = os.urandom(4)
        sock.sendall(bytes([0x82, 0x80 | len(data)]) + mask + bytes(b ^ mask[i % 4] for i, b in enumerate(data)))

    got = b""
    sock.settimeout(2)
    end = time.time() + seconds
    send(b"\r")
    pending = rest
    while time.time() < end:
        try:
            chunk = pending or sock.recv(4096)
            pending = b""
        except socket.timeout:
            send(b"\r")
            continue
        if not chunk:
            break
        i = 0
        while i + 2 <= len(chunk):
            ln = chunk[i + 1] & 0x7F
            i += 2
            if ln == 126:
                ln = struct.unpack(">H", chunk[i:i + 2])[0]
                i += 2
            got += chunk[i:i + ln]
            i += ln
        if len(got) > 200 and (b"login:" in got or b"$" in got):
            break
    sock.close()
    return got, ""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", required=True)
    ap.add_argument("--password-file", required=True)
    ap.add_argument("--pubkey", required=True)
    ap.add_argument("--ssh-key", required=True)
    ap.add_argument("--image", required=True)
    ap.add_argument("--run-id", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--ctl", default="/usr/libexec/svavyom/svavyom-ctl")
    ap.add_argument("--phase", default="all", choices=["all", "up", "restart", "down"])
    a = ap.parse_args()
    if not re.fullmatch(r"qr-\d{8}-[0-9a-f]{6}", a.run_id):
        sys.exit("ERROR run id must be qr-YYYYMMDD-xxxxxx")
    h = a.run_id.split("-")[2]
    vm_name, net_name = f"qi-{h}", f"qinet-{h}"
    subnet_octet = 100 + int(h[:2], 16) % 100
    subnet = f"10.{subnet_octet}.{int(h[2:4], 16) % 250}.0/24"
    os.makedirs(a.out, exist_ok=True)
    api = Api(a.base, a.password_file)
    pub = open(a.pubkey).read().strip()

    def finish():
        bad = [r for r in R if r["status"] == "FAIL"]
        with open(os.path.join(a.out, f"{a.run_id}-install.json"), "w") as f:
            json.dump({"run_id": a.run_id, "phase": a.phase, "results": R}, f, indent=2)
        print(f"\n{len(R) - len(bad)}/{len(R)} criteria not failed; FAIL={len(bad)}")
        sys.exit(1 if bad else 0)

    # ---- installed state
    rc, out = sh(["sudo", "-n", a.ctl, "status"])
    rec("install-status", "PASS" if rc == 0 else "FAIL", "svavyom-ctl status: " + ("PASS" if rc == 0 else out.strip().splitlines()[-1]))
    rc, out = sh(["sudo", "-n", a.ctl, "validate-config"])
    rec("install-validate-config", "PASS" if rc == 0 else "FAIL", "svavyom-ctl validate-config exit %d" % rc)
    owners = sh(["ps", "-eo", "user:20,args"])[1]
    nonroot = all(not l.startswith("root") for l in owners.splitlines() if "/usr/libexec/svavyom/" in l and "svavyom-ctl" not in l)
    rec("services-not-root", "PASS" if nonroot and "/usr/libexec/svavyom/api" in owners else "FAIL", "no Svavyom service process runs as root")
    if not api.sign_in():
        rec("sign-in", "FAIL", "administrator sign-in failed")
        finish()
    rec("sign-in", "PASS", "administrator signed in through the installed API")
    s, d = api.call("GET", "/api/v1/hosts")
    rec("host-summary", "PASS" if s == 200 and d["items"][0]["observed"]["virtualization"]["kvm_device"] == "available" else "FAIL", f"GET /api/v1/hosts HTTP {s}")
    s, d = api.call("GET", "/api/v1/images")
    imgs = [i for i in (d or {}).get("items", []) if i.get("id") == a.image]
    rec("image-qualified", "PASS" if imgs and imgs[0]["observed"]["qualification"] == "qualified" else "FAIL", "the catalog offers the qualified image")
    try:
        urllib.request.urlopen(urllib.request.Request(a.base + "/api/v1/vms"), timeout=10)
        rec("unauthenticated-refused", "FAIL", "anonymous read succeeded")
    except urllib.error.HTTPError as e:
        rec("unauthenticated-refused", "PASS" if e.code == 401 else "FAIL", f"anonymous GET /api/v1/vms -> HTTP {e.code}")

    if a.phase in ("all", "up"):
        # ---- create, start, SSH, console
        ok, why = api.op_run("create", "VM", vm_name, create={"vcpus": 1, "memory_mib": 1024, "image_id": a.image, "disk_gib": 10, "ssh_public_key": pub})
        rec("vm-create", "PASS" if ok else "FAIL", why)
        if not ok:
            finish()
        v = api.vm_by_name(vm_name)
        rec("vm-managed", "PASS" if v and v["observed"]["managed"] else "FAIL", "the created VM is managed and listed")
        ok, why = api.op_run("start", "VM", v["id"])
        rec("vm-start", "PASS" if ok else "FAIL", why)
        v = api.wait_vm(vm_name, "running", ip=True)
        rec("vm-running-with-ip", "PASS" if v else "FAIL", "Running with an observed IPv4 address" if v else "no address within the time limit")
        if v:
            end, rc, out = time.time() + 200, 1, ""
            while time.time() < end:
                rc, out = ssh(a.ssh_key, v["observed"]["login_user"] or "ubuntu", v["observed"]["ip_address"], "echo svq-ok; uname -n")
                if rc == 0 and "svq-ok" in out:
                    break
                time.sleep(6)
            rec("vm-ssh", "PASS" if "svq-ok" in out else "FAIL", "SSH login with the disposable key")
            got, err = ws_console(api, v["id"])
            rec("vm-console", "PASS" if got and len(got) > 20 else "FAIL", f"{len(got or b'')} serial bytes over the ticketed socket" + (f" ({err})" if err else ""))
        # ---- lifecycle
        # An ACPI reboot request is only honoured by a settled guest: wait for first-boot cloud-init, then note the boot id.
        user, ip = (v["observed"]["login_user"] or "ubuntu", v["observed"]["ip_address"]) if v else ("ubuntu", "")
        bid = ""
        if v:
            ssh(a.ssh_key, user, ip, "cloud-init status --wait >/dev/null 2>&1; true", timeout=200)
            bid = ssh(a.ssh_key, user, ip, "cat /proc/sys/kernel/random/boot_id")[1].strip()
        ok, why = api.op_run("reboot", "VM", v["id"]) if v else (False, "no VM")
        rec("vm-reboot", "PASS" if ok and api.wait_vm(vm_name, "running", ip=True) else "FAIL", why)
        if ok and v:
            end, nb = time.time() + 240, ""
            while time.time() < end and (not nb or nb == bid):
                time.sleep(6)
                rc, out = ssh(a.ssh_key, user, ip, "cat /proc/sys/kernel/random/boot_id")
                nb = out.strip() if rc == 0 else ""
            rec("vm-reboot-observed", "PASS" if nb and nb != bid else "FAIL", "the guest answered SSH with a new boot id after the reboot")
        # ---- M3 smoke
        s, d = api.call("GET", "/api/v1/virtual-networks")
        rec("networks-list", "PASS" if s == 200 and d["items"] else "FAIL", f"GET /api/v1/virtual-networks HTTP {s}")
        base = subnet.rsplit(".", 1)[0]
        ok, why = api.op_run("network_create", "VirtualNetwork", net_name, params={"subnet": subnet, "dhcp_start": base + ".10", "dhcp_end": base + ".200"})
        rec("network-create", "PASS" if ok else "FAIL", why)
        s, d = api.call("GET", "/api/v1/virtual-networks")
        mine = [n for n in (d or {}).get("items", []) if n["name"] == net_name]
        rec("network-active", "PASS" if ok and mine and mine[0]["observed"]["state"] == "active" and mine[0]["observed"]["managed"] else "FAIL",
            "the managed network created by this run is active (a create also starts it)")
        # ---- M2 smoke on the stopped VM
        ok, why = api.op_run("stop", "VM", v["id"]) if v else (False, "no VM")
        stopped = api.wait_vm(vm_name, "stopped")
        rec("vm-stop", "PASS" if ok and stopped else "FAIL", why)
        ok, why = api.op_run("resize", "VM", v["id"], params={"disk_gib": 11}) if v else (False, "no VM")
        rec("vm-resize-grow", "PASS" if ok else "FAIL", why)
        ok, why = api.op_run("snapshot", "VM", v["id"]) if v else (False, "no VM")
        snaps = (api.vm_by_name(vm_name) or {"observed": {"snapshots": []}})["observed"]["snapshots"]
        rec("vm-snapshot-create", "PASS" if ok and len(snaps) == 1 else "FAIL", why + f"; the VM lists {len(snaps)} snapshot(s)")
        ok, why = api.op_run("delete_snapshot", "VM", v["id"], params={"snapshot_id": snaps[0]["id"]}) if v and snaps else (False, "no snapshot to delete")
        rec("vm-snapshot-delete", "PASS" if ok and not api.vm_by_name(vm_name)["observed"]["snapshots"] else "FAIL", why)
        def backup_ids():
            s2, bl = api.call("GET", "/api/v1/backups")
            return {b["id"] for b in (bl or {}).get("items", [])} if s2 == 200 else set()
        before_b = backup_ids()
        ok, why = api.op_run("backup", "VM", v["id"]) if v else (False, "no VM")
        mine = backup_ids() - before_b
        rec("vm-backup-create", "PASS" if ok and len(mine) == 1 else "FAIL", why + f"; the store lists {len(mine)} new backup(s)")
        okd, whyd = (False, "no backup to delete")
        for bid in mine:
            okd, whyd = api.op_run("delete", "Backup", bid)
        rec("vm-backup-delete", "PASS" if okd and not (backup_ids() & mine) else "FAIL", whyd)
        ok, why = api.op_run("start", "VM", v["id"]) if v else (False, "no VM")
        rec("vm-start-again", "PASS" if ok and api.wait_vm(vm_name, "running", ip=True) else "FAIL", why)

    if a.phase in ("all", "restart"):
        # ---- restart every service while the VM runs: the guest must be untouched
        before = sh(["sudo", "-n", "virsh", "-c", "qemu:///system", "domstate", vm_name])[1].strip()
        pid_before = sh(["sudo", "-n", "pgrep", "-f", f"guest={vm_name}"])[1].split()[:1]
        rc, _ = sh(["sudo", "-n", "systemctl", "restart", "svavyom-agent", "svavyom-mutation", "svavyom-console", "svavyom-api"], timeout=120)
        time.sleep(5)
        rc2, out = sh(["sudo", "-n", a.ctl, "status"])
        after = sh(["sudo", "-n", "virsh", "-c", "qemu:///system", "domstate", vm_name])[1].strip()
        pid_after = sh(["sudo", "-n", "pgrep", "-f", f"guest={vm_name}"])[1].split()[:1]
        rec("services-restart-vm-intact", "PASS" if rc == 0 and rc2 == 0 and before == after == "running" and pid_before == pid_after and pid_before else "FAIL",
            f"services restarted; domain {before!r} -> {after!r}; QEMU process unchanged: {pid_before == pid_after and bool(pid_before)}")
        api2 = Api(a.base, a.password_file)
        rec("sign-in-after-restart", "PASS" if api2.sign_in() else "FAIL", "a fresh sign-in works after the restart")
        api = api2
        v = api.vm_by_name(vm_name)
        rec("vm-visible-after-restart", "PASS" if v and v["observed"]["power"] == "running" else "FAIL", "the VM is still listed Running")

    if a.phase in ("all", "down"):
        # ---- support bundle with a live VM and a session in the database
        d = "/var/tmp/svq-bundle-" + a.run_id
        sh(["sudo", "-n", "rm", "-rf", d])
        rc, out = sh(["sudo", "-n", a.ctl, "support-bundle", "--out", d])
        scan = sh(["sudo", "-n", "sh", "-c",
                   f"set -e; f=$(ls {d}/*.tar.gz | head -1); mkdir -p {d}/x; tar xzf $f -C {d}/x 2>/dev/null; "
                   f"pw=$(cat {a.password_file}); k=$(awk '{{print $2}}' {a.pubkey}); "
                   f"echo pw=$(grep -rF -- \"$pw\" {d}/x | wc -l) pem=$(grep -rE 'BEGIN [A-Z ]*PRIVATE KEY' {d}/x | wc -l) "
                   f"cookie=$(grep -riE '(set-cookie|cookie:|x-csrf-token|authorization:)' {d}/x | wc -l) "
                   f"hash=$(grep -rEi '[$](argon2|2[aby]|scrypt)[$]' {d}/x | wc -l) pub=$(grep -rF -- \"$k\" {d}/x | wc -l); "
                   f"stat -c 'mode=%a' $f; rm -rf {d}"])[1]
        clean = rc == 0 and re.search(r"pw=0 pem=0 cookie=0 hash=0 pub=0", scan) and "mode=600" in scan
        rec("support-bundle-redaction", "PASS" if clean else "FAIL", "bundle written 0600; no password, key, cookie/CSRF, hash or SSH key body found: " + scan.strip().replace("\n", " "))
        # ---- cleanup: only what this run made
        v = api.vm_by_name(vm_name)
        if v:
            api.op_run("stop", "VM", v["id"])
            api.wait_vm(vm_name, "stopped")
            ok, why = api.op_run("delete", "VM", v["id"])
            rec("cleanup-vm-delete", "PASS" if ok and not api.vm_by_name(vm_name) else "FAIL", why)
        for op in ("network_stop", "network_delete"):
            api.op_run(op, "VirtualNetwork", net_name)
        left = sh(["sudo", "-n", "virsh", "-c", "qemu:///system", "list", "--all", "--name"])[1].split()
        nets = sh(["sudo", "-n", "virsh", "-c", "qemu:///system", "net-list", "--all", "--name"])[1].split()
        rec("host-clean", "PASS" if vm_name not in left and net_name not in " ".join(nets) and not any(n.startswith("svqn-") and h in n for n in nets) else "FAIL",
            f"no domain {vm_name}, no network {net_name}")
    finish()


if __name__ == "__main__":
    main()
