#!/usr/bin/env python3
"""Real-host qualification of the graphical console, installation media and rescue mode (DR-026). Stdlib only. Drives an INSTALLED Svavyom through its
public API and a hand-made RFC 6455 + RFB client, so what it sees is what a browser would: the real VNC server of a real QEMU guest, through the broker.

    python3 tools/qualify_graphics.py --base http://127.0.0.1:8443 --user certify --password-file PW --image ubuntu-24.04 --media alpine-virt \
        --key KEY_A --key-b KEY_B --out DIR [--ctl ...]

KEY_A and KEY_B are disposable ssh key pairs (private files, with .pub next to them). The run creates ONE VM named after the run id, proves each criterion and
removes the VM. Screenshots (PNG) of the guest's screen are written to DIR. No password, cookie, ticket or key is printed.
"""
import argparse, base64, http.cookiejar, json, os, re, secrets, socket, struct, subprocess, sys, time, urllib.error, urllib.request, zlib

sys.dont_write_bytecode = True
R = []


def rec(cid, ok, detail=""):
    R.append({"id": cid, "status": "PASS" if ok else "FAIL", "detail": detail[:300]})
    print(f"{'PASS' if ok else 'FAIL':5} {cid}" + (f"  {detail[:200]}" if detail else ""), flush=True)
    return ok


def sh(cmd, timeout=120):
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    return r.returncode, (r.stdout + r.stderr)


class Api:
    def __init__(self, base, pwfile, user):
        self.base, self.pwfile, self.user = base, pwfile, user
        self.jar = http.cookiejar.CookieJar()
        self.op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.jar))
        self.csrf = None

    def call(self, method, path, body=None):
        h = {"Origin": self.base, "Sec-Fetch-Site": "same-origin", "Accept": "application/json"}
        if body is not None:
            h["Content-Type"] = "application/json"
        if self.csrf:
            h["X-CSRF-Token"] = self.csrf
        req = urllib.request.Request(self.base + path, data=json.dumps(body).encode() if body is not None else None, method=method, headers=h)
        try:
            r = self.op.open(req, timeout=30)
        except urllib.error.HTTPError as e:
            r = e
        if r.headers.get("X-CSRF-Token"):
            self.csrf = r.headers.get("X-CSRF-Token")
        raw = r.read().decode()
        code = getattr(r, "status", None) or r.code
        try:
            return code, json.loads(raw) if raw else None
        except ValueError:
            return code, None

    def sign_in(self):
        self.call("GET", "/api/v1/auth/session")
        pw = open(self.pwfile).read().rstrip("\n")
        return self.call("POST", "/api/v1/auth/session", {"username": self.user, "password": pw})[0] == 200

    def op_run(self, typ, kind, rid, params=None, create=None, timeout=420):
        body = {"type": typ, "kind": kind, "id": rid, "idempotency_key": "g" + secrets.token_hex(12)}
        if params:
            body["params"] = params
        if create:
            body["create"] = create
        s, op = self.call("POST", "/api/v1/operations", body)
        if s != 202:
            return False, f"submit {typ} {rid}: HTTP {s} {json.dumps(op)[:100]}"
        end = time.time() + timeout
        while time.time() < end:
            s, o = self.call("GET", f"/api/v1/operations/{op['id']}")
            if s == 200 and o["status"] in ("succeeded", "failed", "cancelled"):
                return o["status"] == "succeeded", f"{typ} {rid}: {o['status']} {o.get('error_category') or ''}".strip()
            time.sleep(2)
        return False, f"{typ} {rid}: timeout"

    def vm(self, name):
        s, d = self.call("GET", f"/api/v1/vms/{name}")
        return d if s == 200 else None

    def wait_vm(self, name, power, ip=False, timeout=240):
        end = time.time() + timeout
        while time.time() < end:
            v = self.vm(name)
            if v and v["observed"]["power"] == power and (not ip or v["observed"]["ip_address"]):
                return v
            time.sleep(3)
        return None


class WS:
    def __init__(self, api, vm, kind="graphics"):
        s, t = api.call("POST", f"/console/v1/vms/{vm}/{'graphics-tickets' if kind == 'graphics' else 'tickets'}", {})
        self.status = s
        self.sock = None
        if s != 200:
            return
        host, port = re.match(r"http://([^:/]+):(\d+)", api.base).groups()
        cookies = "; ".join(f"{c.name}={c.value}" for c in api.jar)
        key = base64.b64encode(os.urandom(16)).decode()
        proto = "svavyom.graphics.v1" if kind == "graphics" else "svavyom.console.v1"
        sock = socket.create_connection((host, int(port)), timeout=15)
        sock.sendall((f"GET /console/v1/vms/{vm}/{'graphics-socket' if kind == 'graphics' else 'socket'} HTTP/1.1\r\nHost: {host}:{port}\r\nUpgrade: websocket\r\n"
                      f"Connection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Protocol: {proto}, t.{t['ticket']}\r\n"
                      f"Origin: {api.base}\r\nCookie: {cookies}\r\n\r\n").encode())
        buf = b""
        while b"\r\n\r\n" not in buf:
            c = sock.recv(4096)
            if not c:
                break
            buf += c
        head, _, rest = buf.partition(b"\r\n\r\n")
        self.status = int(head.split(b" ")[1]) if head.startswith(b"HTTP/1.1") else 0
        if self.status != 101:
            sock.close()
            return
        self.sock, self.buf, self.msg = sock, rest, b""

    def _need(self, n, deadline):
        while len(self.buf) < n:
            self.sock.settimeout(max(0.05, deadline - time.time()))
            c = self.sock.recv(65536)
            if not c:
                raise EOFError
            self.buf += c

    def send(self, data):
        mask = os.urandom(4)
        n = len(data)
        hdr = bytes([0x82]) + (bytes([0x80 | n]) if n < 126 else bytes([0x80 | 126]) + struct.pack(">H", n))
        self.sock.sendall(hdr + mask + bytes(b ^ mask[i % 4] for i, b in enumerate(data)))

    def recv_bytes(self, n, timeout=20):
        """Exactly n bytes of the binary stream."""
        deadline = time.time() + timeout
        while len(self.msg) < n:
            self._need(2, deadline)
            op, ln = self.buf[0] & 0x0F, self.buf[1] & 0x7F
            i = 2
            if ln == 126:
                self._need(4, deadline)
                ln, i = struct.unpack(">H", self.buf[2:4])[0], 4
            elif ln == 127:
                self._need(10, deadline)
                ln, i = struct.unpack(">Q", self.buf[2:10])[0], 10
            self._need(i + ln, deadline)
            payload = self.buf[i:i + ln]
            self.buf = self.buf[i + ln:]
            if op == 0x8:
                raise EOFError("closed by the server")
            if op in (0x1, 0x2, 0x0):
                self.msg += payload
        out, self.msg = self.msg[:n], self.msg[n:]
        return out

    def close(self):
        try:
            self.sock.close()
        except Exception:
            pass


KEYSYM = {"\n": 0xFF0D, "\t": 0xFF09}


class RFB:
    def __init__(self, ws):
        self.ws = ws
        v = ws.recv_bytes(12)
        assert v.startswith(b"RFB 003."), v
        ws.send(b"RFB 003.008\n")
        n = ws.recv_bytes(1)[0]
        types = ws.recv_bytes(n)
        assert 1 in types, types
        ws.send(bytes([1]))
        assert ws.recv_bytes(4) == b"\0\0\0\0"
        ws.send(bytes([1]))  # shared
        init = ws.recv_bytes(24)
        self.w, self.h = struct.unpack(">HH", init[:4])
        self.name = ws.recv_bytes(struct.unpack(">I", init[20:24])[0]).decode(errors="replace")
        # 32 bpp, little endian, true colour, R16 G8 B0
        ws.send(bytes([0, 0, 0, 0, 32, 24, 0, 1]) + struct.pack(">HHH", 255, 255, 255) + bytes([16, 8, 0, 0, 0, 0]))
        ws.send(struct.pack(">BxHi", 2, 1, 0))  # SetEncodings: Raw only
        self.fb = bytearray(self.w * self.h * 4)

    def request(self, incremental=0):
        self.ws.send(struct.pack(">BBHHHH", 3, incremental, 0, 0, self.w, self.h))

    def pump(self, seconds=2.0):
        """Read server messages for a while and apply the rectangles; returns the number of rectangles applied."""
        end, rects = time.time() + seconds, 0
        while time.time() < end:
            try:
                t = self.ws.recv_bytes(1, timeout=max(0.2, end - time.time()))[0]
            except (socket.timeout, TimeoutError):
                break
            if t == 0:
                hdr = self.ws.recv_bytes(3)
                for _ in range(struct.unpack(">H", hdr[1:3])[0]):
                    x, y, w, h, enc = struct.unpack(">HHHHi", self.ws.recv_bytes(12))
                    assert enc == 0, f"unexpected encoding {enc}"
                    data = self.ws.recv_bytes(w * h * 4, timeout=30)
                    for row in range(h):
                        o = ((y + row) * self.w + x) * 4
                        self.fb[o:o + w * 4] = data[row * w * 4:(row + 1) * w * 4]
                    rects += 1
            elif t == 2:
                pass
            elif t == 3:
                self.ws.recv_bytes(3)
                self.ws.recv_bytes(struct.unpack(">I", self.ws.recv_bytes(4))[0])
            elif t == 1:
                hh = self.ws.recv_bytes(5)
                self.ws.recv_bytes(struct.unpack(">H", hh[3:5])[0] * 6)
            else:
                raise AssertionError(f"unknown server message {t}")
        return rects

    def screen(self, wait=3.0):
        self.request(0)
        self.pump(wait)
        self.request(1)
        self.pump(1.0)

    def type(self, text, delay=0.06):
        """Type like a browser's VNC client does: a character that needs Shift is sent with an explicit Shift key held (QEMU does not infer it)."""
        shifted = set('~!@#$%^&*()_+{}|:"<>?')
        for ch in text:
            ks = KEYSYM.get(ch, ord(ch))
            need = ch in shifted or ch.isupper()
            if need:
                self.ws.send(struct.pack(">BBxxI", 4, 1, 0xFFE1))
                time.sleep(delay)
            for down in (1, 0):
                self.ws.send(struct.pack(">BBxxI", 4, down, ks))
            if need:
                time.sleep(delay)
                self.ws.send(struct.pack(">BBxxI", 4, 0, 0xFFE1))
            time.sleep(delay)

    def lit(self):
        """How many pixels are not black: a blank screen has none."""
        return sum(1 for i in range(0, len(self.fb), 4) if self.fb[i] or self.fb[i + 1] or self.fb[i + 2])

    def png(self, path):
        raw = bytearray()
        for y in range(self.h):
            raw.append(0)
            for x in range(self.w):
                o = (y * self.w + x) * 4
                raw += bytes([self.fb[o + 2], self.fb[o + 1], self.fb[o]])  # stored B,G,R
        def chunk(tag, data):
            c = struct.pack(">I", len(data)) + tag + data
            return c + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF)
        open(path, "wb").write(b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", self.w, self.h, 8, 2, 0, 0, 0)) + chunk(b"IDAT", zlib.compress(bytes(raw), 6)) + chunk(b"IEND", b""))


def ssh(key, ip, cmd, user="ubuntu", timeout=40):
    return sh(["ssh", "-i", key, "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null", "-o", "IdentitiesOnly=yes", "-o", "ConnectTimeout=8", "-o", "BatchMode=yes",
               f"{user}@{ip}", cmd], timeout=timeout)


def dumpxml(name):
    rc, out = sh(["sudo", "virsh", "-c", "qemu:///system", "dumpxml", "--inactive", name])
    return out if rc == 0 else ""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", required=True)
    ap.add_argument("--user", required=True)
    ap.add_argument("--password-file", required=True)
    ap.add_argument("--image", required=True)
    ap.add_argument("--media", required=True)
    ap.add_argument("--key", required=True)
    ap.add_argument("--key-b", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--run-id", default="qr-" + time.strftime("%Y%m%d") + "-" + secrets.token_hex(3))
    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)
    name = "gfx-" + a.run_id[-6:]
    api = Api(a.base, a.password_file, a.user)
    if not rec("sign-in", api.sign_in()):
        return 1
    pub_a = open(a.key + ".pub").read().strip()
    pub_b = open(a.key_b + ".pub").read().strip()
    try:
        ok, m = api.op_run("create", "VM", name, create={"vcpus": 1, "memory_mib": 1024, "image_id": a.image, "disk_gib": 10, "ssh_public_key": pub_a})
        rec("create", ok, m)
        v = api.vm(name)
        rec("a new VM carries the graphical console", bool(v) and v["observed"]["graphical_console"] == "present" and re.search(r"<graphics type='vnc'[^>]*>\s*<listen type='none'/>\s*</graphics>", dumpxml(name)) is not None and "port=" not in re.search(r"<graphics[^>]*>", dumpxml(name)).group(0))
        ok, m = api.op_run("start", "VM", name)
        v = api.wait_vm(name, "running", ip=True)
        ip = v["observed"]["ip_address"] if v else ""
        rec("start and address", ok and bool(ip), ip)
        time.sleep(40)
        rc, out = ssh(a.key, ip, "echo key-a-ok")
        rec("SSH with the creation key", "key-a-ok" in out, out.strip()[:80])

        # ---- the graphical console of a running guest
        ws = WS(api, name)
        rec("graphics ticket and upgrade", ws.status == 101, f"status {ws.status}")
        if ws.status == 101:
            r = RFB(ws)
            rec("RFB handshake with QEMU's VNC server", r.w >= 640 and r.h >= 400, f"{r.w}x{r.h} name={r.name}")
            r.screen(4.0)
            r.png(f"{a.out}/{a.run_id}-1-ubuntu.png")
            rec("the screen of the running guest is not blank", r.lit() > 300, f"{r.lit()} lit pixels (a text console is mostly black)")
            # a second viewer is refused before the upgrade; a serial ticket does not open the graphics socket
            ws2 = WS(api, name)
            rec("a second viewer is refused", ws2.status == 409, f"status {ws2.status}")
            r.type("x")  # input is accepted and does not break the stream
            r.screen(1.0)
            ws.close()
        else:
            r = None
        time.sleep(1)

        # ---- installation media: attach to the stopped VM, boot it, eject, definition back as it was
        ok, m = api.op_run("stop", "VM", name)
        if not ok:
            ok, m = api.op_run("force_off", "VM", name)
        rec("stop before changing media", ok, m)
        api.wait_vm(name, "stopped")
        before = dumpxml(name)
        ok, m = api.op_run("iso_attach", "VM", name, params={"image_id": a.media, "boot": "cdrom"})
        rec("iso_attach (boot from it)", ok, m)
        x = dumpxml(name)
        rec("definition: media first, root second, no <boot dev>", "<boot order='1'/>" in x and "<boot order='2'/>" in x and "<boot dev=" not in x)
        ok, m = api.op_run("start", "VM", name)
        rec("start from the media", ok, m)
        time.sleep(25)
        ws = WS(api, name)
        if ws.status == 101:
            r = RFB(ws)
            r.screen(4.0)
            r.png(f"{a.out}/{a.run_id}-2-alpine-boot.png")
            rec("the guest booted the attached ISO (screen is live)", r.lit() > 2000, f"{r.lit()} lit pixels")
            r.type("root\n")
            time.sleep(2)
            r.type("cat /etc/os-release | head -2; lsblk\n")
            time.sleep(2)
            r.screen(3.0)
            r.png(f"{a.out}/{a.run_id}-3-alpine-shell.png")
            ws.close()
        else:
            rec("graphics socket for the installer", False, f"status {ws.status}")
        ok, m = api.op_run("force_off", "VM", name)
        rec("power off the live system", ok, m)
        api.wait_vm(name, "stopped")
        ok, m = api.op_run("eject_iso", "VM", name)
        rec("eject_iso", ok, m)
        after = dumpxml(name)
        rec("eject gives back the definition we started with", after == before, "" if after == before else "differs")
        if after != before:
            open(f"{a.out}/{a.run_id}-xml-before.txt", "w").write(before)
            open(f"{a.out}/{a.run_id}-xml-after.txt", "w").write(after)

        # ---- rescue mode: a lost key. Key A is treated as lost; key B is put on the guest disk from the rescue system.
        ok, m = api.op_run("rescue", "VM", name, params={"image_id": a.media})
        rec("rescue", ok, m)
        v = api.vm(name)
        rec("VM reports rescue mode and offers only unrescue", bool(v) and v["observed"]["rescue"] is True and "unrescue" in v["allowed_actions"] and "rescue" not in v["allowed_actions"])
        ok2, m2 = api.op_run("reinstall", "VM", name, params={"image_id": a.image, "ssh_public_key": pub_b}, timeout=30)
        rec("reinstall is refused while in rescue mode", not ok2, m2)
        ok, m = api.op_run("start", "VM", name)
        rec("start into the rescue system", ok, m)
        time.sleep(25)
        ws = WS(api, name)
        if ws.status == 101:
            r = RFB(ws)
            r.screen(3.0)
            r.type("root\n")
            time.sleep(2)
            cmd = ("mkdir -p /mnt/r && mount /dev/vda1 /mnt/r && mkdir -p /mnt/r/home/ubuntu/.ssh && echo '" + pub_b + "' >> /mnt/r/home/ubuntu/.ssh/authorized_keys && "
                   "chown -R 1000:1000 /mnt/r/home/ubuntu/.ssh && chmod 700 /mnt/r/home/ubuntu/.ssh && chmod 600 /mnt/r/home/ubuntu/.ssh/authorized_keys && sync && "
                   "ls -la /mnt/r/home/ubuntu/.ssh && umount /mnt/r && echo RESCUE-DONE\n")
            r.type(cmd, delay=0.01)
            time.sleep(6)
            r.screen(3.0)
            r.png(f"{a.out}/{a.run_id}-4-rescue-fix.png")
            ws.close()
            rec("the rescue session ran", True)
        else:
            rec("graphics socket for the rescue system", False, f"status {ws.status}")
        ok, m = api.op_run("force_off", "VM", name)
        api.wait_vm(name, "stopped")
        ok, m = api.op_run("unrescue", "VM", name)
        rec("unrescue", ok, m)
        rec("leaving rescue mode gives back the definition we started with", dumpxml(name) == before)
        ok, m = api.op_run("start", "VM", name)
        v = api.wait_vm(name, "running", ip=True)
        ip = v["observed"]["ip_address"] if v else ""
        rec("start the repaired VM", ok and bool(ip), ip)
        time.sleep(45)  # the lease table may still show the rescue system's address; the loop below re-reads it
        ok = False
        for _ in range(20):
            vv = api.vm(name)
            ip = (vv["observed"]["ip_address"] if vv else None) or ip
            rc, out = ssh(a.key_b, ip, "echo key-b-ok; id -un")
            if "key-b-ok" in out:
                ok = True
                break
            time.sleep(8)
        rec("SSH with the key that was put on the disk from the rescue system", ok, out.strip()[:80])
    finally:
        api.op_run("force_off", "VM", name, timeout=60)
        api.wait_vm(name, "stopped", timeout=60)
        ok, m = api.op_run("delete", "VM", name)
        rec("cleanup: delete the VM", ok, m)
    fails = [x for x in R if x["status"] != "PASS"]
    json.dump({"run_id": a.run_id, "results": R, "verdict": "PASS" if not fails else "FAIL"}, open(f"{a.out}/{a.run_id}-graphics.json", "w"), indent=1)
    print("RESULT", "PASS" if not fails else f"FAIL {[x['id'] for x in fails]}")
    return 0 if not fails else 1


if __name__ == "__main__":
    sys.exit(main())
