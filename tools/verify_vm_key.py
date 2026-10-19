#!/usr/bin/env python3
"""Read-only check that the SSH key a VM was created with is the key it accepts (docs/RELEASE-CHECKLIST.md, section B step 4).

For a Svavyom-managed VM it prints the SHA-256 fingerprint of the public key at every hop and fails unless they agree:
  1. the create operation (the API's database keeps the public key it was asked to install; it never holds a private key);
  2. the cloud-init seed volume attached to the VM (read from the volume file, without mounting it);
  3. the key the guest installed (cloud-init prints an "Authorized keys" table on the serial console; read through the console broker).
Needs root (database, volumes) and ssh-keygen and virsh. Changes nothing. `--list` shows every create operation's key fingerprint.
Usage: sudo tools/verify_vm_key.py NAME [--expect SHA256:...] | sudo tools/verify_vm_key.py --list
"""
import argparse
import base64
import json
import re
import socket
import sqlite3
import struct
import subprocess
import sys

DB = "file:/var/lib/svavyom/api/svavyom.db?mode=ro"
CONSOLE_SOCK = "/run/svavyom/console/console.sock"


def fp_of(pub):
    r = subprocess.run(["ssh-keygen", "-lf", "-"], input=pub + "\n", capture_output=True, text=True)
    m = re.search(r"(SHA256:\S+)", r.stdout)
    return m.group(1) if m else None


def operations():
    c = sqlite3.connect(DB, uri=True)
    return c.execute("select resource_id, status, spec_ssh_fingerprint, spec_ssh_key from operations where type='create' order by seq").fetchall()


def seed_key(name):
    out = subprocess.run(["virsh", "-c", "qemu:///system", "domblklist", name, "--details"], capture_output=True, text=True).stdout
    paths = [ln.split()[-1] for ln in out.splitlines() if ln.split()[:2] == ["file", "cdrom"]]
    if not paths:
        return None
    data = open(paths[0], "rb").read()
    m = re.search(rb'ssh_authorized_keys:\s*\n\s*-\s*"([^"]+)"', data)
    return m.group(1).decode() if m else None


def guest_fp(name):
    s = socket.socket(socket.AF_UNIX)
    s.settimeout(10)
    s.connect(CONSOLE_SOCK)
    body = json.dumps({"v": 1, "op": "snapshot", "vm": name, "max": 65536}).encode()
    s.sendall(struct.pack(">I", len(body)) + body)

    def rd(n):
        d = b""
        while len(d) < n:
            c = s.recv(n - len(d))
            if not c:
                raise OSError("console closed")
            d += c
        return d
    reply = json.loads(rd(struct.unpack(">I", rd(4))[0]))
    text = re.sub(r"\x1b\[[0-9;]*[a-zA-Z]", "", base64.b64decode(reply.get("data", "")).decode("utf-8", "replace"))
    found = re.findall(r"ci-info: \| (ssh-\S+)\s*\| ((?:[0-9a-f]{2}:){31}[0-9a-f]{2})", text)
    return ["SHA256:" + base64.b64encode(bytes.fromhex(h.replace(":", ""))).decode().rstrip("=") for _, h in found]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("name", nargs="?")
    ap.add_argument("--expect", help="the fingerprint of the key you meant (ssh-keygen -lf your-key.pub)")
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--guest-only", action="store_true", help=argparse.SUPPRESS)
    a = ap.parse_args()
    if a.guest_only:  # run as the API identity: the console broker only talks to it
        print(json.dumps(guest_fp(a.name)))
        return 0
    if a.list or not a.name:
        for rid, st, fp, _ in operations():
            print("%-24s %-10s %s" % (rid, st, fp))
        return 0
    ops = [o for o in operations() if o[0] == a.name]
    if not ops:
        print("FAIL no create operation for", a.name)
        return 1
    stored = fp_of(ops[-1][3])
    seed = seed_key(a.name)
    seed_fp = fp_of(seed) if seed else None
    # the broker accepts only the API's identity, so the snapshot is read as that user
    with open(__file__, "rb") as me:  # fed on stdin: the API identity cannot read this checkout
        r = subprocess.run(["sudo", "-n", "-u", "svavyom-api", sys.executable, "-I", "-", a.name, "--guest-only"], stdin=me, capture_output=True, text=True)
    guest = json.loads(r.stdout) if r.returncode == 0 and r.stdout.strip() else []
    rows = [("create operation", stored), ("seed volume", seed_fp), ("guest authorized_keys", ", ".join(guest) if guest else None)]
    if a.expect:
        rows.insert(0, ("the key you meant", a.expect))
    for label, v in rows:
        print("%-22s %s" % (label, v or "(not found)"))
    values = [stored, seed_fp] + guest + ([a.expect] if a.expect else [])
    if None in values or not guest or len(set(values)) != 1:
        print("FAIL the fingerprints do not all agree" if None not in values and guest else "FAIL a hop could not be read or the guest has not installed a key yet")
        return 1
    print("OK the key sent, the key in the seed and the key the guest installed are the same")
    return 0


if __name__ == "__main__":
    sys.exit(main())
