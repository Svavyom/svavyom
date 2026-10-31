#!/usr/bin/env python3
"""Qualification of more than one installation medium on a VM through an INSTALLED Svavyom (M6-E01-S07, criterion AC08). Stdlib only.

    python3 tools/qualify_media_service.py --base http://127.0.0.1:8443 --user NAME --password-file PW \
        --boot-image alpine-virt --data-image virtio-win --out DIR [--catalog /var/lib/svavyom/images] [--run-id qr-YYYYMMDD-xxxxxx]

As an operator, through the API the web console uses, it creates ONE Linux VM from the live ISO, attaches a second ISO beside it, starts it, lets the guest
list its optical drives over the serial console, stops it and ejects the first medium by image id; after every step it compares what the API reports and what
libvirt stored with what the step must produce. It then removes the VM and compares every other domain before and after.

Needs: libvirt read access for the invoking user (`virsh -r`), no sudo; the live ISO must log in as root without a password on the serial console (Alpine's does).
Reuses the HTTP and WebSocket client of tools/qualify_graphics.py. No password, cookie or ticket is printed.
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
import xml.etree.ElementTree as ET

sys.dont_write_bytecode = True

HERE = os.path.dirname(os.path.abspath(__file__))
CRITERIA = ["sign-in", "images-listed", "create", "one-medium", "attach-second", "two-media-definition", "start", "serial-console", "guest-sees-both-drives",
            "guest-booted-first", "stop", "stopped-definition-same", "eject-first", "after-eject", "cleanup", "other-domains-untouched"]


def load_graphics():
    spec = importlib.util.spec_from_file_location("qualify_graphics", os.path.join(HERE, "qualify_graphics.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def virsh(*args, timeout=60):
    r = subprocess.run(["virsh", "-r", "-c", "qemu:///system", *args], capture_output=True, text=True, timeout=timeout, check=False)  # noqa: S603,S607
    return r.returncode, r.stdout


def domain_states():
    rc, out = virsh("list", "--all")
    rows = {}
    for ln in out.splitlines()[2:]:
        p = ln.split(None, 2)
        if len(p) == 3:
            rows[p[1]] = p[2].strip()
    return rows if rc == 0 else None


def catalog_digests(catalog_dir, ids):
    """image id -> (sha256, size_bytes) from the operator-owned catalog (world-readable)."""
    c = json.load(open(os.path.join(catalog_dir, "catalog.json")))
    return {i["id"]: (i["sha256"], i["size_bytes"]) for i in c["images"] if i["id"] in ids}


def cd_list(xml_text):
    """The CD-ROMs of a stored definition, in target order: [(dev, sha256 of the file, readonly, boot order or None)], or None if it is not XML."""
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return None
    out = []
    for d in root.findall("devices/disk"):
        if d.get("device") != "cdrom":
            continue
        src = d.find("source")
        m = re.search(r"/([0-9a-f]{64})\.iso$", src.get("file", "") if src is not None else "")
        boot = d.find("boot")
        out.append((d.find("target").get("dev"), m.group(1) if m else None, d.find("readonly") is not None, boot.get("order") if boot is not None else None))
    return sorted(out)


def root_disk_problems(xml_text):
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return ["the definition is not XML"]
    disks = [d for d in root.findall("devices/disk") if d.get("device") == "disk"]
    return [] if len(disks) == 1 else ["%d root disks, expected 1" % len(disks)]


def media_problems(xml_text, expected):
    """expected: the sha256 list of the media in order. Every medium a read-only CD of the right file; with two, the first boots (order 1) and the second has no
    boot order (DR-031). Empty list = fine."""
    cds, bad = cd_list(xml_text), []
    if cds is None:
        return ["the definition is not XML"]
    bad += root_disk_problems(xml_text)
    if [c[1] for c in cds] != list(expected):
        bad.append("the CDs hold %s, expected %s" % ([(c[1] or "?")[:8] for c in cds], [e[:8] for e in expected]))
    for c in cds:
        if not c[2]:
            bad.append("%s is not read-only" % c[0])
    if len(cds) == 2 and (cds[0][3] != "1" or cds[1][3] is not None):
        bad.append("with two media the first must have boot order 1 and the second none (got %s and %s)" % (cds[0][3], cds[1][3]))
    return bad


def drive_report_problems(text, sizes_bytes, boot_banner="Alpine"):
    """From the serial text after the guest ran the probe between its markers: two optical drives whose sizes are the two media, and the booted system is the first.
    sizes_bytes: the two ISO sizes. Returns (sees_both_problems, boot_problems)."""
    seg = text.split("QMEDIA-BEGIN", 1)[-1].split("QMEDIA-END", 1)[0] if "QMEDIA-BEGIN" in text and "QMEDIA-END" in text else ""
    sees = []
    if not seg:
        return ["the probe's output markers were not seen on the serial console"], ["the probe's output markers were not seen"]
    devs = sorted(set(re.findall(r"/dev/(sr[0-9]+)", seg)))
    if len(devs) != 2:
        sees.append("the guest lists %d optical drives (%s), expected 2" % (len(devs), ", ".join(devs) or "none"))
    sectors = sorted(int(x) for x in re.findall(r"SIZE=([0-9]+)", seg))
    want = sorted(s // 512 for s in sizes_bytes)
    if sectors != want:
        sees.append("the drive sizes are %s sectors, the media are %s" % (sectors, want))
    boot = [] if re.search(r"NAME=.*%s" % re.escape(boot_banner), seg) else ["the running system is not %s" % boot_banner]
    return sees, boot


def parse_args(argv):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--base", required=True)
    ap.add_argument("--user", required=True)
    ap.add_argument("--password-file", required=True)
    ap.add_argument("--boot-image", required=True, help="registered Linux live ISO id")
    ap.add_argument("--data-image", required=True, help="registered second ISO id")
    ap.add_argument("--catalog", default="/var/lib/svavyom/images")
    ap.add_argument("--out", required=True)
    ap.add_argument("--run-id", default="qr-" + time.strftime("%Y%m%d") + "-" + secrets.token_hex(3))
    ap.add_argument("--boot-wait", type=int, default=150, help="seconds to wait for the login prompt on the serial console")
    return ap.parse_args(argv)


def problems(a):
    out = []
    if not re.fullmatch(r"qr-[0-9]{8}-[0-9a-f]{6}", a.run_id):
        out.append("run id must look like qr-YYYYMMDD-xxxxxx")
    for n, v in (("--boot-image", a.boot_image), ("--data-image", a.data_image)):
        if not re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,62}", v or ""):
            out.append("%s is not a valid image id" % n)
    if a.boot_image == a.data_image:
        out.append("the two images must differ")
    if not re.fullmatch(r"http://127\.0\.0\.1:[0-9]{2,5}|http://localhost:[0-9]{2,5}", a.base):
        out.append("--base must be the local API address (http://127.0.0.1:PORT): the console client speaks plain WebSocket")
    if not os.path.isfile(a.password_file):
        out.append("--password-file not found")
    return out


def serial_text(api):
    s, d = api.call("GET", "/console/v1/vms/%s/serial" % api._vm)
    return (d or {}).get("text", "") if s == 200 else ""


def main(argv=None):
    a = parse_args(argv)
    bad = problems(a)
    if bad:
        for b in bad:
            print("ERROR", b)
        return 2
    g = load_graphics()
    rec = g.rec
    os.makedirs(a.out, exist_ok=True)
    name = "med-" + a.run_id[-6:]
    before = domain_states()
    if before is None:
        print("NOT_RUN cannot read libvirt (virsh -r)")
        return 2
    if name in before:
        print("ERROR a domain named %s exists already; nothing was touched" % name)
        return 2
    dig = catalog_digests(a.catalog, (a.boot_image, a.data_image))
    if len(dig) != 2:
        print("ERROR both images must be in the catalog %s" % a.catalog)
        return 2
    sha1, sha2 = dig[a.boot_image][0], dig[a.data_image][0]
    api = g.Api(a.base, a.password_file, a.user)
    api._vm = name
    created = False
    if not rec("sign-in", api.sign_in(), "an operator session"):
        return finish(g, a)
    try:
        s, imgs = api.call("GET", "/api/v1/images")
        items = (imgs or {}).get("items", []) if isinstance(imgs, dict) else []
        rows = {i.get("id"): i for i in items if isinstance(i, dict)}
        rec("images-listed", all(rows.get(i, {}).get("observed", {}).get("media") == "iso" for i in (a.boot_image, a.data_image)), "both are installation media in the catalog the API serves")
        ok, m = api.op_run("create", "VM", name, create={"vcpus": 1, "memory_mib": 1024, "image_id": a.boot_image, "disk_gib": 10})
        created = True
        rec("create", ok, m)
        v = api.vm(name)
        o = (v or {}).get("observed", {})
        rc, x1 = virsh("dumpxml", "--inactive", name)
        p1 = media_problems(x1, [sha1]) if rc == 0 else ["cannot read the definition"]
        rec("one-medium", bool(v) and o.get("isos") == [a.boot_image] and not p1, "isos=%s; %s" % (o.get("isos"), "; ".join(p1) or "the definition holds the one live ISO, read-only"))
        ok, m = api.op_run("iso_attach", "VM", name, params={"image_id": a.data_image, "boot": "disk"})
        v = api.vm(name)
        o = (v or {}).get("observed", {})
        rec("attach-second", ok and o.get("isos") == [a.boot_image, a.data_image], "%s isos=%s" % (m, o.get("isos")))
        rc, x2 = virsh("dumpxml", "--inactive", name)
        p2 = media_problems(x2, [sha1, sha2]) if rc == 0 else ["cannot read the definition"]
        rec("two-media-definition", not p2, "; ".join(p2) or "two read-only CDs; the first boots (order 1), the second has no boot order")
        ok, m = api.op_run("start", "VM", name)
        v = api.wait_vm(name, "running")
        rec("start", ok and bool(v), m)
        end, text = time.time() + a.boot_wait, ""
        while time.time() < end:
            text = serial_text(api)
            if "login:" in text:
                break
            time.sleep(5)
        rec("serial-console", "login:" in text, "the guest's login prompt reached the serial console" if "login:" in text else "no login prompt in %d s (%d bytes of output)" % (a.boot_wait, len(text)))
        sees, boot = ["no serial console"], ["no serial console"]
        if "login:" in text:
            ws = g.WS(api, name, kind="console")
            if ws.status == 101:
                ws.send(b"root\n")
                time.sleep(3)
                probe = ("echo QMEDIA-BEGIN; for d in /dev/sr*; do echo $d SIZE=$(cat /sys/class/block/${d#/dev/}/size); done; grep ^NAME= /etc/os-release; echo QMEDIA-END\n")
                ws.send(probe.encode())
                time.sleep(6)
                ws.close()
                text = serial_text(api)
                sees, boot = drive_report_problems(text, [dig[a.boot_image][1], dig[a.data_image][1]])
            else:
                sees = boot = ["the interactive console answered %s" % ws.status]
        rec("guest-sees-both-drives", not sees, "; ".join(sees) or "two optical drives whose sizes are the two media")
        rec("guest-booted-first", not boot, "; ".join(boot) or "the running system is the first medium's")
        ok, m = api.op_run("force_off", "VM", name)
        v = api.wait_vm(name, "stopped")
        rec("stop", ok and bool(v), m)
        rc, x3 = virsh("dumpxml", "--inactive", name)
        p3 = media_problems(x3, [sha1, sha2]) if rc == 0 else ["cannot read the definition"]
        rec("stopped-definition-same", not p3 and cd_list(x3) == cd_list(x2), "; ".join(p3) or "the stopped VM's media are exactly what they were before the start")
        ok, m = api.op_run("eject_iso", "VM", name, params={"image_id": a.boot_image})
        rec("eject-first", ok, m)
        v = api.vm(name)
        o = (v or {}).get("observed", {})
        rc, x4 = virsh("dumpxml", "--inactive", name)
        cds = cd_list(x4) or []
        keep = [c for c in cds]
        good = o.get("isos") == [a.data_image] and len(keep) == 1 and keep[0][1] == sha2 and keep[0][2] and not root_disk_problems(x4)
        rec("after-eject", bool(good), "isos=%s; the remaining CD is the second medium (boot order %s), read-only; the root disk is intact" % (o.get("isos"), keep[0][3] if keep else "-") if good
            else "isos=%s; cds=%s" % (o.get("isos"), [(c[0], (c[1] or "?")[:8]) for c in cds]))
    finally:
        if created:
            api.op_run("force_off", "VM", name, timeout=90)
            api.wait_vm(name, "stopped", timeout=90)
            ok, m = api.op_run("delete", "VM", name)
            gone = name not in (domain_states() or {name: ""})
            rec("cleanup", ok and gone, m + ("; the domain is gone from libvirt" if gone else "; THE DOMAIN IS STILL IN LIBVIRT"))
        after = domain_states()
        rec("other-domains-untouched", after is not None and after == before, "every other domain is in the state it was found in" if after == before else "libvirt's domain list changed")
    return finish(g, a)


def finish(g, a):
    seen = {x["id"]: x["status"] for x in g.R}
    fails = [c for c in CRITERIA if seen.get(c) == "FAIL"]
    missing = [c for c in CRITERIA if c not in seen]
    verdict = "PASS" if not fails and not missing else ("FAIL" if fails else "NOT_RUN")
    with open(os.path.join(a.out, "%s-media-service.json" % a.run_id), "w") as f:
        json.dump({"run_id": a.run_id, "results": g.R, "verdict": verdict, "missing": missing}, f, indent=1)
    print("RESULT", verdict, fails or "", ("missing: %s" % missing) if missing else "")
    return 0 if verdict == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
