#!/usr/bin/env python3
"""Qualification of the Windows guest profile through an INSTALLED Svavyom (M6-E01-S04, the part tools/qualify_windows.py does not cover). Stdlib only.

    python3 tools/qualify_windows_service.py --base http://127.0.0.1:8443 --user NAME --password-file PW \
        --image windowsserver2019-iso --driver-image virtio-win --out DIR [--run-id qr-YYYYMMDD-xxxxxx]

It drives the installed API as an operator, the way the web console does: it creates ONE Windows VM named after the run id (guest_profile windows, from
installation media), checks what the API reports and what libvirt stored, attaches the driver ISO as the second medium, starts the VM, opens the graphical
console through the broker and reads the guest's screen (the installer must have drawn something), then removes the VM. It does NOT install Windows: that is
tools/qualify_windows.py. Nothing but the one VM is touched; every other domain is compared before and after. No password, cookie or ticket is printed.

Needs: libvirt read access for the invoking user (`virsh -r`), no sudo. Reuses the HTTP, WebSocket and RFB client of tools/qualify_graphics.py.
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
CRITERIA = ["sign-in", "windows-image-listed", "create-windows", "observed-profile", "definition", "second-medium", "second-medium-definition", "start",
            "graphical-console", "console-screen-drawn", "cleanup", "other-domains-untouched"]


def load_graphics():
    spec = importlib.util.spec_from_file_location("qualify_graphics", os.path.join(HERE, "qualify_graphics.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def virsh(*args, timeout=60):
    r = subprocess.run(["virsh", "-r", "-c", "qemu:///system", *args], capture_output=True, text=True, timeout=timeout, check=False)  # noqa: S603,S607
    return r.returncode, r.stdout


def domains():
    rc, out = virsh("list", "--all", "--name")
    return sorted(x for x in out.split("\n") if x.strip()) if rc == 0 else None


def domain_states():
    rc, out = virsh("list", "--all")
    rows = {}
    for ln in out.splitlines()[2:]:
        p = ln.split(None, 2)
        if len(p) == 3:
            rows[p[1]] = p[2].strip()
    return rows if rc == 0 else None


def windows_definition_problems(xml_text, media):
    """What libvirt's stored XML must hold for the Windows profile (DR-032 D1), with `media` = the number of CD-ROMs expected (1 or 2). Empty list = fine."""
    bad = []
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return ["the definition is not XML"]
    os_el = root.find("os")
    if os_el is None or "q35" not in (os_el.find("type").get("machine", "") if os_el.find("type") is not None else ""):
        bad.append("machine is not q35")
    if os_el is not None and (os_el.get("firmware") or os_el.find("loader") is not None):
        bad.append("UEFI firmware present (the profile is BIOS)")
    if root.find("devices/tpm") is not None:
        bad.append("a TPM is present")
    clock = root.find("clock")
    if clock is None or clock.get("offset") != "localtime":
        bad.append("clock is not localtime")
    elif not any(t.get("name") == "hypervclock" for t in clock.findall("timer")):
        bad.append("no hypervclock timer")
    nics = root.findall("devices/interface")
    if len(nics) != 1 or (nics[0].find("model") is None or nics[0].find("model").get("type") != "e1000e"):
        bad.append("not exactly one e1000e NIC")
    disks = {d.find("target").get("dev"): d for d in root.findall("devices/disk") if d.find("target") is not None}
    sda = disks.get("sda")
    if sda is None or sda.get("device") != "disk" or sda.find("target").get("bus") != "sata":
        bad.append("root disk is not sda on SATA")
    for n, dev in enumerate(("sdb", "sdc")[:media]):
        d = disks.get(dev)
        if d is None or d.get("device") != "cdrom" or d.find("target").get("bus") != "sata" or d.find("readonly") is None:
            bad.append("%s is not a read-only SATA CD" % dev)
        elif n == 1 and d.find("boot") is not None:
            bad.append("the second medium has a boot order")
    if media == 2 and "sdc" in disks and disks["sdc"].find("boot") is not None:
        pass
    cds = [k for k, d in disks.items() if d.get("device") == "cdrom"]
    if len(cds) != media:
        bad.append("%d CD-ROMs, expected %d" % (len(cds), media))
    if any(v.get("device") == "disk" and v.find("target").get("bus") == "virtio" for v in disks.values()):
        bad.append("a virtio disk is present (the profile uses SATA, no driver)")
    return bad


def parse_args(argv):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--base", required=True)
    ap.add_argument("--user", required=True)
    ap.add_argument("--password-file", required=True)
    ap.add_argument("--image", required=True, help="registered Windows installation ISO id")
    ap.add_argument("--driver-image", required=True, help="registered virtio-win ISO id")
    ap.add_argument("--out", required=True)
    ap.add_argument("--run-id", default="qr-" + time.strftime("%Y%m%d") + "-" + secrets.token_hex(3))
    ap.add_argument("--screen-wait", type=int, default=90, help="seconds to let the installer draw before reading the screen")
    return ap.parse_args(argv)


def problems(a):
    out = []
    if not re.fullmatch(r"qr-[0-9]{8}-[0-9a-f]{6}", a.run_id):
        out.append("run id must look like qr-YYYYMMDD-xxxxxx")
    for n, v in (("--image", a.image), ("--driver-image", a.driver_image)):
        if not re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,62}", v or ""):
            out.append("%s is not a valid image id" % n)
    if a.image == a.driver_image:
        out.append("the installer and the driver image must differ")
    if not re.fullmatch(r"http://127\.0\.0\.1:[0-9]{2,5}|http://localhost:[0-9]{2,5}", a.base):
        out.append("--base must be the local API address (http://127.0.0.1:PORT): the console client speaks plain WebSocket")
    if not os.path.isfile(a.password_file):
        out.append("--password-file not found")
    return out


def main(argv=None):
    a = parse_args(argv)
    bad = problems(a)
    if bad:
        for b in bad:
            print("ERROR", b)
        return 2
    g = load_graphics()
    os.makedirs(a.out, exist_ok=True)
    name = "win-" + a.run_id[-6:]
    before = domain_states()
    if before is None:
        print("NOT_RUN cannot read libvirt (virsh -r)")
        return 2
    if name in before:
        print("ERROR a domain named %s exists already; nothing was touched" % name)
        return 2
    api = g.Api(a.base, a.password_file, a.user)
    rec = g.rec
    created = False
    if not rec("sign-in", api.sign_in(), "an operator session"):
        return finish(g, a)
    try:
        s, imgs = api.call("GET", "/api/v1/images")
        items = (imgs or {}).get("items", imgs) if isinstance(imgs, (dict, list)) else []
        rows = {i.get("id"): i for i in items if isinstance(i, dict)}
        wi, di = rows.get(a.image), rows.get(a.driver_image)
        rec("windows-image-listed", bool(wi and di and wi["observed"].get("media") == "iso" and di["observed"].get("media") == "iso"),
            "installer and driver image are installation media in the catalog the API serves")
        ok, m = api.op_run("create", "VM", name, create={"vcpus": 4, "memory_mib": 4096, "image_id": a.image, "disk_gib": 40, "guest_profile": "windows"})
        created = True
        rec("create-windows", ok, m)
        v = api.vm(name)
        o = (v or {}).get("observed", {})
        rec("observed-profile", bool(v) and o.get("guest_profile") == "windows" and o.get("power") == "stopped" and o.get("isos") == [a.image] and o.get("managed") is True,
            "guest_profile=%s power=%s isos=%s managed=%s" % (o.get("guest_profile"), o.get("power"), o.get("isos"), o.get("managed")))
        rc, xml1 = virsh("dumpxml", "--inactive", name)
        d1 = windows_definition_problems(xml1, 1) if rc == 0 else ["cannot read the definition"]
        rec("definition", not d1, "libvirt's stored definition is the Windows profile with the installer" if not d1 else "; ".join(d1))
        ok, m = api.op_run("iso_attach", "VM", name, params={"image_id": a.driver_image, "boot": "disk"})
        v = api.vm(name)
        rec("second-medium", ok and bool(v) and (v["observed"].get("isos") == [a.image, a.driver_image]), m + " isos=%s" % ((v or {}).get("observed", {}).get("isos")))
        rc, xml2 = virsh("dumpxml", "--inactive", name)
        d2 = windows_definition_problems(xml2, 2) if rc == 0 else ["cannot read the definition"]
        rec("second-medium-definition", not d2, "the driver ISO is the second, read-only, non-boot CD; the installer is still first" if not d2 else "; ".join(d2))
        ok, m = api.op_run("start", "VM", name)
        v = api.wait_vm(name, "running")
        rec("start", ok and bool(v), m)
        v = api.vm(name)
        rec("graphical-console", bool(v) and v["observed"].get("graphical_console") == "present", "the VM reports the graphical console")
        time.sleep(a.screen_wait)
        ws = g.WS(api, name)
        if ws.status == 101:
            r = g.RFB(ws)
            r.screen(3.0)
            lit = r.lit()
            r.png(os.path.join(a.out, "%s-installer-screen.png" % a.run_id))
            ws.close()
            rec("console-screen-drawn", lit > 5000, "%d lit pixels in %dx%d (a blank screen has none); PNG saved" % (lit, r.w, r.h))
        else:
            rec("console-screen-drawn", False, "the graphics socket answered %s" % ws.status)
    finally:
        if created:
            api.op_run("force_off", "VM", name, timeout=90)
            api.wait_vm(name, "stopped", timeout=90)
            ok, m = api.op_run("delete", "VM", name)
            gone = name not in (domains() or [name])
            rec("cleanup", ok and gone, m + ("; the domain is gone from libvirt" if gone else "; THE DOMAIN IS STILL IN LIBVIRT"))
        after = domain_states()
        rec("other-domains-untouched", after is not None and after == before, "every other domain is in the state it was found in" if after == before else "libvirt's domain list changed")
    return finish(g, a)


def finish(g, a):
    seen = {x["id"]: x["status"] for x in g.R}
    fails = [c for c in CRITERIA if seen.get(c) == "FAIL"]
    missing = [c for c in CRITERIA if c not in seen]
    verdict = "PASS" if not fails and not missing else ("FAIL" if fails else "NOT_RUN")
    with open(os.path.join(a.out, "%s-windows-service.json" % a.run_id), "w") as f:
        json.dump({"run_id": a.run_id, "results": g.R, "verdict": verdict, "missing": missing}, f, indent=1)
    print("RESULT", verdict, fails or "", ("missing: %s" % missing) if missing else "")
    return 0 if verdict == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
