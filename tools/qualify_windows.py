#!/usr/bin/env python3
"""Real-host qualification of the Windows guest profile (story M6-E01-S04, criterion AC07; DR-032, DR-033). Canonical entry: `make docker-qualify-libvirt-windows`.

A disposable VM is created with the production code path (profile windows, from the catalog's Windows installation ISO) on the real qemu:///system, the catalog's
driver ISO is attached as the second medium, and Windows is installed WITHOUT a person: the answer file (Autounattend.xml) rides on a harness-only read-only USB
disk and, as its last step, the guest reports what it sees (disks, network card, volumes, time) by HTTP to a listener this script runs on the host's NAT bridge.

Stages, each criterion PASS / FAIL / NOT_RUN (never a false PASS):
  1. host preflight (read-only, tools/qualify_preflight.py). Missing prerequisites => NOT_RUN, exit 0.
  2. create (Go, locked-down container, TestSystemWindowsQualification): definition on real libvirt, second medium, installer boots from its SATA CD under KVM.
  3. guest (here, on the host): wait for the install and the guest report; judge it; read what the host itself can see (QEMU's -rtc, the root disk's write counter).
  4. cleanup (Go, TestSystemWindowsQualificationCleanup): after proving ownership, remove the run's VM and volumes; re-check the definition, the catalog images and every
     other VM. `--keep` leaves the VM for inspection and runs only `--stage cleanup --run-id ID` later.

The report (qualification-out/<RUN_ID>/report-*.{txt,json}) is console output to attach to the qualification record, not an evidence-format record: the signature on the
record is the owner's. The run needs a Windows Server installation ISO and a driver ISO already registered by the host administrator (`api register-image --media iso`).

Limits stated with the result, not hidden: this host's clock is UTC, where libvirt's `localtime` and `utc` clocks give the guest the same RTC, so the guest-observed time cannot
tell them apart; the proof of the clock criterion is then QEMU's own `-rtc base=localtime`. No guest agent is used: everything the guest says, it says in the one report.
"""
import argparse
import base64
import datetime
import http.server
import json
import os
import re
import secrets
import struct
import subprocess
import sys
import threading
import time
import urllib.request
import xml.etree.ElementTree as ET
import zlib

sys.dont_write_bytecode = True
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import qualify_create as qc  # noqa: E402
import qualify_preflight as pf  # noqa: E402

PASS, FAIL, NOT_RUN = "PASS", "FAIL", "NOT_RUN"
RUN_ID_RE = qc.RUN_ID_RE
IMAGE_ID_RE = qc.IMAGE_ID_RE
GO_TAGS = qc.GO_TAGS
DEV_IMAGE = qc.DEV_IMAGE
LIBVIRT_RW_SOCK, LIBVIRT_RO_SOCK = qc.LIBVIRT_RW_SOCK, qc.LIBVIRT_RO_SOCK

GUEST_TIMEOUT_MIN = 75          # a Server Core install under KVM takes 15 to 30 minutes; this bounds a stuck one
MAX_REPORT_BYTES = 64 << 10
ROOT_DISK_GIB = 40              # must equal windowsDiskGiB in the Go stage
MIN_ROOT_WRITE_BYTES = 2 << 30  # an installed Windows has written well over this to its root disk
CLOCK_TOLERANCE_S = 600
NAT_PREFIX = "192.168."

# What every criterion of AC07 is called, in the order the record lists them. The Go stages report the first group, this script the second and third.
CRITERIA_CREATE = ["trust-layout", "managed-image", "image-immutable-before", "real-libvirt", "kvm-capable", "host-ready", "profile-spec", "domain-defined", "no-duplicates", "profile-definition",
                   "profile-observed", "svavyom-owned", "second-medium", "answer-disk", "vm-started", "kvm-guest", "installer-boots", "vm-running"]
CRITERIA_GUEST = ["install-completed", "root-disk-sata-no-driver", "root-disk-written", "nic-e1000e-no-driver", "address-observed", "clock-local-time", "driver-cd-readable"]
CRITERIA_CLEANUP = ["profile-definition-after", "other-domains-untouched", "image-immutable-after", "cleanup"]
ALL_CRITERIA = CRITERIA_CREATE + CRITERIA_GUEST + CRITERIA_CLEANUP


# ---------------------------------------------------------------- the answer file

def guest_script(report_url):
    """The PowerShell the guest runs at its first logon: collect what AC07 asks about and POST it as JSON; then power off. Plain and short; sent as -EncodedCommand."""
    return r"""
$ErrorActionPreference = 'Continue'
$r = [ordered]@{}
$r.time_local = (Get-Date).ToString('yyyy-MM-ddTHH:mm:ss')
$r.time_zone = (Get-TimeZone).Id
$r.os = (Get-CimInstance Win32_OperatingSystem).Caption
$r.build = (Get-CimInstance Win32_OperatingSystem).BuildNumber
$r.adapters = @(Get-NetAdapter | ForEach-Object { [ordered]@{ name = $_.Name; description = $_.InterfaceDescription; status = [string]$_.Status } })
$r.disks = @(Get-Disk | ForEach-Object { [ordered]@{ number = $_.Number; bus = [string]$_.BusType; model = $_.FriendlyName; size = [int64]$_.Size } })
$r.volumes = @(Get-Volume | ForEach-Object { [ordered]@{ letter = [string]$_.DriveLetter; label = $_.FileSystemLabel; type = [string]$_.DriveType; fs = $_.FileSystem } })
$r.cd = @()
foreach ($v in (Get-Volume | Where-Object { $_.DriveType -eq 'CD-ROM' -and $_.DriveLetter })) {
  $p = "$($v.DriveLetter):\"
  $r.cd += [ordered]@{ drive = $p; label = $v.FileSystemLabel; msi = (Test-Path ($p + 'virtio-win-gt-x64.msi')); entries = @(Get-ChildItem $p -ErrorAction SilentlyContinue).Count }
}
$body = $r | ConvertTo-Json -Depth 6 -Compress
for ($i = 0; $i -lt 8; $i++) {
  try { Invoke-RestMethod -Uri '__URL__' -Method Post -ContentType 'application/json' -Body $body -TimeoutSec 20 | Out-Null; break } catch { Start-Sleep -Seconds 10 }
}
Start-Sleep -Seconds 5
Stop-Computer -Force
""".replace("__URL__", report_url).strip()


def encoded_command(script):
    return base64.b64encode(script.encode("utf-16-le")).decode("ascii")


def answer_file(report_url, admin_password, image_index=1, computer_name="SVQWIN", time_zone="UTC"):
    """Autounattend.xml for a Windows Server 2019 install on BIOS firmware to disk 0 (one NTFS partition) with no driver of any kind (no DriverPaths, no
    PnpCustomizationsWinPE): Windows Setup must see the SATA disk, and the e1000e card must work, with what the installation media itself holds. The one
    logon command reports to report_url. The password is for a VM that is deleted at the end of the run."""
    if not re.fullmatch(r"[A-Za-z0-9!_.-]{16,64}", admin_password or ""):
        raise ValueError("the administrator password must be 16 to 64 characters from A-Z a-z 0-9 ! _ . -")
    if not re.fullmatch(r"http://[0-9.]{7,15}:[0-9]{2,5}/[0-9a-f]{32}/report", report_url or ""):
        raise ValueError("the report URL must be http://<ipv4>:<port>/<32 hex>/report")
    if not isinstance(image_index, int) or not 1 <= image_index <= 16:
        raise ValueError("image index")
    if not re.fullmatch(r"[A-Z0-9-]{1,15}", computer_name) or not re.fullmatch(r"[A-Za-z0-9 ().,-]{1,64}", time_zone):
        raise ValueError("computer name or time zone")
    cmd = "powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand " + encoded_command(guest_script(report_url))
    ns = 'xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"'
    comp = 'processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" ' + ns
    return f"""<?xml version="1.0" encoding="utf-8"?>
<unattend xmlns="urn:schemas-microsoft-com:unattend">
  <settings pass="windowsPE">
    <component name="Microsoft-Windows-International-Core-WinPE" {comp}>
      <SetupUILanguage><UILanguage>en-US</UILanguage></SetupUILanguage>
      <InputLocale>en-US</InputLocale><SystemLocale>en-US</SystemLocale><UILanguage>en-US</UILanguage><UserLocale>en-US</UserLocale>
    </component>
    <component name="Microsoft-Windows-Setup" {comp}>
      <DiskConfiguration>
        <WillShowUI>OnError</WillShowUI>
        <Disk wcm:action="add">
          <DiskID>0</DiskID>
          <WillWipeDisk>true</WillWipeDisk>
          <CreatePartitions>
            <CreatePartition wcm:action="add"><Order>1</Order><Type>Primary</Type><Extend>true</Extend></CreatePartition>
          </CreatePartitions>
          <ModifyPartitions>
            <ModifyPartition wcm:action="add"><Order>1</Order><PartitionID>1</PartitionID><Format>NTFS</Format><Label>System</Label><Letter>C</Letter><Active>true</Active></ModifyPartition>
          </ModifyPartitions>
        </Disk>
      </DiskConfiguration>
      <ImageInstall>
        <OSImage>
          <InstallFrom><MetaData wcm:action="add"><Key>/IMAGE/INDEX</Key><Value>{image_index}</Value></MetaData></InstallFrom>
          <InstallTo><DiskID>0</DiskID><PartitionID>1</PartitionID></InstallTo>
          <WillShowUI>OnError</WillShowUI>
        </OSImage>
      </ImageInstall>
      <UserData><AcceptEula>true</AcceptEula></UserData>
    </component>
  </settings>
  <settings pass="specialize">
    <component name="Microsoft-Windows-Shell-Setup" {comp}>
      <ComputerName>{computer_name}</ComputerName>
      <TimeZone>{time_zone}</TimeZone>
    </component>
  </settings>
  <settings pass="oobeSystem">
    <component name="Microsoft-Windows-Shell-Setup" {comp}>
      <UserAccounts><AdministratorPassword><Value>{admin_password}</Value><PlainText>true</PlainText></AdministratorPassword></UserAccounts>
      <AutoLogon><Enabled>true</Enabled><LogonCount>1</LogonCount><Username>Administrator</Username><Password><Value>{admin_password}</Value><PlainText>true</PlainText></Password></AutoLogon>
      <OOBE><HideEULAPage>true</HideEULAPage><HideLocalAccountScreen>true</HideLocalAccountScreen><HideOnlineAccountScreens>true</HideOnlineAccountScreens><ProtectYourPC>3</ProtectYourPC></OOBE>
      <FirstLogonCommands>
        <SynchronousCommand wcm:action="add"><Order>1</Order><CommandLine>{cmd}</CommandLine><Description>qualification report</Description></SynchronousCommand>
      </FirstLogonCommands>
    </component>
  </settings>
</unattend>
"""


def new_password():
    return "Q" + secrets.token_urlsafe(18).replace("_", "x").replace("-", "y") + "a1!"


# ---------------------------------------------------------------- the report listener

class Report:
    def __init__(self):
        self.body = None
        self.client = None
        self.at = None
        self.lock = threading.Lock()

    def put(self, body, client):
        with self.lock:
            if self.body is None:  # the first valid report is the one that counts
                self.body, self.client, self.at = body, client, time.time()


def make_handler(token, report):
    want = "/%s/report" % token

    class H(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):  # no request line, no body, no address in logs
            pass

        def _send(self, code):
            self.send_response(code)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def do_POST(self):
            if self.path != want:
                return self._send(404)
            try:
                n = int(self.headers.get("Content-Length", "-1"))
            except ValueError:
                n = -1
            if n > MAX_REPORT_BYTES:
                return self._send(413)
            if n < 2:
                return self._send(400)
            try:
                body = json.loads(self.rfile.read(n).decode("utf-8-sig"))
            except (ValueError, UnicodeDecodeError):
                return self._send(400)
            if not isinstance(body, dict):
                return self._send(400)
            report.put(body, self.client_address[0])
            self._send(204)

    return H


def start_listener(bind, token):
    """A threaded HTTP server on bind:<random port>; returns (server, port, report). Only POST /<token>/report is served; everything else is 404."""
    report = Report()
    srv = http.server.ThreadingHTTPServer((bind, 0), make_handler(token, report))
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, srv.server_address[1], report


# ---------------------------------------------------------------- judging

def host_wall_clock(now=None):
    now = now or datetime.datetime.now()
    return now.replace(microsecond=0)


def judge_guest(rep, client_ip, root_written, rtc_localtime, host_offset_s, now=None, answer_text=""):
    """Criteria of the guest stage from the guest's report and the host's own facts. rep is the decoded JSON or None."""
    out = []

    def add(cid, ok, detail):
        out.append((cid, PASS if ok else FAIL, detail))

    if not rep:
        for cid in CRITERIA_GUEST:
            out.append((cid, FAIL if cid == "install-completed" else NOT_RUN, "no guest report arrived" if cid == "install-completed" else "needs the guest report"))
        return out
    osname = str(rep.get("os", ""))
    add("install-completed", "Windows Server 2019" in osname and bool(re.fullmatch(r"[0-9]{5}", str(rep.get("build", "")))),
        "the installed system reported itself as %r build %s" % (osname[:60], str(rep.get("build", ""))[:6]))
    no_driver = not re.search(r"DriverPaths|PnpCustomizationsWinPE|DriverPath", answer_text)
    disks = [d for d in rep.get("disks") or [] if isinstance(d, dict)]
    sata = [d for d in disks if str(d.get("bus", "")).upper() == "SATA" and abs(int(d.get("size", 0) or 0) - (ROOT_DISK_GIB << 30)) < (2 << 30)]
    add("root-disk-sata-no-driver", bool(sata) and no_driver,
        "Windows saw a %d GiB SATA disk and installed to it; the answer file names no driver (%s)" % (ROOT_DISK_GIB, "none" if no_driver else "DRIVER PATHS PRESENT") if sata and no_driver
        else "disks=%s; no_driver_in_answer=%s" % ([(d.get("bus"), d.get("size")) for d in disks][:4], no_driver))
    add("root-disk-written", root_written >= MIN_ROOT_WRITE_BYTES, "the root disk's write counter is %d MiB (an installed Windows needs at least %d MiB)" % (root_written >> 20, MIN_ROOT_WRITE_BYTES >> 20))
    nics = [a for a in rep.get("adapters") or [] if isinstance(a, dict)]
    e1000 = [a for a in nics if re.search(r"82574|e1000|Intel\(R\) .*Gigabit", str(a.get("description", "")), re.I) and str(a.get("status", "")).lower() == "up"]
    add("nic-e1000e-no-driver", bool(e1000) and no_driver, "adapter %r is Up with the driver Windows itself carries" % (e1000[0].get("description") if e1000 else None) if e1000
        else "adapters=%s" % [(a.get("description"), a.get("status")) for a in nics][:4])
    add("address-observed", str(client_ip or "").startswith(NAT_PREFIX), "the report reached the host over the NAT network from %s (a DHCP lease and a working card)" % (client_ip or "?"))
    # the clock: QEMU must have been started with the local-time RTC; the guest's own wall clock must agree with the host's
    try:
        guest = datetime.datetime.strptime(str(rep.get("time_local", "")), "%Y-%m-%dT%H:%M:%S")
        skew = abs((guest - host_wall_clock(now)).total_seconds())
    except ValueError:
        guest, skew = None, None
    ok = rtc_localtime and skew is not None and skew <= CLOCK_TOLERANCE_S
    note = ("host offset from UTC is 0: a localtime clock and a utc clock give the guest the same time here, so the guest-observed time cannot tell them apart; "
            "the proof is QEMU's own -rtc base=localtime") if host_offset_s == 0 else "host offset from UTC is %+d s: a utc clock would put the guest that far from the host" % host_offset_s
    add("clock-local-time", ok, "QEMU runs with -rtc base=%s; guest time %s vs host %s (skew %s s); %s" % ("localtime" if rtc_localtime else "NOT localtime", rep.get("time_local"),
        host_wall_clock(now).isoformat(), "?" if skew is None else int(skew), note))
    cds = [c for c in rep.get("cd") or [] if isinstance(c, dict)]
    drv = [c for c in cds if c.get("msi") is True or str(c.get("label", "")).lower().startswith("virtio-win")]
    add("driver-cd-readable", bool(drv), "the guest reads the driver CD %s (label %r, %s entries)" % (drv[0].get("drive") if drv else "-", drv[0].get("label") if drv else None, drv[0].get("entries") if drv else "-")
        if drv else "CD volumes seen by the guest: %s" % [(c.get("drive"), c.get("label")) for c in cds][:4])
    return out


def overall(criteria):
    """PASS only when every criterion of AC07 is listed and PASS; any FAIL is FAIL; otherwise NOT_RUN (something was not run: never a PASS)."""
    seen = {cid: st for cid, st, _ in criteria}
    if any(st == FAIL for st in seen.values()):
        return FAIL
    if all(seen.get(cid) == PASS for cid in ALL_CRITERIA):
        return PASS
    return NOT_RUN


def render(run_id, criteria, verdict):
    names = {cid: i for i, cid in enumerate(ALL_CRITERIA)}
    lines = ["Windows guest profile qualification (AC07) run %s" % run_id, ""]
    for cid, st, detail in sorted(criteria, key=lambda c: names.get(c[0], 999)):
        lines.append("%-8s %-28s %s" % (st, cid, detail[:300]))
    for cid in ALL_CRITERIA:
        if cid not in {c for c, _, _ in criteria}:
            lines.append("%-8s %-28s %s" % (NOT_RUN, cid, "its stage did not run"))
    lines += ["", "RESULT: %s" % verdict]
    return "\n".join(lines)


# ---------------------------------------------------------------- host facts and the Go stages

def run_diag(argv, timeout=30):
    try:
        p = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, check=False)  # noqa: S603
        return p.stdout + p.stderr
    except (OSError, subprocess.SubprocessError):
        return ""


def bridge_ip(network):
    """The host address on the libvirt NAT network (read-only query); the guest's report goes there."""
    if not re.fullmatch(r"[A-Za-z0-9._-]{1,64}", network or ""):
        return ""
    m = re.search(r"<ip address='([0-9.]+)'", run_diag(["virsh", "-r", "-c", "qemu:///system", "net-dumpxml", "--", network]))
    return m.group(1) if m else ""


def qemu_rtc_localtime(vm_name):
    """True if the running QEMU process for this VM was started with -rtc base=localtime (read from /proc: world-readable)."""
    for line in run_diag(["ps", "-eo", "pid,args", "--no-headers"]).splitlines():
        if ("guest=%s," % vm_name) in line and "qemu-system" in line:
            return "-rtc base=localtime" in line
    return False


def root_write_bytes(vm_name):
    m = re.search(r"wr_bytes\s+([0-9]+)", run_diag(["virsh", "-r", "-c", "qemu:///system", "domblkstat", "--", vm_name, "sda"]))
    return int(m.group(1)) if m else 0


def domain_state(vm_name):
    return run_diag(["virsh", "-r", "-c", "qemu:///system", "domstate", "--", vm_name]).strip()


def ppm_to_png(ppm):
    """A binary PPM (P6) to PNG, stdlib only, so a screenshot of a stuck Setup can be attached to the record."""
    m = re.match(rb"P6\s+([0-9]+)\s+([0-9]+)\s+255\s", ppm)
    if not m:
        return b""
    w, h = int(m.group(1)), int(m.group(2))
    data = ppm[m.end():]
    if len(data) < w * h * 3:
        return b""
    raw = b"".join(b"\x00" + data[y * w * 3:(y + 1) * w * 3] for y in range(h))

    def chunk(t, d):
        c = struct.pack(">I", len(d)) + t + d
        return c + struct.pack(">I", zlib.crc32(t + d) & 0xFFFFFFFF)
    return b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 2, 0, 0, 0)) + chunk(b"IDAT", zlib.compress(raw, 6)) + chunk(b"IEND", b"")


def screenshot(vm_name, out_dir, tag):
    ppm = os.path.join(out_dir, "shot-%s.ppm" % tag)
    run_diag(["virsh", "-c", "qemu:///system", "screenshot", "--file", ppm, "--", vm_name], 60)
    try:
        png = ppm_to_png(open(ppm, "rb").read())
        os.remove(ppm)
    except OSError:
        return ""
    if not png:
        return ""
    p = os.path.join(out_dir, "screenshot-%s.png" % tag)
    with open(p, "wb") as f:
        f.write(png)
    return p


def docker_argv(stage, a, catalog_dir, gid, out_dir, answer_path=None, pool_dir=None, domains_before=""):
    """The container gets what the create harness gives it (the libvirt sockets, the read-only checkout, config and catalog, one writable output directory; no capability,
    no network, read-only root) plus, for create, the answer file read-only. /dev/kvm is not needed: libvirtd's qemu uses it."""
    run = ["docker", "run", "--rm", "-u", "%d:%d" % (os.getuid(), os.getgid()), "--group-add", str(gid), "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true",
           "--read-only", "--network", "none", "--tmpfs", "/tmp:exec,mode=1777,size=2g", "-v", "%s:/workspace/cloud-platform:ro" % a.repo,
           "-v", "%s:%s" % (LIBVIRT_RW_SOCK, LIBVIRT_RW_SOCK), "-v", "%s:/qualify/config.json:ro" % a.config, "-v", "%s:%s:ro" % (catalog_dir, catalog_dir),
           "-v", "%s:/qualify/out" % out_dir]
    if pool_dir:
        run += ["-v", "%s:%s:ro" % (pool_dir, pool_dir)]
    if stage == "create":
        run += ["-v", "%s:%s" % (LIBVIRT_RO_SOCK, LIBVIRT_RO_SOCK), "-v", "%s:/qualify/answer.xml:ro" % answer_path, "-e", "SVAVYOM_QUALIFY_ANSWER_FILE=/qualify/answer.xml"]
    else:
        run += ["-e", "SVAVYOM_QUALIFY_DOMAINS_BEFORE=" + domains_before]
    run += ["-e", "SVAVYOM_QUALIFY_WINDOWS=1", "-e", "SVAVYOM_QUALIFY_STAGE=" + stage, "-e", "SVAVYOM_QUALIFY_RUN_ID=" + a.run_id, "-e", "SVAVYOM_QUALIFY_CONFIG=/qualify/config.json",
            "-e", "SVAVYOM_QUALIFY_OUT=/qualify/out", "-e", "SVAVYOM_QUALIFY_IMAGE_ID=" + a.image, "-e", "SVAVYOM_QUALIFY_DRIVER_IMAGE_ID=" + a.driver_image,
            "-e", "GOMODCACHE=/opt/go-mod-cache", "-e", "GOPROXY=off", "-e", "HOME=/tmp", "-e", "GOCACHE=/tmp/go-cache", "-w", "/workspace/cloud-platform/backend", DEV_IMAGE,
            "go", "test", "-tags", GO_TAGS, "-count=1", "-v", "-run", "TestSystemWindowsQualification$" if stage == "create" else "TestSystemWindowsQualificationCleanup$",
            "./internal/hypervisor/libvirtmut/"]
    return run


def read_stage_result(out_dir, stage):
    try:
        res = json.load(open(os.path.join(out_dir, stage + "-result.json")))
        return res, [(c["id"], c["status"], c.get("detail", "")) for c in res.get("criteria", [])]
    except (OSError, ValueError, KeyError):
        return {}, []


def validate(a):
    problems = []
    if not RUN_ID_RE.match(a.run_id or ""):
        problems.append("run id must look like qr-YYYYMMDD-xxxxxx")
    for flag, v in (("--image", a.image), ("--driver-image", a.driver_image)):
        if not IMAGE_ID_RE.match(v or ""):
            problems.append("%s (a registered installation-media image id) is required" % flag)
    if a.image and a.image == a.driver_image:
        problems.append("the installer and the driver image must differ")
    if not a.config or not os.path.isabs(a.config) or not os.path.isfile(a.config):
        problems.append("QUALIFY_CONFIG (absolute path of the provisioning config) is required")
    if not 5 <= a.timeout_min <= 240:
        problems.append("--timeout-min must be between 5 and 240")
    return problems


def catalog_problems(catalog_dir, image, driver):
    """Read-only: both ids must be installation media in the catalog. Returns a list of problems (empty = fine)."""
    try:
        cat = json.load(open(os.path.join(catalog_dir, "catalog.json")))
    except (OSError, ValueError):
        return ["the catalog is not readable"]
    by = {i.get("id"): i for i in cat.get("images", [])}
    out = []
    for what, iid in (("installer", image), ("driver", driver)):
        im = by.get(iid)
        if not im:
            out.append("%s image %s is not in the catalog" % (what, iid))
        elif im.get("media") != "iso" or im.get("state") not in ("verified", "qualified"):
            out.append("%s image %s is not usable installation media" % (what, iid))
    return out


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--stage", choices=("create", "cleanup", "plan"), default="create")
    ap.add_argument("--config", default=os.environ.get("QUALIFY_CONFIG", ""))
    ap.add_argument("--image", default=os.environ.get("QUALIFY_WINDOWS_IMAGE", ""), help="registered Windows Server installation ISO id")
    ap.add_argument("--driver-image", default=os.environ.get("QUALIFY_DRIVER_IMAGE", ""), help="registered virtio-win ISO id")
    ap.add_argument("--image-index", type=int, default=int(os.environ.get("QUALIFY_IMAGE_INDEX", "1")), help="install.wim image index (1 = Standard, Server Core, on the 2019 media)")
    ap.add_argument("--run-id", default=os.environ.get("QUALIFY_RUN_ID", ""))
    ap.add_argument("--out", default=os.environ.get("QUALIFY_OUT", "qualification-out"))
    ap.add_argument("--timeout-min", type=int, default=GUEST_TIMEOUT_MIN)
    ap.add_argument("--keep", action="store_true", help="leave the VM after the guest stage (run --stage cleanup --run-id ID later)")
    ap.add_argument("--repo", default=os.getcwd())
    a = ap.parse_args(argv)

    miss = [m for m in ((LIBVIRT_RW_SOCK, LIBVIRT_RO_SOCK, "/dev/kvm")) if not os.path.exists(m)]
    if miss:
        print("NOT_RUN: missing prerequisites: %s (see docs/QUALIFICATION-WINDOWS.md); real-KVM Windows qualification pending" % ", ".join(miss))
        return 0
    if a.stage == "create" and not a.run_id:
        a.run_id = qc.new_run_id()
    problems = validate(a)
    if problems:
        print("ERROR " + "; ".join(problems), file=sys.stderr)
        return 2
    a.config, a.repo = os.path.abspath(a.config), os.path.abspath(a.repo)
    out_dir = os.path.abspath(os.path.join(a.out, a.run_id))
    try:
        cfg = json.load(open(a.config))
    except (OSError, ValueError):
        print("ERROR the provisioning config is not readable JSON", file=sys.stderr)
        return 2
    catalog_dir = cfg.get("catalog_dir", "")
    if not os.path.isabs(catalog_dir) or not os.path.isdir(catalog_dir):
        print("ERROR config.catalog_dir is not a directory on this host", file=sys.stderr)
        return 2
    cp = catalog_problems(catalog_dir, a.image, a.driver_image)
    if cp and a.stage != "cleanup":
        print("NOT_RUN: " + "; ".join(cp))
        return 0
    pool_dir = qc.pool_target_dir(cfg.get("pool", ""))
    gid = qc.sock_gid(LIBVIRT_RW_SOCK)
    if a.stage == "plan":  # print what would run, touch nothing (used by tests and by reviewers)
        print(" ".join(docker_argv("create", a, catalog_dir, gid, out_dir, "/path/to/answer.xml", pool_dir)))
        print(" ".join(docker_argv("cleanup", a, catalog_dir, gid, out_dir, None, pool_dir, "")))
        return 0

    os.makedirs(out_dir, mode=0o755, exist_ok=True)
    criteria = []
    domains_before = ""
    if a.stage == "create":
        rep = pf.run_all(pf.Probe("/"), a.config, 30)
        print(pf.render(rep))
        if rep["verdict"] != "READY":
            print("NOT_RUN: the host is not ready for qualification (preflight above)")
            return 0
        ip = bridge_ip(cfg.get("network", ""))
        if not ip:
            print("NOT_RUN: cannot find the host address on the libvirt network %r" % cfg.get("network"))
            return 0
        token, password = secrets.token_hex(16), new_password()
        srv, port, report = start_listener(ip, token)
        try:
            url = "http://%s:%d/%s/report" % (ip, port, token)
            text = answer_file(url, password, a.image_index)
            apath = os.path.join(out_dir, "answer.xml")
            fd = os.open(apath, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w") as f:
                f.write(text)
            rc = subprocess.run(docker_argv("create", a, catalog_dir, gid, out_dir, apath, pool_dir), check=False).returncode  # noqa: S603
            res, crit = read_stage_result(out_dir, "create")
            criteria += crit or [("real-libvirt", FAIL, "the container produced no result (exit %d)" % rc)]
            if rc != 0 and not any(st == FAIL for _, st, _ in crit):
                criteria.append(("qualification-stage", FAIL, "the Go create stage exited %d" % rc))
            domains_before = (res.get("host") or {}).get("domains_before", "")
            if not any(st == FAIL for _, st, _ in criteria):
                print("create stage done; waiting up to %d minutes for the guest to install and report ..." % a.timeout_min, flush=True)
                deadline, last_shot, vm = time.time() + a.timeout_min * 60, 0, res.get("vm_name", "")
                while time.time() < deadline and report.body is None:
                    time.sleep(15)
                    if time.time() - last_shot > 300:
                        screenshot(vm, out_dir, time.strftime("%H%M%S"))
                        last_shot = time.time()
                    if domain_state(vm) == "shut off" and report.body is None:
                        time.sleep(30)  # the guest powers off right after it reports: give the report a moment
                        break
                if report.body is None:
                    screenshot(vm, out_dir, "final")
                client = report.client
                criteria += judge_guest(report.body, client, root_write_bytes(vm), qemu_rtc_localtime(vm), time.localtime().tm_gmtoff, answer_text=text)
                with open(os.path.join(out_dir, "guest-report.json"), "w") as f:
                    json.dump(report.body or {}, f, indent=2)
                deadline = time.time() + 300
                while time.time() < deadline and domain_state(vm) != "shut off":
                    time.sleep(10)
        finally:
            srv.shutdown()
            try:
                os.remove(os.path.join(out_dir, "answer.xml"))  # it holds the one-off password of a VM that is about to be deleted
            except OSError:
                pass
        if not a.keep:
            a.stage = "cleanup"
    if a.stage == "cleanup":
        if not domains_before:
            domains_before = (read_stage_result(out_dir, "create")[0].get("host") or {}).get("domains_before", "")
        rc = subprocess.run(docker_argv("cleanup", a, catalog_dir, gid, out_dir, None, pool_dir, domains_before), check=False).returncode  # noqa: S603
        _, crit = read_stage_result(out_dir, "cleanup")
        criteria += crit or [("cleanup", FAIL, "the container produced no result (exit %d)" % rc)]
    verdict = overall(criteria)
    text = render(a.run_id, criteria, verdict)
    if "PRIVATE KEY" in text or "Password" in text:
        print("ERROR the report contains credential-like material; refusing to write it", file=sys.stderr)
        return 2
    print(text)
    for name, body in (("report-windows.txt", text + "\n"), ("report-windows.json", json.dumps({"run_id": a.run_id, "result": verdict, "criteria":
                       [{"id": c, "status": s, "detail": d} for c, s, d in criteria]}, indent=2) + "\n")):
        with open(os.path.join(out_dir, name), "w") as f:
            f.write(body)
    return 0 if verdict in (PASS, NOT_RUN) else 1


if __name__ == "__main__":
    sys.exit(main())
