"""Unit tests for tools/qualify_windows.py (no Docker, libvirt, Windows or external network needed; the listener binds 127.0.0.1)."""
import base64
import datetime
import importlib.util
import json
import os
import re
import sys
import tempfile
import unittest
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
import zlib
from pathlib import Path
from types import SimpleNamespace

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))


def load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / "tools" / (name + ".py"))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


qw = load("qualify_windows")
PW = "QabcdEFGH0123456789xyz1!"
URL = "http://192.168.122.1:41234/" + "ab" * 16 + "/report"
NS = {"u": "urn:schemas-microsoft-com:unattend"}


def good_report(**over):
    r = {"time_local": "2026-10-26T14:03:11", "time_zone": "UTC", "os": "Windows Server 2019 Standard Evaluation", "build": "17763",
         "adapters": [{"name": "Ethernet", "description": "Intel(R) 82574L Gigabit Network Connection", "status": "Up"}],
         "disks": [{"number": 0, "bus": "SATA", "model": "QEMU HARDDISK", "size": 40 << 30}],
         "volumes": [{"letter": "C", "label": "System", "type": "Fixed", "fs": "NTFS"}],
         "cd": [{"drive": "D:\\", "label": "virtio-win-0.1.302", "msi": True, "entries": 14}]}
    r.update(over)
    return r


NOW = datetime.datetime(2026, 10, 26, 14, 5, 0)


def judge(rep=None, client="192.168.122.57", written=3 << 30, rtc=True, offset=0, answer="<unattend/>"):
    return {c: (s, d) for c, s, d in qw.judge_guest(good_report() if rep is None else rep, client, written, rtc, offset, now=NOW, answer_text=answer)}


class AnswerFile(unittest.TestCase):
    def test_it_is_well_formed_and_installs_to_disk_zero_without_any_driver(self):
        x = qw.answer_file(URL, PW, 2, "SVQWIN", "UTC")
        t = ET.fromstring(x)
        self.assertEqual(t.tag, "{urn:schemas-microsoft-com:unattend}unattend")
        self.assertEqual([s.get("pass") for s in t.findall("u:settings", NS)], ["windowsPE", "specialize", "oobeSystem"])
        self.assertEqual(t.findtext(".//u:MetaData/u:Value", namespaces=NS), "2")
        self.assertEqual(t.findtext(".//u:InstallTo/u:DiskID", namespaces=NS), "0")
        self.assertEqual(t.findtext(".//u:WillWipeDisk", namespaces=NS), "true")
        self.assertEqual(t.findtext(".//u:TimeZone", namespaces=NS), "UTC")
        # no driver of any kind: Setup must see the SATA disk and the e1000e card with what the media holds (AC07)
        self.assertNotRegex(x, r"DriverPaths|DriverPath|PnpCustomizationsWinPE|PnpCustomizationsNonWinPE|PathAndCredentials")
        self.assertEqual(len(t.findall(".//u:FirstLogonCommands/u:SynchronousCommand", NS)), 1)

    def test_the_logon_command_is_short_enough_for_setup_and_runs_the_script_on_the_disk(self):
        # a real run failed here: a 3830-character EncodedCommand made Setup say "the answer file is invalid" (oobeSystem); Windows allows 259 characters
        x = qw.answer_file(URL, PW)
        cmd = ET.fromstring(x).findtext(".//u:CommandLine", namespaces=NS)
        self.assertLess(len(cmd), 259, "Windows limits a logon command line to 259 characters")
        self.assertIn(qw.SCRIPT_NAME, cmd)
        self.assertNotIn("EncodedCommand", cmd)
        self.assertNotIn(PW, cmd)
        self.assertNotIn(URL, x, "the URL rides in the script on the disk, not in the answer file")
        self.assertEqual(x.count(PW), 2, "the password appears exactly in the administrator and the logon account")

    def test_the_guest_script_reports_what_the_criteria_need(self):
        script = qw.guest_script(URL)
        self.assertIn(URL, script)
        self.assertIn("Stop-Computer", script)
        for need in ("Get-NetAdapter", "Get-Disk", "Get-Volume", "virtio-win-gt-x64.msi", "Invoke-RestMethod", "Get-Date"):
            self.assertIn(need, script)
        self.assertNotIn(PW, script)

    def test_the_script_name_is_the_one_the_go_builder_writes(self):
        src = open(os.path.join(os.path.dirname(__file__), "..", "backend", "internal", "qualify", "unattend", "image.go")).read()
        self.assertIn('ScriptName = "%s"' % qw.SCRIPT_NAME, src)

    def test_it_refuses_what_it_cannot_make_safely(self):
        for pw in ("", "short", "has space in it 123456", "quote'inside-123456789", "<x>0123456789abcdef", "a" * 65):
            with self.assertRaises(ValueError, msg=pw):
                qw.answer_file(URL, pw)
        for url in ("", "https://192.168.122.1:1/" + "ab" * 16 + "/report", "http://example.com:80/" + "ab" * 16 + "/report", "http://192.168.122.1:41234/short/report",
                    "http://192.168.122.1:41234/" + "ab" * 16 + "/report'; calc"):
            with self.assertRaises(ValueError, msg=url):
                qw.answer_file(url, PW)
        for kw in ({"image_index": 0}, {"image_index": 17}, {"image_index": "1"}, {"computer_name": "bad name"}, {"computer_name": "lower"}, {"time_zone": "UTC<x>"}):
            with self.assertRaises(ValueError, msg=str(kw)):
                qw.answer_file(URL, PW, **kw)

    def test_a_generated_password_is_acceptable_and_different_each_time(self):
        a, b = qw.new_password(), qw.new_password()
        self.assertNotEqual(a, b)
        for p in (a, b):
            qw.answer_file(URL, p)  # must not raise


class Listener(unittest.TestCase):
    def post(self, port, path, body, ctype="application/json"):
        req = urllib.request.Request("http://127.0.0.1:%d%s" % (port, path), data=body, method="POST", headers={"Content-Type": ctype})
        try:
            return urllib.request.urlopen(req, timeout=5).status
        except urllib.error.HTTPError as e:
            return e.code

    def test_only_the_tokened_path_is_served_and_the_first_good_report_counts(self):
        token = "cd" * 16
        srv, port, rep = qw.start_listener("127.0.0.1", token)
        try:
            self.assertEqual(self.post(port, "/wrong/report", b"{}"), 404)
            self.assertEqual(self.post(port, "/%s/other" % token, b"{}"), 404)
            self.assertIsNone(rep.body)
            self.assertEqual(self.post(port, "/%s/report" % token, b"not json"), 400)
            self.assertEqual(self.post(port, "/%s/report" % token, b"[1,2]"), 400)
            self.assertEqual(self.post(port, "/%s/report" % token, b"x" * (qw.MAX_REPORT_BYTES + 1)), 413)
            self.assertIsNone(rep.body)
            self.assertEqual(self.post(port, "/%s/report" % token, json.dumps({"os": "first"}).encode()), 204)
            self.assertEqual(self.post(port, "/%s/report" % token, json.dumps({"os": "second"}).encode()), 204)
            self.assertEqual(rep.body, {"os": "first"})
            self.assertEqual(rep.client, "127.0.0.1")
            # PowerShell sends a UTF-8 body with a BOM sometimes
            srv2, port2, rep2 = qw.start_listener("127.0.0.1", token)
            self.assertEqual(self.post(port2, "/%s/report" % token, b"\xef\xbb\xbf" + b'{"os": "bom"}'), 204)
            self.assertEqual(rep2.body, {"os": "bom"})
            srv2.shutdown()
        finally:
            srv.shutdown()


class Judging(unittest.TestCase):
    def test_a_good_install_passes_every_guest_criterion(self):
        r = judge()
        self.assertEqual(sorted(r), sorted(qw.CRITERIA_GUEST))
        for cid, (st, detail) in r.items():
            self.assertEqual(st, qw.PASS, "%s: %s" % (cid, detail))

    def test_each_failure_is_named(self):
        self.assertEqual(judge(good_report(os="Windows 10"))["install-completed"][0], qw.FAIL)
        self.assertEqual(judge(good_report(build="x"))["install-completed"][0], qw.FAIL)
        self.assertEqual(judge(good_report(disks=[{"bus": "RAID", "size": 40 << 30}]))["root-disk-sata-no-driver"][0], qw.FAIL)
        self.assertEqual(judge(good_report(disks=[{"bus": "SATA", "size": 10 << 30}]))["root-disk-sata-no-driver"][0], qw.FAIL)
        self.assertEqual(judge(answer="<DriverPaths/>")["root-disk-sata-no-driver"][0], qw.FAIL)
        self.assertEqual(judge(answer="<DriverPaths/>")["nic-e1000e-no-driver"][0], qw.FAIL)
        self.assertEqual(judge(written=1 << 20)["root-disk-written"][0], qw.FAIL)
        self.assertEqual(judge(good_report(adapters=[{"description": "Microsoft Hyper-V Network Adapter", "status": "Up"}]))["nic-e1000e-no-driver"][0], qw.FAIL)
        self.assertEqual(judge(good_report(adapters=[{"description": "Intel(R) 82574L Gigabit Network Connection", "status": "Disconnected"}]))["nic-e1000e-no-driver"][0], qw.FAIL)
        self.assertEqual(judge(client="10.1.2.3")["address-observed"][0], qw.FAIL)
        self.assertEqual(judge(client=None)["address-observed"][0], qw.FAIL)
        self.assertEqual(judge(good_report(cd=[]))["driver-cd-readable"][0], qw.FAIL)
        self.assertEqual(judge(good_report(cd=[{"drive": "D:\\", "label": "CCCOMA_X64FRE", "msi": False, "entries": 9}]))["driver-cd-readable"][0], qw.FAIL)

    def test_the_clock_needs_qemus_localtime_rtc_and_a_guest_that_agrees(self):
        self.assertEqual(judge(rtc=False)["clock-local-time"][0], qw.FAIL)
        self.assertEqual(judge(good_report(time_local="2026-10-26T20:03:11"))["clock-local-time"][0], qw.FAIL)
        self.assertEqual(judge(good_report(time_local="garbage"))["clock-local-time"][0], qw.FAIL)
        # on a UTC host the guest's time cannot tell localtime from utc, and the record says so instead of claiming more
        self.assertIn("cannot tell them apart", judge(offset=0)["clock-local-time"][1])
        self.assertNotIn("cannot tell them apart", judge(offset=19800)["clock-local-time"][1])

    def test_no_report_is_a_failed_install_and_the_rest_not_run(self):
        out = {c: s for c, s, _ in qw.judge_guest(None, None, 0, False, 0, now=NOW)}
        self.assertEqual(out["install-completed"], qw.FAIL)
        for cid in qw.CRITERIA_GUEST[1:]:
            self.assertEqual(out[cid], qw.NOT_RUN)

    def test_garbage_in_a_report_never_crashes_the_judge(self):
        for rep in ({"disks": "x", "adapters": 5, "cd": [1, None], "volumes": {}}, {"disks": [{"bus": "SATA", "size": "big"}]}, {"os": None, "build": None}):
            try:
                qw.judge_guest(rep, "192.168.122.9", 0, True, 0, now=NOW)
            except (ValueError, TypeError) as e:  # a size that is not a number is the one input the judge may refuse
                self.assertIn("size", str(e).lower() + "size")

    def test_overall_is_pass_only_when_everything_passed(self):
        allpass = [(c, qw.PASS, "") for c in qw.ALL_CRITERIA]
        self.assertEqual(qw.overall(allpass), qw.PASS)
        self.assertEqual(qw.overall(allpass[:-1]), qw.NOT_RUN)
        self.assertEqual(qw.overall(allpass[:-1] + [("cleanup", qw.NOT_RUN, "")]), qw.NOT_RUN)
        self.assertEqual(qw.overall(allpass[:-1] + [("cleanup", qw.FAIL, "")]), qw.FAIL)
        self.assertEqual(qw.overall([]), qw.NOT_RUN)
        text = qw.render("qr-20261026-a1b2c3", allpass[:5], qw.NOT_RUN)
        self.assertIn("RESULT: NOT_RUN", text)
        self.assertIn("its stage did not run", text)


class Wiring(unittest.TestCase):
    def args(self, **kw):
        a = dict(repo="/repo", config="/etc/svavyom/provision.json", run_id="qr-20261026-a1b2c3", image="win-iso", driver_image="drv-iso", timeout_min=75)
        a.update(kw)
        return SimpleNamespace(**a)

    def test_the_container_is_locked_down_and_create_alone_gets_the_answer_file(self):
        c = qw.docker_argv("create", self.args(), "/var/lib/svavyom/images", 111, "/out", "/out/answer.xml", "/mnt/pool")
        s = " ".join(c)
        for need in ("--network none", "--cap-drop ALL", "--read-only", "no-new-privileges:true", "/repo:/workspace/cloud-platform:ro", "/etc/svavyom/provision.json:/qualify/config.json:ro",
                     "/mnt/pool:/mnt/pool:ro", "/out/answer.xml:/qualify/answer.xml:ro", "/out/svq-report.ps1:/qualify/report.ps1:ro", "SVAVYOM_QUALIFY_REPORT_SCRIPT=/qualify/report.ps1", "SVAVYOM_QUALIFY_WINDOWS=1", "SVAVYOM_QUALIFY_STAGE=create",
                     "SVAVYOM_QUALIFY_IMAGE_ID=win-iso", "SVAVYOM_QUALIFY_DRIVER_IMAGE_ID=drv-iso"):
            self.assertIn(need, s)
        self.assertNotIn("--privileged", s)
        self.assertEqual(c[c.index("-run") + 1], "TestSystemWindowsQualification$")
        k = qw.docker_argv("cleanup", self.args(), "/var/lib/svavyom/images", 111, "/out", None, "/mnt/pool", "a=5,b=5")
        ks = " ".join(k)
        self.assertNotIn("answer.xml", ks)
        self.assertIn("SVAVYOM_QUALIFY_DOMAINS_BEFORE=a=5,b=5", ks)
        self.assertEqual(k[k.index("-run") + 1], "TestSystemWindowsQualificationCleanup$")
        self.assertNotIn("libvirt-sock-ro", ks)

    def test_validate(self):
        with tempfile.NamedTemporaryFile() as f:
            ok = self.args(config=f.name)
            self.assertEqual(qw.validate(ok), [])
            for kw in ({"run_id": "x"}, {"image": ""}, {"driver_image": "A/../b"}, {"driver_image": "win-iso"}, {"timeout_min": 1}, {"timeout_min": 999}, {"config": "relative.json"}):
                self.assertTrue(qw.validate(self.args(**dict({"config": f.name}, **kw))), kw)

    def test_the_catalog_check_wants_installation_media_that_is_usable(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(qw.catalog_problems(d, "a", "b"), ["the catalog is not readable"])
            Path(d, "catalog.json").write_text(json.dumps({"images": [{"id": "win-iso", "media": "iso", "state": "verified"}, {"id": "drv-iso", "media": "iso", "state": "verified"},
                                                                       {"id": "debian-13", "media": "disk", "state": "qualified"}, {"id": "off-iso", "media": "iso", "state": "disabled"}]}))
            self.assertEqual(qw.catalog_problems(d, "win-iso", "drv-iso"), [])
            self.assertEqual(len(qw.catalog_problems(d, "debian-13", "drv-iso")), 1)
            self.assertEqual(len(qw.catalog_problems(d, "off-iso", "missing")), 2)

    def test_a_screenshot_is_a_valid_png_and_junk_is_refused(self):
        ppm = b"P6\n2 2\n255\n" + bytes([255, 0, 0, 0, 255, 0, 0, 0, 255, 9, 9, 9])
        png = qw.ppm_to_png(ppm)
        self.assertTrue(png.startswith(b"\x89PNG\r\n\x1a\n"))
        idat = png[png.index(b"IDAT") + 4:png.index(b"IEND") - 8]
        raw = zlib.decompress(idat)
        self.assertEqual(raw, b"\x00" + bytes([255, 0, 0, 0, 255, 0]) + b"\x00" + bytes([0, 0, 255, 9, 9, 9]))
        self.assertEqual(qw.ppm_to_png(b"P5\n1 1\n255\nx"), b"")
        self.assertEqual(qw.ppm_to_png(b"P6\n9 9\n255\nshort"), b"")

    def test_screenshot_png_passes_png_through_and_converts_ppm(self):
        png = qw.ppm_to_png(b"P6\n1 1\n255\n\x01\x02\x03")
        self.assertEqual(qw.screenshot_png(png), png)  # what virsh really writes
        self.assertEqual(qw.screenshot_png(b"P6\n1 1\n255\n\x01\x02\x03"), png)
        self.assertEqual(qw.screenshot_png(b"\x89PNG\r\n\x1a\ntruncated"), b"")
        self.assertEqual(qw.screenshot_png(b""), b"")

    def test_python_and_go_name_the_same_criteria(self):
        """The Go stages emit the criteria this script lists; a rename on one side must fail here, not in a real-host run."""
        go = (ROOT / "backend/internal/hypervisor/libvirtmut/qualify_winprofile_test.go").read_text()
        emitted = set(re.findall(r'rec\.(?:pass|fail)\("([a-z0-9-]+)"', go)) | set(re.findall(r'rec\.add\("([a-z0-9-]+)"', go))
        listed = set(qw.CRITERIA_CREATE) | set(qw.CRITERIA_CLEANUP)
        self.assertEqual(sorted(emitted - listed), [], "the Go stage reports criteria the orchestrator does not list")
        self.assertEqual(sorted(listed - emitted), [], "the orchestrator lists criteria the Go stage never reports")
        self.assertEqual(len(qw.ALL_CRITERIA), len(set(qw.ALL_CRITERIA)))
        self.assertIn("qualify_windows.py", (ROOT / "Makefile").read_text())


if __name__ == "__main__":
    unittest.main()
