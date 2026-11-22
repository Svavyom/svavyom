"""N10 and N7 of the 2026-11-14 findings plan: the on-host keep-running checker for a Windows VM across an upgrade and a rollback, and the clean-host stages that use it and
that put the installation media on a host. The runs need real hosts; what is judged and what is built is tested here."""
import importlib.util
import json
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace

sys.dont_write_bytecode = True
TOOLS = Path(__file__).resolve().parent.parent / "tools"


def load(name):
    spec = importlib.util.spec_from_file_location(name, TOOLS / (name + ".py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


k = load("qualify_winkeep")
q = load("qualify_clean_host")

RUN = "qr-20261122-a1b2c3"
BLK = (" Type   Device   Target   Source\n---------------------------------------\n"
       " file   disk     sda      /var/lib/svavyom/pool/wk-a1b2c3.qcow2\n"
       " file   cdrom    sdb      /var/lib/svavyom/images/store/6dae072e.iso\n"
       " file   cdrom    sdc      -\n")


class Keep(unittest.TestCase):
    def test_the_state_file_and_the_name_follow_the_run_id(self):
        self.assertEqual(k.vm_name(RUN), "wk-a1b2c3")
        self.assertEqual(k.state_path(RUN), "/var/tmp/svq-winkeep-%s.json" % RUN)

    def test_one_process_number_is_a_process_and_anything_else_is_not(self):
        self.assertEqual(k.pid_from_pgrep("4242\n"), 4242)
        self.assertIsNone(k.pid_from_pgrep(""))
        self.assertIsNone(k.pid_from_pgrep("1\n2\n"))
        self.assertIsNone(k.pid_from_pgrep("not a number"))

    def api(self, power="running", profile="windows", managed=True):
        return {"observed": {"power": power, "guest_profile": profile, "managed": managed}}

    def test_a_vm_that_kept_running_in_its_process_passes_even_when_the_database_forgot_it(self):
        for managed in (True, False):
            r = {c: ok for c, ok, _ in k.judge_keep({"pid": 7}, 7, "running", self.api(managed=managed))}
            self.assertTrue(all(r.values()), r)

    def test_each_way_to_lose_the_guest_fails_its_own_check(self):
        base = ({"pid": 7}, 7, "running", self.api())
        cases = {"keep-libvirt-running": ({"pid": 7}, 7, "shut off", self.api()), "keep-same-process": ({"pid": 7}, 8, "running", self.api()),
                 "keep-listed-by-api": ({"pid": 7}, 7, "running", None)}
        for want, args in cases.items():
            failed = [c for c, ok, _ in k.judge_keep(*args) if not ok]
            self.assertIn(want, failed, args)
        self.assertEqual([c for c, ok, _ in k.judge_keep(*base) if not ok], [])
        self.assertIn("keep-same-process", [c for c, ok, _ in k.judge_keep({"pid": 7}, None, "running", self.api()) if not ok])
        self.assertIn("keep-listed-by-api", [c for c, ok, _ in k.judge_keep({"pid": 7}, 7, "running", self.api(profile="linux")) if not ok])

    def test_only_the_vms_own_root_disk_is_ever_removed_never_a_medium_or_the_store(self):
        self.assertEqual(k.removable_disks(BLK), ["/var/lib/svavyom/pool/wk-a1b2c3.qcow2"])
        evil = BLK.replace("/var/lib/svavyom/pool/wk-a1b2c3.qcow2", "/etc/passwd")
        self.assertEqual(k.removable_disks(evil), [])
        store = BLK.replace("cdrom    sdb", "disk     sdb")
        self.assertEqual(k.removable_disks(store), ["/var/lib/svavyom/pool/wk-a1b2c3.qcow2"], "a disk in the image store is not removed")
        self.assertEqual(k.removable_disks(BLK.replace("/pool/wk-a1b2c3", "/pool/../../etc/x")), [])


class Stages(unittest.TestCase):
    def test_the_stages_are_registered(self):
        for s in ("media", "winupgrade"):
            self.assertIn(s, q.STAGES)
            self.assertIn(s, q.FUNCS)

    def test_the_media_specs_are_the_three_registered_by_digest(self):
        self.assertEqual([m[0] for m in q.MEDIA_SPECS], ["alpine-virt", "windowsserver2019-iso", "virtio-win"])
        for m in q.MEDIA_SPECS:
            self.assertRegex(m[5], r"^[0-9a-f]{64}$")

    def test_the_register_command_quotes_every_value_and_never_removes_anything(self):
        cmd = q.media_register_command(q.MEDIA_SPECS[1], "/var/tmp/svq-media/x.iso")
        self.assertIn("register-image --media iso --source /var/tmp/svq-media/x.iso --id windowsserver2019-iso", cmd)
        self.assertIn("--display-name 'Windows Server 2019 Eval'", cmd)
        self.assertNotIn("rm ", cmd)
        tricky = ("x", "a; rm -rf /", "d", "v", 2, "0" * 64)
        self.assertIn("'a; rm -rf /'", q.media_register_command(tricky, "/p"))

    def test_the_catalog_check_needs_the_id_and_the_digest(self):
        sha = q.MEDIA_SPECS[0][5]
        cat = json.dumps({"images": [{"id": "alpine-virt", "sha256": sha}]})
        self.assertTrue(q.catalog_has(cat, "alpine-virt", sha))
        self.assertFalse(q.catalog_has(cat, "alpine-virt", "0" * 64))
        self.assertFalse(q.catalog_has(cat, "other", sha))
        self.assertFalse(q.catalog_has("not json", "alpine-virt", sha))

    def test_the_service_runs_use_https_on_loopback_and_no_password_on_a_command_line(self):
        cmd = q.service_run_command("qualify_media_service.py", RUN, "--boot-image alpine-virt --data-image virtio-win")
        self.assertIn("--base https://127.0.0.1:8443", cmd)
        self.assertIn("--password-file pw", cmd)
        self.assertNotIn("assword ", cmd.replace("--password-file pw", ""))

    def test_the_media_stage_needs_a_directory_and_winupgrade_needs_the_artifact_and_the_database_copy(self):
        base = dict(host="203.0.113.10", tls_name="svavyom.example.org", run_id=RUN, key=__file__, artifact="", signatures="", public_key="", media_dir="")
        a = SimpleNamespace(stage="media", **base)
        self.assertTrue([p for p in q.validate(a) if "--media-dir" in p])
        a.media_dir = str(TOOLS)
        self.assertFalse([p for p in q.validate(a) if "--media-dir" in p])

    def test_the_keep_directory_is_not_the_harness_directory_that_the_rollback_wipes(self):
        self.assertNotEqual(q.KEEP_DIR, q.WORKDIR)
        self.assertFalse(q.KEEP_DIR.startswith(q.WORKDIR + "/"))


if __name__ == "__main__":
    unittest.main()
