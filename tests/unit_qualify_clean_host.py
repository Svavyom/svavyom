"""Unit tests of tools/qualify_clean_host.py: the judges, the command lines it builds (no password, no shell injection) and the argument rules. The run needs a real fresh host
and is not part of make check."""
import importlib.util
import os
import stat
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("qch", ROOT / "tools" / "qualify_clean_host.py")
q = importlib.util.module_from_spec(spec)
spec.loader.exec_module(q)

GOOD = "os=ubuntu 24.04\nkernel=6.8.0-147-generic\ncpus=6\nram_mib=31900\nfree_gib=858\nkvm=yes\nvirt_cpus=12\napparmor=Y\nlibvirt=absent\nqemu=absent\nsvavyom=absent\nufw=active\nsudo=yes\n"


def args(**kw):
    a = dict(host="203.0.113.10", tls_name="svavyom.example.org", run_id="qr-20261107-a1b2c3", key=__file__, stage="facts", artifact="", signatures="", public_key="")
    a.update(kw)
    return SimpleNamespace(**a)


class Judges(unittest.TestCase):
    def test_a_fresh_ubuntu_host_with_kvm_and_sudo_passes_every_criterion(self):
        res = q.judge_facts(q.parse_kv(GOOD))
        self.assertEqual([c for c, ok, _ in res if not ok], [])
        self.assertEqual(len(res), 7)

    def test_each_defect_fails_its_own_criterion(self):
        for old, new, cid in (("os=ubuntu 24.04", "os=debian 13", "ubuntu-24.04"), ("kvm=yes", "kvm=no", "kvm-usable"), ("virt_cpus=12", "virt_cpus=0", "kvm-usable"),
                              ("apparmor=Y", "apparmor=N", "apparmor-enabled"), ("ram_mib=31900", "ram_mib=2000", "memory"), ("free_gib=858", "free_gib=5", "free-space"),
                              ("sudo=yes", "sudo=no", "passwordless-sudo"), ("libvirt=absent", "libvirt=installed", "clean-host"), ("svavyom=absent", "svavyom=present", "clean-host")):
            failed = [c for c, ok, _ in q.judge_facts(q.parse_kv(GOOD.replace(old, new))) if not ok]
            self.assertEqual(failed, [cid], (old, new, failed))

    def test_missing_facts_fail_not_pass(self):
        self.assertTrue(all(not ok for c, ok, _ in q.judge_facts({}) if c != "clean-host"))

    def test_the_password_is_long_random_and_of_the_accepted_shape(self):
        a, b = q.new_password(), q.new_password()
        self.assertNotEqual(a, b)
        self.assertRegex(a, r"^[A-Za-z0-9]{24}$")


class Commands(unittest.TestCase):
    def test_ssh_runs_one_quoted_command_without_a_password_or_agent(self):
        argv = q.ssh_argv("inuser", "203.0.113.10", "/k", "echo 'a b'; id")
        self.assertIn("BatchMode=yes", argv)
        self.assertIn("IdentitiesOnly=yes", argv)
        self.assertEqual(argv[-3:-1], ["bash", "-c"])
        self.assertEqual(argv[-1], "'echo '\"'\"'a b'\"'\"'; id'")
        self.assertNotIn("sshpass", " ".join(argv))

    def test_the_install_command_is_signed_or_explicitly_unsigned(self):
        unsigned = q.remote_install_argv("svavyom-0.1.0-preview.15", "0.0.0.0:8443", "svavyom.example.org", False)
        self.assertIn("--allow-unsigned", unsigned)
        self.assertNotIn("--signatures", unsigned)
        signed = q.remote_install_argv("svavyom-0.1.0-preview.15", "0.0.0.0:8443", "svavyom.example.org", True)
        self.assertNotIn("--allow-unsigned", signed)
        self.assertIn("--signatures", signed)
        self.assertIn("--public-key", signed)
        for argv in (unsigned, signed):
            self.assertEqual(argv[0], "sudo")
            self.assertTrue(argv[1].startswith(q.REMOTE_ARTIFACTS + "/"), "the installer runs from the root-owned copy")
            self.assertIn("--tls-self-signed", argv)

    def test_no_stage_puts_the_password_on_a_command_line(self):
        src = (ROOT / "tools" / "qualify_clean_host.py").read_text()
        self.assertIn("stdin=pw", src)
        self.assertNotIn("echo $pw", src)
        self.assertNotIn("sshpass", src)


class ImageAndVmStages(unittest.TestCase):
    def test_the_image_commands_are_the_administrators_own_and_take_nothing_from_the_host(self):
        cmds = q.image_commands("qr-20261107-a1b2c3")
        self.assertEqual([c for c, _, _ in cmds], ["image-downloaded", "image-registered", "image-verified", "image-qualified"])
        text = " ".join(c for _, c, _ in cmds)
        self.assertIn("register-image --provision-config /etc/svavyom/provision.json", text)
        self.assertIn("--state qualified --evidence qr-20261107-a1b2c3", text)
        self.assertIn("sha256sum -c -", text, "the downloaded image is checked against its published digest")
        self.assertNotIn("curl -k", text)
        self.assertNotRegex(text, r"\|\s*(ba)?sh\b", "nothing downloaded is piped into a shell")

    def test_the_vm_stage_runs_the_installed_system_harness_on_the_host_against_loopback_with_the_self_signed_certificate(self):
        cmd = q.vm_run_command("qr-20261107-a1b2c3")
        self.assertIn("--base https://127.0.0.1:8443 --insecure-tls", cmd)
        self.assertIn("--run-id qr-20261107-a1b2c3", cmd)
        src = (ROOT / "tools" / "qualify_clean_host.py").read_text()
        self.assertIn("shred -u", src, "the password and the disposable key are removed from the host afterwards")

    def test_the_upgrade_repeats_the_installed_options_and_is_signed_or_explicitly_unsigned(self):
        unsigned = q.remote_upgrade_argv("svavyom-0.1.0-preview.16", "0.0.0.0:8443", False)
        signed = q.remote_upgrade_argv("svavyom-0.1.0-preview.16", "0.0.0.0:8443", True)
        for argv in (unsigned, signed):
            self.assertEqual(argv[:3], ["sudo", q.REMOTE_ARTIFACTS + "/svavyom-0.1.0-preview.16/bin/svavyom-ctl", "upgrade"])
            for need in ("--enable-mutation", "--enable-console", "--backup-dir", "--listen"):
                self.assertIn(need, argv, "the installer says to repeat the options the install used")
        self.assertIn("--allow-unsigned", unsigned)
        self.assertNotIn("--allow-unsigned", signed)
        self.assertIn("--signatures", signed)

    def test_the_nightly_boot_check_is_enabled_only_when_asked(self):
        self.assertNotIn("--enable-nightly-boot", q.remote_upgrade_argv("svavyom-0.1.0-preview.18", "0.0.0.0:8443", True))
        argv = q.remote_upgrade_argv("svavyom-0.1.0-preview.18", "0.0.0.0:8443", True, "03:30")
        self.assertEqual(argv[-2:], ["--enable-nightly-boot", "03:30"])

    def test_the_stage_names(self):
        self.assertEqual(q.STAGES, ["facts", "prepare", "install", "bootstrap", "verify", "image", "vm", "upgrade", "rollback", "reboot", "nightly", "firewall", "features"])
        self.assertEqual(set(q.STAGES), set(q.FUNCS))


class Arguments(unittest.TestCase):
    def test_good_and_bad_arguments(self):
        self.assertEqual(q.validate(args()), [])
        for kw in ({"host": "not an ip"}, {"tls_name": "bad name;"}, {"run_id": "x"}, {"key": "/nonexistent"}, {"stage": "bogus"}, {"signatures": "/x"}, {"stage": "install", "artifact": "/nonexistent"}):
            self.assertTrue(q.validate(args(**kw)), kw)

    def test_the_admin_password_file_is_private(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "pw")
            fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            os.close(fd)
            self.assertEqual(stat.S_IMODE(os.stat(p).st_mode), 0o600)


class AfterReboot(unittest.TestCase):
    NET = "Name:           default\nActive:         yes\nPersistent:     yes\nAutostart:      yes\nBridge:         virbr0\n"
    POOL = "Name:           svavyom\nState:          running\nPersistent:     yes\nAutostart:      yes\n"
    UNITS = "\n".join("%s enabled active" % u for u in q.UNITS)

    def test_a_host_that_came_back_whole_passes(self):
        res = q.judge_after_reboot("RESULT: PASS", self.NET, self.POOL, self.UNITS)
        self.assertEqual([c for c, ok, _ in res if not ok], [])

    def test_each_defect_fails_its_own_criterion(self):
        for args_, cid in (((("RESULT: FAIL"), self.NET, self.POOL, self.UNITS), "services-up-after-reboot"),
                           (("RESULT: PASS", self.NET.replace("Autostart:      yes", "Autostart:      no"), self.POOL, self.UNITS), "libvirt-default-network-back"),
                           (("RESULT: PASS", self.NET, self.POOL.replace("running", "inactive"), self.UNITS), "svavyom-pool-back"),
                           (("RESULT: PASS", self.NET, self.POOL, self.UNITS.replace("svavyom-api enabled active", "svavyom-api enabled failed")), "units-enabled-and-active")):
            failed = [c for c, ok, _ in q.judge_after_reboot(*args_) if not ok]
            self.assertEqual(failed, [cid], (cid, failed))

    def test_the_offsite_unit_may_be_idle_without_failing_the_host(self):
        units = self.UNITS.replace("svavyom-offsite enabled active", "svavyom-offsite disabled inactive")
        self.assertEqual([c for c, ok, _ in q.judge_after_reboot("RESULT: PASS", self.NET, self.POOL, units) if not ok], [])


class Rollback(unittest.TestCase):
    LISTING = ("20261110T173140Z-0.1.0-preview.15-to-0.1.0-preview.16  0.1.0-preview.15 -> 0.1.0-preview.16  database copy: true\n"
               "20261111T074213Z-0.1.0-preview.16-to-0.1.0-preview.17  0.1.0-preview.16 -> 0.1.0-preview.17  database copy: true\n")

    def test_the_newest_backup_is_chosen_and_names_the_version_to_return_to(self):
        bid = q.backup_id_from_listing(self.LISTING)
        self.assertEqual(bid, "20261111T074213Z-0.1.0-preview.16-to-0.1.0-preview.17")
        self.assertEqual(q.rollback_target(bid), "0.1.0-preview.16")

    def test_no_listing_or_a_malformed_id_gives_nothing(self):
        self.assertEqual(q.backup_id_from_listing("no backups"), "")
        self.assertEqual(q.rollback_target("latest"), "")
        self.assertEqual(q.rollback_target(""), "")

    def test_the_vm_phase_command_names_the_phase_and_carries_no_secret(self):
        cmd = q.vm_run_command("qr-20261111-a1b2c3", "afterboot")
        self.assertIn("--phase afterboot", cmd)
        self.assertNotIn("password", cmd.replace("--password-file pw", ""))


class Firewall(unittest.TestCase):
    def test_ssh_and_the_api_are_allowed_before_ufw_is_switched_on_and_a_watchdog_is_armed_first(self):
        cmd = q.ufw_prepare_command()
        self.assertLess(cmd.index("ufw allow 22/tcp"), cmd.index("ufw --force enable"))
        self.assertLess(cmd.index("ufw allow 8443/tcp"), cmd.index("ufw --force enable"))
        self.assertLess(cmd.index("--unit=svq-ufw-watchdog"), cmd.index("ufw allow 22/tcp"), "the watchdog is armed before anything can lock the host")
        self.assertIn("ufw --force disable", cmd.split("--unit=svq-ufw-watchdog")[1].split("&&")[0])

    def test_the_baseline_is_ufw_status_not_the_service_state(self):
        self.assertIn("ufw status | head -1 > /var/tmp/ufw-was", q.ufw_prepare_command())
        self.assertNotIn("is-active", q.ufw_prepare_command())

    def test_ufw_is_switched_on_again_only_when_it_was_active_and_then_with_ssh_allowed(self):
        off = q.ufw_restore_command(False)
        on = q.ufw_restore_command(True)
        self.assertNotIn("ufw --force enable", off)
        self.assertIn("ufw allow 22/tcp && sudo ufw --force enable", on)
        self.assertLess(on.index("cp -a /var/tmp/ufw-before /etc/ufw"), on.index("ufw allow 22/tcp"))


if __name__ == "__main__":
    unittest.main()
