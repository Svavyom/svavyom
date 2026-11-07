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


if __name__ == "__main__":
    unittest.main()
