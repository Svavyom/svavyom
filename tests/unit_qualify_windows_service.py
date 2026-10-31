"""Unit tests of tools/qualify_windows_service.py: the definition checker on a real libvirt dump (sanitised) and on deliberate breakages, the argument rules, and
that every criterion the harness names is one it records. The run itself needs an installed Svavyom and is not part of make check."""
import importlib.util
import os
import re
import unittest
from types import SimpleNamespace

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
spec = importlib.util.spec_from_file_location("qws", os.path.join(ROOT, "tools", "qualify_windows_service.py"))
q = importlib.util.module_from_spec(spec)
spec.loader.exec_module(q)
GOOD = open(os.path.join(HERE, "fixtures", "libvirt-windows-two-cds.xml")).read()


def args(**kw):
    a = dict(run_id="qr-20261031-a1b2c3", image="win-iso", driver_image="drv-iso", base="http://127.0.0.1:8443", password_file=__file__)
    a.update(kw)
    return SimpleNamespace(**a)


class Definition(unittest.TestCase):
    def test_a_real_libvirt_dump_of_the_profile_is_accepted(self):
        self.assertEqual(q.windows_definition_problems(GOOD, 2), [])

    def test_the_count_of_media_is_checked(self):
        self.assertTrue(q.windows_definition_problems(GOOD, 1))
        one = re.sub(r"\s*<disk type='file' device='cdrom'>(?:(?!</disk>).)*?<target dev='sdc'.*?</disk>", "", GOOD, flags=re.S)
        self.assertNotEqual(one, GOOD)
        self.assertEqual(q.windows_definition_problems(one, 1), [])
        self.assertTrue(q.windows_definition_problems(one, 2))

    def test_each_breakage_is_named(self):
        cases = [
            ("machine='pc-q35-noble'", "machine='pc-i440fx-noble'", "q35"),
            ("<clock offset='localtime'>", "<clock offset='utc'>", "localtime"),
            ("<timer name='hypervclock' present='yes'/>", "", "hypervclock"),
            ("<model type='e1000e'/>", "<model type='virtio'/>", "e1000e"),
            ("<target dev='sda' bus='sata'/>", "<target dev='vda' bus='virtio'/>", "sda"),
            ("<os>", "<os firmware='efi'>", "UEFI"),
        ]
        for old, new, word in cases:
            self.assertIn(old, GOOD, old)
            bad = q.windows_definition_problems(GOOD.replace(old, new, 1), 2)
            self.assertTrue(any(word in b for b in bad), (word, bad))

    def test_the_second_medium_must_not_boot(self):
        i = GOOD.index("<target dev='sdc'")
        j = GOOD.index("<readonly/>", i) + len("<readonly/>")
        bad = q.windows_definition_problems(GOOD[:j] + "<boot order='3'/>" + GOOD[j:], 2)
        self.assertTrue(any("boot order" in b for b in bad), bad)

    def test_junk_is_refused(self):
        self.assertEqual(q.windows_definition_problems("not xml", 2), ["the definition is not XML"])


class Arguments(unittest.TestCase):
    def test_good_arguments(self):
        self.assertEqual(q.problems(args()), [])

    def test_bad_arguments(self):
        for kw in ({"run_id": "x"}, {"image": "Upper"}, {"driver_image": "a/../b"}, {"driver_image": "win-iso"}, {"base": "https://example.org:8443"}, {"base": "http://10.0.0.5:8443"},
                   {"password_file": "/nonexistent/pw"}):
            self.assertTrue(q.problems(args(**kw)), kw)


class Wiring(unittest.TestCase):
    def test_every_criterion_is_recorded_by_the_harness(self):
        src = open(os.path.join(ROOT, "tools", "qualify_windows_service.py")).read()
        for c in q.CRITERIA:
            self.assertIn('"%s"' % c, src.split("def main", 1)[1], c)

    def test_it_never_uses_sudo_or_prints_a_password(self):
        src = open(os.path.join(ROOT, "tools", "qualify_windows_service.py")).read()
        self.assertNotIn('"sudo"', src)
        self.assertNotIn("print(pw", src)


if __name__ == "__main__":
    unittest.main()
