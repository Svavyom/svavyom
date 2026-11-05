"""Unit tests of tools/qualify_media_service.py (M6-E01-S07 AC08): the definition and drive-report judges on a real libvirt dump with two CDs and on deliberate
breakages, the argument rules, and that every criterion named is one the harness records. The run itself needs an installed Svavyom and is not part of make check."""
import importlib.util
import os
import re
import unittest
from types import SimpleNamespace

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
spec = importlib.util.spec_from_file_location("qms", os.path.join(ROOT, "tools", "qualify_media_service.py"))
q = importlib.util.module_from_spec(spec)
spec.loader.exec_module(q)
with open(os.path.join(ROOT, "backend", "internal", "provision", "testdata", "libvirt-dump-two-cds.xml")) as f:
    TWO = f.read()
A, B = "6dae072e7f78f4ccab74a45341de0d6e2d45c39be25f1f5920a2ab4f51d7bcbb", "303f7ae40dad495d6ae474fdc571df58958a4dbc5c37a522d80f9a203867949d"


def args(**kw):
    a = dict(run_id="qr-20261031-a1b2c3", boot_image="alpine-virt", data_image="virtio-win", base="http://127.0.0.1:8443", password_file=__file__)
    a.update(kw)
    return SimpleNamespace(**a)


class Definition(unittest.TestCase):
    def test_a_real_libvirt_dump_with_two_media_is_accepted(self):
        self.assertEqual(q.media_problems(TWO, [A, B]), [])
        self.assertEqual([(c[1], c[2], c[3]) for c in q.cd_list(TWO)], [(A, True, "1"), (B, True, None)])

    def test_wrong_media_or_order_is_named(self):
        self.assertTrue(any("expected" in b for b in q.media_problems(TWO, [B, A])))
        self.assertTrue(any("expected" in b for b in q.media_problems(TWO, [A])))

    def test_the_second_medium_must_not_boot_and_must_be_read_only(self):
        i = TWO.index("<target dev='sdb'")
        j = TWO.index("<readonly/>", i)
        bad = q.media_problems(TWO[:j] + "<boot order='3'/>" + TWO[j:], [A, B])
        self.assertTrue(any("boot order" in b for b in bad), bad)
        bad = q.media_problems(TWO[:j] + TWO[j + len("<readonly/>"):], [A, B])
        self.assertTrue(any("read-only" in b for b in bad), bad)

    def test_junk_and_missing_root_disk_are_refused(self):
        self.assertEqual(q.media_problems("not xml", [A]), ["the definition is not XML"])
        self.assertIsNone(q.cd_list("not xml"))
        self.assertTrue(any("root disks" in b for b in q.media_problems(re.sub(r"<disk type='file' device='disk'>.*?</disk>", "", TWO, count=1, flags=re.S), [A, B])))


class Guest(unittest.TestCase):
    OK = "login: root\nQMEDIA-BEGIN\n/dev/sr0 SIZE=135168\n/dev/sr1 SIZE=1713620\nNAME=\"Alpine Linux\"\nQMEDIA-END\n"
    SIZES = [135168 * 512, 1713620 * 512]

    def test_both_drives_and_the_first_system(self):
        self.assertEqual(q.drive_report_problems(self.OK, self.SIZES), ([], []))

    def test_one_drive_wrong_size_or_wrong_system(self):
        one = self.OK.replace("/dev/sr1 SIZE=1713620\n", "")
        sees, _ = q.drive_report_problems(one, self.SIZES)
        self.assertTrue(sees)
        wrong = self.OK.replace("1713620", "99")
        self.assertTrue(q.drive_report_problems(wrong, self.SIZES)[0])
        _, boot = q.drive_report_problems(self.OK.replace("Alpine", "Debian"), self.SIZES)
        self.assertTrue(boot)

    def test_the_echo_of_the_typed_command_is_not_judged(self):
        # a real run read the echoed command line (it named both markers) and found no drives; the output after it is what counts
        echo = "localhost:~# echo QMEDIA-BEGIN; for d in /dev/sr*; do echo $d; done; echo QMEDIA-END\n"
        self.assertEqual(q.drive_report_problems(echo + self.OK, self.SIZES), ([], []))
        sees, boot = q.drive_report_problems(echo, self.SIZES)
        self.assertTrue(sees and boot, "the echo alone must not pass")

    def test_the_probe_does_not_print_its_markers_in_its_own_echo(self):
        with open(os.path.join(ROOT, "tools", "qualify_media_service.py")) as f:
            src = f.read()
        self.assertIn("echo QMEDIA-BE''GIN", src)
        self.assertIn("echo QMEDIA-E''ND", src)

    def test_no_markers_is_a_failure_not_a_pass(self):
        sees, boot = q.drive_report_problems("login:", self.SIZES)
        self.assertTrue(sees and boot)


class Arguments(unittest.TestCase):
    def test_good_arguments(self):
        self.assertEqual(q.problems(args()), [])

    def test_bad_arguments(self):
        for kw in ({"run_id": "x"}, {"boot_image": "Upper"}, {"data_image": "a/../b"}, {"data_image": "alpine-virt"}, {"base": "https://example.org:8443"}, {"base": "http://10.0.0.5:8443"},
                   {"password_file": "/nonexistent/pw"}):
            self.assertTrue(q.problems(args(**kw)), kw)


class Wiring(unittest.TestCase):
    def test_every_criterion_is_recorded_and_there_is_no_sudo(self):
        with open(os.path.join(ROOT, "tools", "qualify_media_service.py")) as f:
            src = f.read()
        body = src.split("def main", 1)[1]
        for c in q.CRITERIA:
            self.assertIn('"%s"' % c, body, c)
        self.assertNotIn('"sudo"', src)


if __name__ == "__main__":
    unittest.main()
