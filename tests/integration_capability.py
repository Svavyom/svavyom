"""Capability-checker CLI integration and fault tests (story M0-E02-S05 AC03, tier T1 container_integration, simulated).

Builds the release CLI and a fault-injection build (-tags capability_fault), reads the support matrix at the
pinned docs commit (DOCS_REPO) and runs the CLI on fixture roots and on --root / inside the pinned container.
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FIX = ROOT / "tests" / "fixtures" / "distribution"
HAVE = shutil.which("go") and os.environ.get("DOCS_REPO")


@unittest.skipUnless(HAVE, "needs the Go toolchain and DOCS_REPO (pinned dev container / make check)")
class CLI(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp(prefix="capability-"))
        cls.bin = cls.tmp / "capability-check"
        cls.fault = cls.tmp / "capability-check-fault"
        for out, tags in ((cls.bin, []), (cls.fault, ["-tags", "capability_fault"])):
            subprocess.run(["go", "build", *tags, "-o", str(out), "./cmd/capability-check"], cwd=ROOT / "backend", check=True)
        cls.matrix = cls.tmp / "support-matrix.json"
        subprocess.run([sys.executable, str(ROOT / "tools" / "support_matrix.py"), "--docs-repo", os.environ["DOCS_REPO"],
                        "--out", str(cls.matrix)], check=True, stdout=subprocess.DEVNULL)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def cli(self, root, binary=None, env=None, timeout=60):
        start = time.monotonic()
        proc = subprocess.run([str(binary or self.bin), "--root", str(root), "--matrix", str(self.matrix)],
                              capture_output=True, timeout=timeout, env=dict(os.environ, **(env or {})))
        return proc.returncode, proc.stdout, time.monotonic() - start

    def test_supported_fixtures_match_golden_and_rerun_identical(self):
        for name in ("debian-13", "ubuntu-24.04", "ubuntu-26.04"):
            rc, out, _ = self.cli(FIX / "roots" / name)
            self.assertEqual(rc, 0, name)
            self.assertEqual(out, (FIX / "expected-reports" / ("%s.json" % name)).read_bytes(), name)
            self.assertEqual(self.cli(FIX / "roots" / name)[1], out, "re-run must be byte-identical")

    def test_dev_container_is_containerized_unknown(self):
        if not Path("/.dockerenv").exists() and not Path("/run/.containerenv").exists():
            self.skipTest("not running inside a container")
        rc, out, _ = self.cli("/")
        report = json.loads(out)
        self.assertEqual((rc, report["verdict"], report["reasons"]), (11, "unknown", ["CONTAINERIZED"]))
        self.assertEqual(report["qualification"], "none")

    def test_slow_probe_times_out_within_deadline_never_supported(self):
        deadline = json.loads(self.matrix.read_text())["deadlines_ms"]["run"] / 1000
        for probe in ("cpu_virt", "lsm", "containment"):
            rc, out, elapsed = self.cli(FIX / "roots" / "debian-13", self.fault, {"CAPABILITY_FAULT": "slow:%s" % probe})
            report = json.loads(out)
            self.assertEqual(rc, 11, probe)
            self.assertLess(elapsed, deadline + 5, probe)
            self.assertEqual(next(p for p in report["probes"] if p["id"] == probe)["reason"], "TIMEOUT")

    def test_vanishing_file_is_unknown(self):
        cases = {"proc/cpuinfo": "cpu_virt", "sys/kernel/security/lsm": "lsm", "proc/self/uid_map": "containment",
                 "sys/fs/cgroup/cgroup.controllers": "cgroup_v2", "proc/sys/kernel/osrelease": "kernel_floor"}
        for path, probe in cases.items():
            rc, out, _ = self.cli(FIX / "roots" / "debian-13", self.fault, {"CAPABILITY_FAULT": "vanish:%s" % path})
            report = json.loads(out)
            result = next(p for p in report["probes"] if p["id"] == probe)
            self.assertEqual((rc, report["verdict"], result["result"]), (11, "unknown", "unknown"), path)

    def test_unreadable_file_is_unknown(self):
        work = self.tmp / "unreadable"
        shutil.copytree(FIX / "roots" / "debian-13", work, symlinks=True)
        os.chmod(work / "proc" / "1" / "environ", 0)
        try:
            rc, out, _ = self.cli(work)
        finally:
            os.chmod(work / "proc" / "1" / "environ", 0o644)
        self.assertEqual((rc, json.loads(out)["verdict"]), (11, "unknown"))

    def test_release_binary_ignores_fault_environment(self):
        rc, out, _ = self.cli(FIX / "roots" / "debian-13", env={"CAPABILITY_FAULT": "slow:cpu_virt,vanish:proc/cpuinfo"})
        self.assertEqual(rc, 0)

    def test_checker_writes_nothing_into_the_root(self):
        work = self.tmp / "ro"
        shutil.copytree(FIX / "roots" / "ubuntu-24.04", work, symlinks=True)
        before = sorted((p.relative_to(work), p.stat().st_mtime_ns) for p in work.rglob("*") if not p.is_symlink())
        self.cli(work)
        after = sorted((p.relative_to(work), p.stat().st_mtime_ns) for p in work.rglob("*") if not p.is_symlink())
        self.assertEqual(before, after)


if __name__ == "__main__":
    unittest.main()
