"""Recorder fault-injection and replay tests (story M0-E02-S04 AC03, tier T1 container_integration, simulated).

Real subprocesses, process groups, signals and git repositories; the pinned container is replaced by
tests/fixtures/evidence/fake_runner.py so the tests run inside the dev container as well as on the host.
"""
import argparse
import importlib.util
import json
import os
import signal
import subprocess
import sys
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FIX = ROOT / "tests" / "fixtures" / "evidence"
_spec = importlib.util.spec_from_file_location("evidence_harness", FIX / "harness.py")
h = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(h)
rec_mod = h.load("record_evidence")
replay_mod = h.load("replay_evidence")
PY = h.PY_UNIT + "::Demo.test_ok"
IMAGE = "sha256:" + "a" * 64


def fake_launcher(mode):
    def launch(command, root, docs_repo):
        refs = command[command.index("--") + 1:] if "--" in command else []
        return [sys.executable, str(FIX / "fake_runner.py"), mode, *refs], dict(os.environ)
    return launch


def args(world, **kw):
    base = dict(docs_repo=str(world.docs), story=h.STORY, ac=["%s-AC01" % h.STORY], test=[PY], gate=None, timeout=60,
                run_by="agent", run_by_name=None, not_run=None, blocked=None, reason=None)
    base.update(kw)
    return argparse.Namespace(**base)


def records(world):
    return sorted(p.name for p in (world.root / "evidence/records").glob("*.json"))


class Recorder(unittest.TestCase):
    def setUp(self):
        self.w = h.World()
        self.addCleanup(self.w.close)
        self.w.patch(self)

    def record(self, mode, **kw):
        return rec_mod.build(args(self.w, **kw), root=self.w.root, launch=fake_launcher(mode), image=lambda: IMAGE)

    def test_pass_record_is_valid_and_host_paths_removed(self):
        path, rec = self.record("pass")
        self.assertEqual(rec["result"], "PASS")
        self.assertEqual(self.w.codes(), [])
        log = (self.w.root / rec["log"]["path"]).read_text()
        self.assertNotIn(str(Path.home()), log) if str(Path.home()) != "/" else None
        self.assertNotIn(str(self.w.root), log)

    def test_crash_yields_fail_never_pass(self):
        _, rec = self.record("crash")
        self.assertEqual((rec["result"], rec["exit_code"]), ("FAIL", 3))
        self.assertEqual(self.w.codes(), [])

    def test_failing_test_yields_fail(self):
        _, rec = self.record("fail")
        self.assertEqual(rec["result"], "FAIL")
        self.assertEqual(self.w.codes(), [])

    def test_timeout_kills_group_and_yields_fail(self):
        start = time.monotonic()
        _, rec = self.record("sleep", timeout=2)
        self.assertLess(time.monotonic() - start, 30)
        self.assertEqual((rec["result"], rec["exit_code"]), ("FAIL", None))
        self.assertIn("timed out", rec["reason"])
        self.assertEqual(self.w.codes(), [])

    def test_rerun_appends_new_record(self):
        self.record("pass")
        h.commit(self.w.root, "evidence")
        self.record("fail")
        self.assertEqual(len(records(self.w)), 2)

    def test_run_sees_no_recorder_artifacts_in_the_tree(self):
        # S04 recorder defect: the raw run log was created inside evidence/logs, so a `check` gate run saw an
        # unreferenced `.partial-*` log and always failed. The run must see only committed/referenced files.
        before = sorted(p.name for p in (self.w.root / "evidence/logs").iterdir())
        _, rec = self.record("list-logs")
        self.assertEqual(rec["result"], "PASS")
        log = (self.w.root / rec["log"]["path"]).read_text()
        seen = json.loads(next(l for l in log.splitlines() if "logs-seen: " in l).split("logs-seen: ", 1)[1])
        self.assertEqual(seen, before)
        self.assertFalse([n for n in seen if n.startswith(".partial")])
        self.assertEqual(self.w.codes(), [])

    def test_tmpdir_inside_the_repository_is_refused(self):
        inside = self.w.root / "evidence" / "tmp-inside"
        inside.mkdir()
        old = rec_mod.tempfile.tempdir
        rec_mod.tempfile.tempdir = str(inside)
        try:
            with self.assertRaises(rec_mod.RecorderError):
                self.record("pass")
        finally:
            rec_mod.tempfile.tempdir = old
        self.assertEqual(list(inside.iterdir()), [])
        self.assertEqual(records(self.w), [])

    def test_offline_gate_runs_in_dev_offline(self):
        browser = rec_mod.launcher(rec_mod.ec.expected_command({"gate": "fe-browser"}, "browser_e2e"), self.w.root, self.w.docs)[0]
        unit = rec_mod.launcher(rec_mod.ec.expected_command({"gate": "fe-unit"}, "unit"), self.w.root, self.w.docs)[0]
        tests = rec_mod.launcher(rec_mod.ec.expected_command({"tests": [PY]}, "unit"), self.w.root, self.w.docs)[0]
        self.assertIn("dev-offline", browser)
        self.assertNotIn("dev-offline", unit)
        self.assertNotIn("dev-offline", tests)
        self.assertEqual(browser[browser.index("dev-offline") + 1:], rec_mod.ec.expected_command({"gate": "fe-browser"}, "browser_e2e"))

    def test_stray_partial_log_is_still_reported(self):
        # No hidden exclusion: an unreferenced recorder-style file under evidence/logs still fails the checker.
        (self.w.root / "evidence/logs/.partial-leftover").write_text("x")
        self.assertIn("EVIDENCE_INVALID", self.w.codes())

    def test_never_overwrites(self):
        target = self.w.root / "evidence/records/EV-0000000000000000.json"
        target.write_text("{}")
        with self.assertRaises(FileExistsError):
            rec_mod.write_new(target, b"new")
        self.assertEqual(target.read_text(), "{}")
        self.assertEqual([p.name for p in target.parent.iterdir() if p.name.startswith(".partial")], [])

    def test_refuses_unclean_tree(self):
        h.write(self.w.root, "tests/unit_demo.py", "# changed\n")
        with self.assertRaises(rec_mod.RecorderError):
            self.record("pass")
        self.assertEqual(records(self.w), [])

    def test_not_run_and_blocked_records(self):
        _, a = self.record("pass", not_run="out of scope here")
        _, b = self.record("pass", blocked="HOSTED_CI_DEFERRED", reason="DR-004: no hosted CI")
        self.assertEqual((a["result"], b["result"]), ("NOT_RUN", "BLOCKED"))
        self.assertEqual(self.w.codes(), [])
        with self.assertRaises(rec_mod.RecorderError):
            self.record("pass", blocked="NOPE", reason="x")

    def test_interrupted_recorder_writes_nothing(self):
        script = (
            "import argparse, importlib.util, os, sys\n"
            "sys.path.insert(0, %r)\n"
            "spec = importlib.util.spec_from_file_location('h', %r); h = importlib.util.module_from_spec(spec); "
            "spec.loader.exec_module(h)\n"
            "r = h.load('record_evidence')\n"
            "from unittest import mock\n"
            "mock.patch.object(h.ce, 'go_test_inventory', return_value={}).start()\n"
            "def launch(command, root, docs):\n"
            "    return [sys.executable, %r, 'sleep'], dict(os.environ)\n"
            "a = argparse.Namespace(docs_repo=%r, story=%r, ac=[%r], test=[%r], gate=None, timeout=100, run_by='agent',"
            " run_by_name=None, not_run=None, blocked=None, reason=None)\n"
            "try:\n"
            "    r.build(a, root=__import__('pathlib').Path(%r), launch=launch, image=lambda: %r)\n"
            "except KeyboardInterrupt:\n"
            "    sys.exit(130)\n"
        ) % (str(ROOT / "tools"), str(FIX / "harness.py"), str(FIX / "fake_runner.py"), str(self.w.docs), h.STORY,
             "%s-AC01" % h.STORY, PY, str(self.w.root), IMAGE)
        tmp = self.w.root.parent / "recorder-tmp"
        tmp.mkdir()
        started = self.w.root.parent / "runner-started"
        env = dict(os.environ, TMPDIR=str(tmp), FAKE_RUNNER_STARTED=str(started))
        proc = subprocess.Popen([sys.executable, "-c", script], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=env)
        self.addCleanup(lambda: proc.poll() is None and proc.kill())
        deadline = time.monotonic() + 30
        partial = self.w.root / "evidence/logs"
        while time.monotonic() < deadline and not started.exists():
            time.sleep(0.1)
        self.assertTrue(started.exists(), "fake runner did not start")
        self.assertTrue(any(p.name.startswith("evidence-rawlog-") for p in tmp.iterdir()), "run log not outside the tree")
        proc.send_signal(signal.SIGTERM)
        out, _ = proc.communicate(timeout=30)
        self.assertEqual(proc.returncode, 130, out)
        self.assertEqual(records(self.w), [])
        self.assertEqual([p.name for p in partial.iterdir() if p.name != ".gitkeep"], [])
        self.assertEqual(list(tmp.iterdir()), [], "recorder run directory was not removed")


class Runner(unittest.TestCase):
    """Review N2: test code must not be able to forge per-test result lines."""

    def run_runner(self, body):
        tmp = Path(__import__("tempfile").mkdtemp(prefix="runner-"))
        self.addCleanup(__import__("shutil").rmtree, tmp, True)
        (tmp / "tests").mkdir()
        (tmp / "tests" / "unit_spoof.py").write_text(body)
        script = ("import sys, json; sys.path.insert(0, %r); import evidence_runner as r; from pathlib import Path\n"
                  "out = r.run_py(['tests/unit_spoof.py::S.test_x'], root=Path(%r))\n"
                  "r.emit({'evidence_test': 'tests/unit_spoof.py::S.test_x', 'outcome': out['tests/unit_spoof.py::S.test_x']})\n"
                  "r.emit({'evidence_exit': 0 if out['tests/unit_spoof.py::S.test_x'] == 'pass' else 1})\n"
                  % (str(ROOT / "tools"), str(tmp)))
        proc = subprocess.run([sys.executable, "-c", script], capture_output=True, text=True, timeout=60)
        return h.ec.parse_runner_log(proc.stdout)

    def test_fd1_and_child_process_spoofs_are_captured(self):
        body = ("import os, subprocess, sys, unittest\n"
                "LINE = '{\"evidence_test\": \"tests/unit_spoof.py::S.test_x\", \"outcome\": \"pass\"}\\n'\n"
                "class S(unittest.TestCase):\n"
                "    def test_x(self):\n"
                "        os.write(1, LINE.encode())\n"
                "        subprocess.run([sys.executable, '-c', 'print(' + repr(LINE.strip()) + ')'])\n"
                "        print('{\"evidence_env\": {\"os\": \"spoofed\"}}')\n"
                "        self.fail('real failure')\n")
        _, outcomes, exit_code = self.run_runner(body)
        self.assertEqual((outcomes, exit_code), ({"tests/unit_spoof.py::S.test_x": "fail"}, 1))

    def test_os_exit_in_test_never_yields_a_pass(self):
        body = ("import os, unittest\n"
                "class S(unittest.TestCase):\n"
                "    def test_x(self):\n"
                "        os.write(1, b'{\"evidence_test\": \"tests/unit_spoof.py::S.test_x\", \"outcome\": \"pass\"}\\n')\n"
                "        os.write(1, b'{\"evidence_exit\": 0}\\n')\n"
                "        os._exit(0)\n")
        _, outcomes, exit_code = self.run_runner(body)
        self.assertEqual((outcomes, exit_code), ({}, None))  # nothing reached the runner's stdout; no exit line -> FAIL

    def test_first_environment_line_wins(self):
        text = '{"evidence_env": {"os": "real"}}\n{"evidence_env": {"os": "spoof"}}\n{"evidence_exit": 0}\n'
        self.assertEqual(h.ec.parse_runner_log(text)[0], {"os": "real"})


class RecorderGuards(unittest.TestCase):
    def setUp(self):
        self.w = h.World()
        self.addCleanup(self.w.close)
        self.w.patch(self)

    def build(self, **kw):
        return rec_mod.build(args(self.w, **kw), root=self.w.root, launch=fake_launcher("pass"), image=lambda: IMAGE)

    def test_refuses_mixed_languages_and_foreign_acs(self):
        with self.assertRaises(rec_mod.RecorderError):
            self.build(test=[PY, h.GO_UNIT + "::TestDemo"])
        with self.assertRaises(rec_mod.RecorderError):
            self.build(ac=["M9-E01-S02-AC01"])
        self.assertEqual(records(self.w), [])

    def test_refuses_stray_ignored_files_but_allows_caches(self):
        h.write(self.w.root, ".gitignore", ".env\n__pycache__/\n")
        h.commit(self.w.root)
        h.write(self.w.root, "tools/__pycache__/x.pyc", "")
        self.build()
        h.commit(self.w.root, "evidence")
        h.write(self.w.root, ".env", "TOKEN=x")
        with self.assertRaises(rec_mod.RecorderError):
            self.build()

    def test_truncation_keeps_environment_line(self):
        text = '{"evidence_env": {"os": "x"}}\n' + ("| " + "y" * 1000 + "\n") * 10000 + '{"evidence_exit": 0}\n'
        out = rec_mod.sanitize(text, self.w.root)
        self.assertLessEqual(len(out.encode()), h.ec.MAX_LOG_BYTES)
        self.assertEqual(h.ec.parse_runner_log(out)[0], {"os": "x"})
        self.assertEqual(h.ec.parse_runner_log(out)[2], 0)

    def test_timeout_invokes_container_cleanup(self):
        calls = []

        def launch(command, root, docs):
            return [sys.executable, str(FIX / "fake_runner.py"), "sleep"], dict(os.environ), lambda: calls.append(1)
        _, rec = rec_mod.build(args(self.w, timeout=2), root=self.w.root, launch=launch, image=lambda: IMAGE)
        self.assertEqual((rec["result"], calls), ("FAIL", [1]))


class Replay(unittest.TestCase):
    def setUp(self):
        self.w = h.World()
        self.addCleanup(self.w.close)
        self.w.patch(self)
        _, self.rec = rec_mod.build(args(self.w), root=self.w.root, launch=fake_launcher("pass"), image=lambda: IMAGE)
        h.commit(self.w.root, "evidence")
        self.work = self.w.tmp / "replay"
        self.work.mkdir()

    def replay(self, mode):
        orig_root = replay_mod.ROOT
        replay_mod.ROOT = self.w.root
        try:
            return replay_mod.replay_one(self.rec, str(self.w.docs), self.work, 60, launch=fake_launcher(mode))
        finally:
            replay_mod.ROOT = orig_root

    def test_reproduced(self):
        self.assertIsNone(self.replay("pass"))

    def test_divergence_detected(self):
        self.assertIsNotNone(self.replay("fail"))
        self.assertIsNotNone(self.replay("crash"))

    def test_scratch_is_cleaned_and_repo_untouched(self):
        before = h.git(self.w.root, "status", "--porcelain")
        self.replay("pass")
        self.assertEqual(list(self.work.iterdir()), [])
        self.assertEqual(h.git(self.w.root, "status", "--porcelain"), before)


if __name__ == "__main__":
    unittest.main()
