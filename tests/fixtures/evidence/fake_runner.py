"""Fake tier runner for recorder tests (M0-E02-S04 AC03): stands in for the container.

argv: MODE REF...   MODE in pass | fail | crash | sleep | hang-no-exit | list-logs
FAKE_RUNNER_STARTED (optional env): a file created once the runner has started.
Prints runner lines like tools/evidence_runner.py, then exits accordingly.
"""
import json
import os
import sys
import time

mode, refs = sys.argv[1], sys.argv[2:]
env = {"os": "Debian GNU/Linux 13 (trixie)", "kernel": "6.0", "arch": "x86_64", "apt_versions_sha256": "b" * 64}
print(json.dumps({"evidence_env": env}), flush=True)
print("| /home/someone/secret/path appears in tool output", flush=True)
if os.environ.get("FAKE_RUNNER_STARTED"):
    open(os.environ["FAKE_RUNNER_STARTED"], "w").close()
if mode == "list-logs":  # what a gate run (cwd = checkout) sees under evidence/logs
    print("| logs-seen: " + json.dumps(sorted(os.listdir("evidence/logs"))), flush=True)
    mode = "pass"
if mode == "sleep":
    print("started", flush=True)
    time.sleep(120)
if mode == "crash":
    sys.exit(3)
for r in refs:
    print(json.dumps({"evidence_test": r, "outcome": "pass" if mode == "pass" else "fail"}), flush=True)
rc = 0 if mode == "pass" else 1
print(json.dumps({"evidence_exit": rc}), flush=True)
sys.exit(rc)
