#!/usr/bin/env python3
"""Evidence replay (story M0-E02-S04 AC03; DR-006 D3 = A).

Re-executes every CURRENT local PASS record at its revision.platform in a
fresh clone (git clone + detached checkout in a scratch directory; the
repository's .git is never written, erratum r2a W7), inside the pinned dev
container, with the recorded generated command. Fails on any divergence in
per-test outcomes or exit status. Records are claims; replay is what gives
local evidence its authenticity. Merge records cite this tool's output.

  python3 tools/replay_evidence.py --docs-repo ../cloud-product-docs --workdir ../evidence-replay
Exit: 0 all reproduced, 1 divergence or checker findings, 2 usage/environment error.
"""
import argparse
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import evidence_common as ec  # noqa: E402
import record_evidence as re_  # noqa: E402

ROOT = ec.ROOT


def materialise(rev, workdir):
    """Fresh clone of this repository checked out (detached) at rev, under workdir."""
    dest = Path(tempfile.mkdtemp(dir=workdir, prefix="replay-")) / "cloud-platform"
    for argv in (["git", "clone", "--quiet", "--no-hardlinks", "--no-checkout", str(ROOT), str(dest)],
                 ["git", "-C", str(dest), "checkout", "--quiet", "--detach", rev]):
        proc = subprocess.run(argv, capture_output=True, text=True, check=False)
        if proc.returncode != 0:
            raise re_.RecorderError("%s failed: %s" % (argv[1], proc.stderr.strip()[-300:]))
    return dest


def replay_one(rec, docs_repo, workdir, timeout, launch=re_.launcher):
    """Return None if reproduced, else a divergence description."""
    clone = materialise(rec["revision"]["platform"], workdir)
    try:
        argv, env, cleanup = re_.launch_parts(launch(rec["command"], clone, docs_repo))
        log_path = clone.parent / "replay.log"
        rc = re_.run_command(argv, env, clone, timeout, log_path, cleanup)
        _, outcomes, exit_line = ec.parse_runner_log(log_path.read_text(encoding="utf-8", errors="replace"))
        original = (ROOT / rec["log"]["path"]).read_text(encoding="utf-8", errors="replace")
        _, orig_outcomes, orig_exit = ec.parse_runner_log(original)
        if rc != 0 or exit_line != orig_exit or outcomes != orig_outcomes:
            return "replay rc=%r exit=%r outcomes=%s; recorded exit=%r outcomes=%s" % (
                rc, exit_line, outcomes, orig_exit, orig_outcomes)
        return None
    finally:
        shutil.rmtree(clone.parent, ignore_errors=True)


class ReplayEnvError(Exception):
    pass


def current_pass_records(docs_repo, workdir, launch=re_.launcher):
    """Run the checker inside the pinned container (it needs Go) and return the current PASS records."""
    command = ["toolchain/run-in-copy.sh", "python3", "tools/check_evidence.py", "--docs-repo",
               "/workspace/cloud-product-docs", "--states"]
    argv, env, cleanup = re_.launch_parts(launch(command, ROOT, docs_repo))
    log = Path(tempfile.mkdtemp(dir=workdir, prefix="states-")) / "check.log"
    try:
        rc = re_.run_command(argv, env, ROOT, 1800, log, cleanup)
        text = log.read_text(encoding="utf-8", errors="replace")
    finally:
        shutil.rmtree(log.parent, ignore_errors=True)
    if rc != 0:
        raise ReplayEnvError(text[-2000:]) if rc == 2 or rc is None else \
            re_.RecorderError("evidence checker reported findings (rc %r):\n%s" % (rc, text[-2000:]))
    ids = set()
    for line in text.splitlines():
        if line.startswith('{"evidence_record"'):
            obj = json.loads(line)
            if obj["state"] == "current" and obj["result"] == "PASS":
                ids.add(obj["evidence_record"])
    return [ec.loads((ROOT / ec.RECORDS_DIR / ("%s.json" % i)).read_text()) for i in sorted(ids)]


def main(argv=None):
    parser = argparse.ArgumentParser(description="Replay current local PASS evidence records (M0-E02-S04).")
    parser.add_argument("--docs-repo", required=True)
    parser.add_argument("--workdir", required=True, help="scratch directory for fresh clones (not inside the repo)")
    parser.add_argument("--timeout", type=int, default=re_.DEFAULT_TIMEOUT)
    args = parser.parse_args(argv)
    workdir = Path(args.workdir).resolve()
    if workdir == ROOT or ROOT in workdir.parents:
        print("ERROR --workdir must be outside the repository")
        return 2
    workdir.mkdir(parents=True, exist_ok=True)
    try:
        targets = current_pass_records(args.docs_repo, workdir)
        image = re_.image_id()
    except ReplayEnvError as exc:
        print("ERROR USAGE evidence checker could not run:\n%s" % exc)
        return 2
    except re_.RecorderError as exc:
        print("ERROR %s" % exc)
        return 1
    diverged = 0
    for rec in targets:
        try:
            why = replay_one(rec, args.docs_repo, workdir, args.timeout)
        except re_.RecorderError as exc:
            why = str(exc)
        note = "" if rec["environment"].get("image") == image else " (note: replayed on image %s, recorded on %s)" % (
            image[:19], rec["environment"].get("image", "?")[:19])
        print("%s %s %s%s" % ("REPRODUCED" if why is None else "DIVERGED", rec["id"], why or "", note))
        diverged += why is not None
    print("replay: %d current PASS record(s), %d reproduced, %d diverged" % (len(targets), len(targets) - diverged,
                                                                             diverged))
    return 1 if diverged else 0


if __name__ == "__main__":
    sys.exit(main())
