#!/usr/bin/env python3
"""Host-side evidence recorder (story M0-E02-S04; DR-006 D1/D2/D3 = A).

Runs the generated tier-runner command inside the pinned dev container
(docker compose run --rm dev toolchain/run-in-copy.sh ...; never a shell
wrapper) for a clean, committed revision and writes ONE new evidence record
plus its log: evidence/records/<id>.json and evidence/logs/<id>.log.

Guarantees (AC03): writes are atomic and never overwrite; on timeout the child
process group is killed and a FAIL record is written; on interruption
(SIGINT/SIGTERM) nothing is written; a run never yields PASS unless the runner
reported exit 0 and a pass for every cited test. Only allowlisted environment
facts are captured; host paths are removed from the log.

Run as an unprivileged, non-root user on the host:
  python3 tools/record_evidence.py --docs-repo ../cloud-product-docs --story S --ac S-AC01 --test REF [...]
  python3 tools/record_evidence.py ... --gate go-test-libvirt
  python3 tools/record_evidence.py ... --test REF --not-run "reason"
  python3 tools/record_evidence.py ... --test REF --blocked HOSTED_CI_DEFERRED --reason "DR-004: no hosted CI"
"""
import argparse
import contextlib
import datetime
import hashlib
import os
import platform
import shutil
import signal
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import evidence_common as ec  # noqa: E402
import check_evidence as ce  # noqa: E402

ROOT = ec.ROOT
IMAGE = "dedicatedcloud-dev:local"
DEFAULT_TIMEOUT = 3600


class RecorderError(Exception):
    pass


def now():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def git(*args, root=ROOT):
    proc = subprocess.run(["git", *args], cwd=root, capture_output=True, text=True, check=False)
    if proc.returncode != 0:
        raise RecorderError("git %s failed: %s" % (args[0], proc.stderr.strip()[-300:]))
    return proc.stdout


IGNORED_OK = ("__pycache__/", "node_modules/", "dist/", ".pytest_cache/", "coverage/")


def tree_clean(root=ROOT):
    """Clean except new untracked files under evidence/records and evidence/logs (erratum r2a, W6).

    Ignored files are refused too (they would be copied into the container run), except caches and
    dependency/build output (review N11); e.g. a stray .env is refused.
    """
    for line in git("status", "--porcelain", "--untracked-files=all", "--ignored", root=root).splitlines():
        if line.startswith("?? evidence/records/") or line.startswith("?? evidence/logs/"):
            continue
        if line.startswith("!! ") and any(line[3:].endswith(x) or "/" + x in "/" + line[3:] for x in IGNORED_OK):
            continue
        return False
    return True


def git_mounts(root=ROOT):
    """A linked worktree's .git is a file pointing into the main repository: mount its common dir read-only."""
    dot = Path(root) / ".git"
    if not dot.is_file():
        return []
    gitdir = Path(dot.read_text().split("gitdir:", 1)[1].strip())
    common = (gitdir / (gitdir / "commondir").read_text().strip()).resolve() if (gitdir / "commondir").exists() else gitdir
    return ["-v", "%s:%s:ro" % (common, common)]


def toolchain_versions(root=ROOT):
    out = {}
    for line in (Path(root) / "toolchain" / "versions.env").read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            out[k] = v
    return out


def image_id():
    proc = subprocess.run(["docker", "image", "inspect", "--format", "{{.Id}}", IMAGE], capture_output=True, text=True,
                          check=False)
    if proc.returncode != 0 or not ce.IMAGE_RE.fullmatch(proc.stdout.strip()):
        raise RecorderError("cannot identify image %s (build it with make docker-image)" % IMAGE)
    return proc.stdout.strip()


def host_os():
    try:
        for line in Path("/etc/os-release").read_text().splitlines():
            if line.startswith("PRETTY_NAME="):
                return line.split("=", 1)[1].strip().strip('"')
    except OSError:
        pass
    return "unknown"


# Gates that must run with no network at all (M0-E02-S06 r5 section 10, DR-010 D4 = A): compose service dev-offline.
OFFLINE_GATES = frozenset({"fe-browser"})


def service_for(command):
    """`dev-offline` for an offline gate, otherwise `dev`. The command is generated (ec.expected_command)."""
    if "--gate" in command and command.index("--gate") + 1 < len(command) and command[command.index("--gate") + 1] in OFFLINE_GATES:
        return "dev-offline"
    return "dev"


def launcher(command, root, docs_repo):
    """Return (argv, env, cleanup). cleanup() kills the named container (killing the compose client alone leaves
    the container running; review N1)."""
    name = "evidence-run-%s" % uuid.uuid4().hex[:12]
    argv = ["docker", "compose", "-p", "evidence", "--env-file", "toolchain/versions.env", "run", "--rm", "-T",
            "--name", name, *git_mounts(root), service_for(command), *command]
    env = dict(os.environ, HOST_UID=str(os.getuid()), HOST_GID=str(os.getgid()),
               DOCS_REPO_HOST=str(Path(docs_repo).resolve()))

    def cleanup():
        subprocess.run(["docker", "kill", name], capture_output=True, check=False)
        subprocess.run(["docker", "rm", "-f", name], capture_output=True, check=False)
    return argv, env, cleanup


def launch_parts(result):
    argv, env = result[0], result[1]
    return argv, env, (result[2] if len(result) > 2 else (lambda: None))


def sanitize(text, root):
    for p in sorted({str(Path(root).resolve()), str(Path.home())}, key=len, reverse=True):
        if p and p != "/":
            text = text.replace(p, "<host-path>")
    if len(text.encode("utf-8")) > ec.MAX_LOG_BYTES:
        # keep the runner's environment line (first) and the tail with the results (review N7)
        head = next((l for l in text.splitlines() if l.startswith('{"evidence_env"')), "")
        text = head + "\n<log truncated to the last %d bytes>\n" % (ec.MAX_LOG_BYTES // 2) + \
            text.encode("utf-8")[-(ec.MAX_LOG_BYTES // 2):].decode("utf-8", "ignore")
    return text


@contextlib.contextmanager
def signals_deferred():
    """Defer SIGINT/SIGTERM while the log and record are written, so a record is never half-written (review N7)."""
    old = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGINT, signal.SIGTERM})
    try:
        yield
    finally:
        signal.pthread_sigmask(signal.SIG_SETMASK, old)


def write_new(path, data):
    """Atomic create: temp file in the same directory, then link (fails if path exists), then unlink temp."""
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".partial-")
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.link(tmp, path)  # raises FileExistsError: never overwrite
    finally:
        os.unlink(tmp)


def run_command(argv, env, cwd, timeout, log_path, cleanup=lambda: None):
    """Run in a new process group; return returncode, or None on timeout. Kills the group (and, via cleanup, the
    container) on timeout or interrupt."""
    with open(log_path, "wb") as log:
        proc = subprocess.Popen(argv, cwd=cwd, env=env, stdout=log, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
                                start_new_session=True)

        def stop(signum, _frame):
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            cleanup()
            raise KeyboardInterrupt

        old = {s: signal.signal(s, stop) for s in (signal.SIGINT, signal.SIGTERM)}
        try:
            return proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            os.killpg(proc.pid, signal.SIGKILL)
            proc.wait()
            cleanup()
            return None
        finally:
            for s, h in old.items():
                signal.signal(s, h)


def build(args, root=ROOT, launch=launcher, image=image_id):
    """Create the record. Returns (record_path, record). Raises RecorderError for refusals (nothing written)."""
    if args.test and args.gate:
        raise RecorderError("use --test ... or --gate, not both")
    if args.gate is None and args.test and len({(ec.test_ref(r) or ("?",))[0] for r in args.test}) != 1:
        raise RecorderError("cited tests must all be Go or all Python (one runner per record)")
    if not tree_clean(root):
        raise RecorderError("working tree is not clean (only new evidence files may be untracked)")
    git_ctx, docs, docs_sha, taxonomy, classes = ce.load(root, args.docs_repo)
    head = git("rev-parse", "HEAD", root=root).strip()
    lock = ec.loads((Path(root) / "docs-lock.json").read_text())
    backlog = ce.Context(root, git_ctx, docs, docs_sha, taxonomy, classes).backlog_at(lock["commit"])
    if backlog is None or args.story not in backlog[0] or any(
            backlog[1].get(a, {}).get("story_id") != args.story for a in args.ac):
        raise RecorderError("--ac must be acceptance criteria of --story at the pinned docs commit")
    subject = {"gate": args.gate} if args.gate else {"tests": sorted(set(args.test or []))}
    if args.gate:
        gate = taxonomy["gates"].get(args.gate)
        if gate is None:
            raise RecorderError("unknown gate %s" % args.gate)
        tier, kinds = gate["tier"], sorted(gate["kinds"])
    else:
        if not subject["tests"] or any(ec.test_ref(r) is None for r in subject["tests"]):
            raise RecorderError("give --test refs: Go path::TestName or tests/x.py::Class.test_method")
        tiers = set()
        for ref in subject["tests"]:
            hits = ec.classify(classes, ec.test_ref(ref)[1])
            if len(hits) != 1:
                raise RecorderError("%s is not classified exactly once" % ref)
            tiers.add(hits[0]["tier"])
        if len(tiers) != 1:
            raise RecorderError("cited tests span tiers %s; record them separately" % sorted(tiers))
        tier, kinds = tiers.pop(), ce.record_kinds(classes, subject["tests"])
    t = taxonomy["tiers"][tier]
    command = ec.expected_command(subject, tier)
    record = {"schema": 1, "story": args.story, "acceptance": sorted(set(args.ac)), "subject": subject, "tier": tier,
              "kinds": kinds, "environment_class": t["environment_class"], "cost_class": t["cost_class"],
              "origin": "local", "run_by": args.run_by, "command": command,
              "revision": {"platform": head, "tree_clean": True, "docs": lock["commit"]}}
    if args.run_by == "human":
        record["run_by_name"] = args.run_by_name
    environment = {"kind": "local_container", "image": image(), "toolchain": toolchain_versions(root),
                   "apt_versions_sha256": None, "os": host_os(), "kernel": platform.release(), "arch": platform.machine()}
    logs_dir, recs_dir = Path(root) / ec.LOGS_DIR, Path(root) / ec.RECORDS_DIR
    logs_dir.mkdir(parents=True, exist_ok=True)
    recs_dir.mkdir(parents=True, exist_ok=True)
    started = now()
    if args.not_run or args.blocked:
        if args.blocked and args.blocked not in taxonomy["blockers"]:
            raise RecorderError("unknown blocker %s" % args.blocked)
        record.update(environment=environment, started_at=started, finished_at=now(),
                      result="BLOCKED" if args.blocked else "NOT_RUN", exit_code=None,
                      reason=args.reason if args.blocked else args.not_run)
        if args.blocked:
            record["blocker"] = args.blocked
        log_text = None
    else:
        argv, env, cleanup = launch_parts(launch(command, root, args.docs_repo))
        # The raw run log lives in a private directory OUTSIDE the repository: the command (for example the
        # `check` gate, which runs `make evidence`) sees the checkout, and a recorder artifact inside
        # evidence/logs would be an unreferenced log to it (S04 recorder defect; fixed under M0-E02-S06).
        # The checker still reports every unreferenced file under evidence/ (no exclusion is added).
        run_dir = tempfile.mkdtemp(prefix="evidence-rawlog-")
        if Path(run_dir).resolve().is_relative_to(Path(root).resolve()):
            os.rmdir(run_dir)
            raise RecorderError("TMPDIR resolves inside the repository; set TMPDIR outside it")
        raw_log = os.path.join(run_dir, "run.log")
        try:
            rc = run_command(argv, env, root, args.timeout, raw_log, cleanup)
            log_text = sanitize(Path(raw_log).read_text(encoding="utf-8", errors="replace"), root)
        finally:
            # Deterministic removal; interruption propagates and nothing is written. A failed removal is reported.
            shutil.rmtree(run_dir, onexc=lambda _f, path, exc: print(
                "WARNING could not remove recorder temp %s: %s" % (path, exc), file=sys.stderr))
        env_line, outcomes, exit_line = ec.parse_runner_log(log_text)
        if isinstance(env_line, dict):  # the container's own identification, not the host's
            for k in ("os", "kernel", "arch"):
                if isinstance(env_line.get(k), str) and env_line[k]:
                    environment[k] = env_line[k]
            environment["apt_versions_sha256"] = env_line.get("apt_versions_sha256")
            if tier == "simulated_libvirt":
                environment["libvirt"] = env_line.get("libvirt")
        passed = rc == 0 and exit_line == 0 and (
            "gate" in subject or (set(outcomes) == set(subject["tests"]) and all(v == "pass" for v in outcomes.values())))
        # The runner's own exit line is authoritative; without it (crash, timeout) only a non-zero/None FAIL is recorded.
        exit_code = exit_line if exit_line is not None else (rc if rc else None)
        record.update(environment=environment, started_at=started, finished_at=now(),
                      result="PASS" if passed else "FAIL", exit_code=exit_code)
        if rc is None:
            record["reason"] = "timed out after %ss; process group killed" % args.timeout
        record["log"] = {"path": "", "sha256": hashlib.sha256(log_text.encode("utf-8")).hexdigest()}
    rid = ec.record_id(record)
    record = dict(record, id=rid)
    rec_path = recs_dir / ("%s.json" % rid)
    with signals_deferred():
        if log_text is not None:
            record["log"]["path"] = "%s/%s.log" % (ec.LOGS_DIR, rid)
            write_new(Path(root) / record["log"]["path"], log_text.encode("utf-8"))
        write_new(rec_path, (ec.canonical(record).decode("utf-8") + "\n").encode("utf-8"))
    return rec_path, record


def main(argv=None):
    parser = argparse.ArgumentParser(description="Record test evidence (M0-E02-S04).")
    parser.add_argument("--docs-repo", required=True)
    parser.add_argument("--story", required=True)
    parser.add_argument("--ac", action="append", required=True)
    parser.add_argument("--test", action="append")
    parser.add_argument("--gate")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT)
    parser.add_argument("--run-by", choices=("agent", "human"), default="agent")
    parser.add_argument("--run-by-name")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--not-run", metavar="REASON")
    group.add_argument("--blocked", metavar="BLOCKER")
    parser.add_argument("--reason")
    args = parser.parse_args(argv)
    if args.blocked and not args.reason:
        parser.error("--blocked needs --reason")
    if args.run_by == "human" and not args.run_by_name:
        parser.error("--run-by human needs --run-by-name")
    if os.getuid() == 0:
        print("ERROR refusing to run as root")
        return 2
    try:
        path, record = build(args)
    except (RecorderError, ce.EnvError) as exc:
        print("ERROR %s" % exc)
        return 2
    except KeyboardInterrupt:
        print("INTERRUPTED: no record written")
        return 130
    print("%s %s %s" % (record["result"], record["id"], path.relative_to(ROOT)))
    return 0 if record["result"] in ("PASS", "NOT_RUN", "BLOCKED") else 1


if __name__ == "__main__":
    sys.exit(main())
