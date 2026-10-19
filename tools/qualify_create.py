#!/usr/bin/env python3
"""Real-host VM-create qualification orchestrator (canonical entry: `make docker-qualify-libvirt-create`).

Stages, each reported PASS / FAIL / NOT_RUN per criterion:
  1. host preflight (read-only, tools/qualify_preflight.py). Missing prerequisites => NOT_RUN, exit 0 (never a false PASS).
  2. create stage in a locked-down container (Go test TestSystemCreateQualification): real qemu:///system, managed image digest,
     root volume, NoCloud seed, domain, forced interrupted-provision recovery without duplicates, ownership proof, start, lease.
  3. guest stage on the HOST with an operator-supplied DISPOSABLE private key (ssh): cloud-init consumed the intended seed, the
     expected login user exists, the supplied public key authenticates. The private key is never read by this script, never mounted
     into the container, never written to the report; only its path is handed to ssh.
  `--stage cleanup --run-id ID` removes ONE run's resources and refuses (manual cleanup required) unless ownership is proven.

The report (qualification-out/<RUN_ID>/report.{json,txt}) is console output to attach to the qualification record, not an
evidence-format record. Nothing here marks an image qualified: that is a separate, explicit `api image-state` step.
"""
import argparse
import datetime
import json
import os
import re
import secrets
import shutil
import subprocess
import sys

sys.dont_write_bytecode = True
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import qualify_preflight as pf  # noqa: E402

RUN_ID_RE = re.compile(r"^qr-[0-9]{8}-[0-9a-f]{6}$")
IMAGE_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,62}$")
LIBVIRT_RW_SOCK = "/var/run/libvirt/libvirt-sock"
LIBVIRT_RO_SOCK = "/var/run/libvirt/libvirt-sock-ro"
DEV_IMAGE = "dedicatedcloud-dev:local"
GO_TAGS = "libvirt libvirt_test"
PASS, FAIL, NOT_RUN = "PASS", "FAIL", "NOT_RUN"

# The full criterion list of the first-VM qualification (CT-PRODUCT-DELIVERY-007 section 25). Everything must be PASS.
CRITERIA = [
    ("real-libvirt", "1. real qemu:///system reached"),
    ("managed-image", "2. managed image digest accepted"),
    ("root-volume", "3. root volume created"),
    ("seed-volume", "4. NoCloud seed created and uploaded"),
    ("domain-defined", "5. domain defined"),
    ("vm-started", "6. VM starts"),
    ("kvm-guest", "7. KVM/QEMU actually runs the guest"),
    ("vm-running", "8. VM reaches Running"),
    ("cloud-init-seed", "9. cloud-init processed the intended seed"),
    ("login-user", "10. expected login user exists"),
    ("ssh-key-auth", "11. supplied SSH public key authenticates"),
    ("address-observed", "12. reachable networking / address (approved NAT model)"),
    ("no-duplicates", "13. no duplicate resources after forced unknown-outcome recovery"),
    ("svavyom-owned", "14. resources identifiable as Svavyom-owned"),
    ("cleanup", "15. cleanup touches only proven-owned qualification resources"),
    ("image-immutable-after", "    base image unchanged after cleanup"),
]
# Reported, required for PASS, not numbered in the directive. CT-PRODUCT-DELIVERY-008: the managed base image is recorded and compared
# immediately before start (-before), while the guest runs (-running) and after shutdown and cleanup (-after, proven by the cleanup stage).
ALSO = ["trust-layout", "host-ready", "forced-recovery", "root-source-resolved", "seed-source-resolved", "domain-backing-declared", "domain-root-source", "domain-seed-source", "domain-volume-identity", "image-immutable-before", "image-immutable-running"]
CLEANUP_REQUIRED = ["cleanup", "image-immutable-after"]


def new_run_id(now=None):
    now = now or datetime.datetime.now(datetime.timezone.utc)
    return "qr-%s-%s" % (now.strftime("%Y%m%d"), secrets.token_hex(3))


def sock_gid(path):
    return os.stat(path).st_gid


def docker_argv(stage, a, catalog_dir, gid, out_dir, pool_dir=None):
    """The container gets exactly: the libvirt RW socket and, for create, the RO socket; /dev/kvm is NOT needed (libvirtd's qemu uses it), the read-only checkout,
    the read-only config, the read-only catalog directory at its own path, the PUBLIC key, and one writable output directory.
    pool_dir, when given, is the pool's target directory on the host, mounted READ-ONLY at its own path so the Go stage can inspect
    (lstat, never open or write) the root volume file libvirt resolves there (CT-PRODUCT-DELIVERY-009).
    No capabilities, no network, read-only root, not privileged."""
    run = ["docker", "run", "--rm", "-u", "%d:%d" % (os.getuid(), os.getgid()), "--group-add", str(gid), "--cap-drop", "ALL",
           "--security-opt", "no-new-privileges:true", "--read-only", "--network", "none", "--tmpfs", "/tmp:exec,mode=1777,size=2g",
           "-v", "%s:/workspace/cloud-platform:ro" % a.repo, "-v", "%s:%s" % (LIBVIRT_RW_SOCK, LIBVIRT_RW_SOCK),
           "-v", "%s:/qualify/config.json:ro" % a.config, "-v", "%s:%s:ro" % (catalog_dir, catalog_dir),
           "-v", "%s:/qualify/out" % out_dir]
    if pool_dir:
        run += ["-v", "%s:%s:ro" % (pool_dir, pool_dir)]
    if stage == "create":
        run += ["-v", "%s:%s" % (LIBVIRT_RO_SOCK, LIBVIRT_RO_SOCK),
                "-v", "%s:/qualify/key.pub:ro" % a.pubkey,
                "-e", "SVAVYOM_QUALIFY_SSH_PUBKEY_FILE=/qualify/key.pub"]
    run += ["-e", "SVAVYOM_QUALIFY_CREATE=1", "-e", "SVAVYOM_QUALIFY_STAGE=" + stage, "-e", "SVAVYOM_QUALIFY_RUN_ID=" + a.run_id,
            "-e", "SVAVYOM_QUALIFY_CONFIG=/qualify/config.json", "-e", "SVAVYOM_QUALIFY_OUT=/qualify/out", "-e", "SVAVYOM_QUALIFY_IMAGE_ID=" + a.image,
            "-e", "GOMODCACHE=/opt/go-mod-cache", "-e", "GOPROXY=off", "-e", "HOME=/tmp", "-e", "GOCACHE=/tmp/go-cache",
            "-w", "/workspace/cloud-platform/backend", DEV_IMAGE, "go", "test", "-tags", GO_TAGS, "-count=1", "-v", "-run",
            "TestSystemCreateQualification" if stage == "create" else "TestSystemCreateQualificationCleanup", "./internal/hypervisor/libvirtmut/"]
    return run


POOL_DIR_RE = re.compile(r"^/[A-Za-z0-9._/-]{1,198}$")


def pool_target_dir(pool):
    """The target directory of the configured pool as libvirt reports it (read-only query), or "" when it cannot be established or
    is not a plain absolute path. Only used to decide what to mount read-only; the Go stage re-derives and checks everything."""
    if not re.match(r"^[A-Za-z0-9._-]{1,64}$", pool or ""):
        return ""
    out = run_diag(["virsh", "-r", "-c", "qemu:///system", "pool-dumpxml", "--", pool])
    m = re.search(r"<target>\s*<path>([^<]+)</path>", out)
    p = m.group(1) if m else ""
    return p if POOL_DIR_RE.match(p) and os.path.isdir(p) and p != "/" else ""


def ssh_argv(a, ip, user, known_hosts, remote):
    # Only the PATH of the private key reaches ssh. IdentitiesOnly keeps ssh from offering any other key; BatchMode forbids prompts.
    return ["ssh", "-i", a.ssh_key, "-o", "IdentitiesOnly=yes", "-o", "BatchMode=yes", "-o", "PasswordAuthentication=no", "-o", "StrictHostKeyChecking=accept-new",
            "-o", "UserKnownHostsFile=" + known_hosts, "-o", "ConnectTimeout=10", "--", "%s@%s" % (user, ip), remote]


# One remote command; each fact on its own labelled line. No secrets are read in the guest.
REMOTE = "echo USER=$(id -un); echo HOST=$(hostname); echo INSTANCE=$(cat /var/lib/cloud/data/instance-id 2>/dev/null); " \
         "echo DS=$(cat /var/lib/cloud/instance/datasource 2>/dev/null); echo CI=$(cloud-init status 2>/dev/null | tr -d '\\n')"


def parse_guest(out):
    return dict(l.split("=", 1) for l in out.splitlines() if "=" in l)


def judge_guest(facts, user, uuid, name):
    """Criteria 9-11 from the guest's own answers. Login succeeding at all is what proves the key (11)."""
    c = []
    c.append(("ssh-key-auth", PASS, "key accepted for %s" % facts.get("USER", "?")))
    c.append(("login-user", PASS if facts.get("USER") == user else FAIL, "id -un = %r, expected %r" % (facts.get("USER"), user)))
    ok = facts.get("INSTANCE") == uuid and "NoCloud" in facts.get("DS", "") and "done" in facts.get("CI", "") and facts.get("HOST") == name
    c.append(("cloud-init-seed", PASS if ok else FAIL, "instance-id=%s datasource=%s status=%s hostname=%s" % (facts.get("INSTANCE"), facts.get("DS"), facts.get("CI"), facts.get("HOST"))))
    return c


def overall(criteria, required_extra=()):
    """PASS only if every create-stage criterion (1-14 and the supporting checks) is PASS; any FAIL fails; otherwise NOT_RUN."""
    status = {cid: st for cid, st, _ in criteria}
    required = [cid for cid, _ in CRITERIA if cid not in CLEANUP_REQUIRED] + ALSO + list(required_extra)
    if any(st == FAIL for _, st, _ in criteria):
        return FAIL
    if all(status.get(c) == PASS for c in required):
        return PASS
    return NOT_RUN


def cleanup_verdict(criteria):
    """Cleanup PASS needs the safe-cleanup proof AND the base image proven unchanged afterwards; any FAIL fails; anything missing is
    NOT_RUN (for example: the create stage never recorded the base image, so there is nothing to compare with). Never a PASS."""
    status = {cid: st for cid, st, _ in criteria}
    if any(st == FAIL for st in status.values()):
        return FAIL
    if all(status.get(c) == PASS for c in CLEANUP_REQUIRED) and all(st == PASS for st in status.values()):
        return PASS
    return NOT_RUN


def render(run_id, criteria, verdict):
    names = dict(CRITERIA)
    lines = ["Svavyom first-VM qualification  run %s" % run_id]
    seen = set()
    for cid, st, detail in criteria:
        seen.add(cid)
        lines.append("  %-7s %-34s %s" % (st, names.get(cid, cid), detail))
    failed = any(st == FAIL for _, st, _ in criteria)
    for cid, label in CRITERIA:
        if cid not in seen:
            lines.append("  %-7s %-34s %s" % (NOT_RUN, label, "not run (blocked by an earlier FAIL)" if failed else "not run"))
    lines.append("RESULT: %s" % verdict)
    if verdict != PASS:
        lines.append("The image must NOT be marked qualified. A PASS needs every criterion PASS.")
    return "\n".join(lines)


REDACTIONS = [
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(-----END [A-Z ]*PRIVATE KEY-----|\Z)", re.S), "[private key removed]"),
    (re.compile(r"(?i)\b(password|passwd|secret|token)=\S+"), r"\1=[removed]"),
]


VOLUME_PATH_RE = re.compile(r"^/[A-Za-z0-9._/-]{1,250}$")


def redact(text, limit=16384):
    """Diagnostics are evidence, not a channel for secrets: private-key blocks and credential assignments are removed, control
    characters replaced, and the size bounded."""
    for rx, rep in REDACTIONS:
        text = rx.sub(rep, text)
    text = re.sub(r"[^\t\n\x20-\x7e]", "?", text)
    return text if len(text) <= limit else text[:limit] + "\n[truncated]"


def run_diag(argv, timeout=20):
    try:
        p = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, check=False)  # noqa: S603
        return "$ %s\n%s%s(exit %d)\n" % (" ".join(argv), p.stdout, p.stderr, p.returncode)
    except (OSError, subprocess.SubprocessError) as e:
        return "$ %s\n(not available: %s)\n" % (" ".join(argv), type(e).__name__)


def backing_chain_evidence(out_dir):
    """The resolved root and seed volume paths libvirt reported (storage-volume-paths.txt): the host's own stat and readlink -f of each
    file the domain names, and the real qcow2 chain behind the root, read-only: qemu-img info --backing-chain with -U (no image lock
    taken, so a running guest is not disturbed). Every path must be absolute and made of safe characters before it reaches an argv."""
    parts = []
    try:
        lines = open(os.path.join(out_dir, "storage-volume-paths.txt")).read().splitlines()
    except OSError:
        return ["(storage-volume-paths.txt not recorded: the create stage did not reach volume creation)\n"]
    parts.append("$ storage volume paths (libvirt)\n" + "\n".join(lines) + "\n")
    for ln in lines:
        f = ln.split(" ", 1)
        if len(f) == 2 and (f[0].endswith("-root.qcow2") or f[0].endswith("-seed.iso")) and VOLUME_PATH_RE.match(f[1]):
            # The host's own view of each file the domain names: type (a symlink shows as one), owner and mode, and the fully resolved path.
            parts.append(run_diag(["stat", "-c", "%U:%G %a %F %n", "--", f[1]]))
            parts.append(run_diag(["readlink", "-f", "--", f[1]]))
            if f[0].endswith("-root.qcow2"):
                parts.append(run_diag(["qemu-img", "info", "-U", "--backing-chain", "--output=json", "--", f[1]], timeout=30))
    return parts


def classify_denials(text):
    """Which AppArmor profile denied access decides the remedy (CT-PRODUCT-DELIVERY-008 addendum 2): the virt-aa-helper profile means
    the helper cannot process the path (narrow helper override); a per-guest libvirt-<uuid> profile needs Control Tower review."""
    helper = [l for l in text.splitlines() if 'profile="/usr/lib/libvirt/virt-aa-helper"' in l]
    guest = [l for l in text.splitlines() if re.search(r'profile="libvirt-[0-9a-f-]+"', l)]
    return "DENIAL ANALYSIS: virt-aa-helper denials=%d guest-profile denials=%d (%s)\n" % (
        len(helper), len(guest),
        "helper cannot process the path: consider packages/ubuntu/apparmor/virt-aa-helper.local.svavyom" if helper
        else "guest profile denied: do not widen policy; capture evidence for Control Tower" if guest else "no AppArmor denial recorded")


def collect_host_diagnostics(stage, run_id, out_dir):
    """Best-effort, read-only host evidence for the qualification record (CT-PRODUCT-DELIVERY-008): the base image as the HOST sees
    it (independent of the container), the guest's QEMU log, AppArmor denials from the kernel log and the libvirt domain state.
    Whatever the unprivileged operator account cannot read is stated, never guessed. Nothing here mutates anything."""
    vm = "svq-" + run_id[3:]
    parts = ["run %s stage %s vm %s\n" % (run_id, stage, vm)]
    anchor = os.path.join(out_dir, "image-anchor.json")
    try:
        path = json.load(open(anchor)).get("path", "")
    except (OSError, ValueError):
        path = ""
    if path.startswith("/") and "\n" not in path:
        parts.append(run_diag(["stat", "-c", "%U:%G %a %s bytes %F %n", "--", path]))
    parts.extend(backing_chain_evidence(out_dir))
    log = "/var/log/libvirt/qemu/%s.log" % vm
    try:
        with open(log, errors="replace") as f:
            parts.append("$ tail -n 200 %s\n%s" % (log, "".join(f.readlines()[-200:])))
    except OSError as e:
        parts.append("$ tail %s\n(not readable by this account: %s; read it as root if the guest failed to start)\n" % (log, type(e).__name__))
    denied = run_diag(["journalctl", "-k", "--no-pager", "-n", "100", "-g", "apparmor=\"DENIED\"", "--since", "-2h"])
    parts.append(denied)
    parts.append(classify_denials(denied))
    parts.append(run_diag(["virsh", "-r", "-c", "qemu:///system", "domstate", "--reason", vm]))
    name = os.path.join(out_dir, "host-diagnostics-%s.txt" % stage)
    with open(name, "w") as f:
        f.write(redact("\n".join(parts)) + "\n")
    return name


def scrub_check(text):
    """Defence in depth: refuse to write a report that looks like it contains private key material."""
    return "PRIVATE KEY" not in text and "OPENSSH PRIVATE" not in text


def validate(a):
    problems = []
    if not RUN_ID_RE.match(a.run_id or ""):
        problems.append("run id must look like qr-YYYYMMDD-xxxxxx")
    if a.stage == "create":
        if not a.pubkey or not os.path.isfile(a.pubkey):
            problems.append("QUALIFY_PUBKEY (public key file) is required")
        if not IMAGE_ID_RE.match(a.image or ""):
            problems.append("QUALIFY_IMAGE (registered image id) is required")
    if not a.config or not os.path.isabs(a.config) or not os.path.isfile(a.config):
        problems.append("QUALIFY_CONFIG (absolute path of the provisioning config) is required")
    return problems


def missing_prereqs(a):
    miss = []
    if not os.path.exists(LIBVIRT_RW_SOCK):
        miss.append("libvirt read-write socket %s" % LIBVIRT_RW_SOCK)
    if a.stage == "create" and not os.path.exists(LIBVIRT_RO_SOCK):
        miss.append("libvirt read-only socket %s" % LIBVIRT_RO_SOCK)
    if not os.path.exists("/dev/kvm"):
        miss.append("/dev/kvm")
    for name, v in (("QUALIFY_CONFIG", a.config), ("QUALIFY_PUBKEY", a.pubkey), ("QUALIFY_IMAGE", a.image)):
        if a.stage == "create" or name == "QUALIFY_CONFIG":
            if not v:
                miss.append(name)
    return miss


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--stage", choices=("create", "cleanup", "plan"), default="create")
    ap.add_argument("--config", default=os.environ.get("QUALIFY_CONFIG", ""))
    ap.add_argument("--pubkey", default=os.environ.get("QUALIFY_PUBKEY", ""))
    ap.add_argument("--image", default=os.environ.get("QUALIFY_IMAGE", ""))
    ap.add_argument("--ssh-key", default=os.environ.get("QUALIFY_SSH_KEY", ""), help="path of the disposable PRIVATE key (path only is used)")
    ap.add_argument("--run-id", default=os.environ.get("QUALIFY_RUN_ID", ""))
    ap.add_argument("--out", default=os.environ.get("QUALIFY_OUT", "qualification-out"))
    ap.add_argument("--repo", default=os.getcwd())
    a = ap.parse_args(argv)

    miss = missing_prereqs(a)
    if miss:
        print("NOT_RUN: missing prerequisites: %s (see docs/QUALIFICATION-LIBVIRT-CREATE.md); real-KVM create qualification pending" % ", ".join(miss))
        return 0
    if a.stage == "create" and not a.run_id:
        a.run_id = new_run_id()
    problems = validate(a)
    if problems:
        print("ERROR " + "; ".join(problems), file=sys.stderr)
        return 2
    a.config, a.repo = os.path.abspath(a.config), os.path.abspath(a.repo)
    if a.pubkey:
        a.pubkey = os.path.abspath(a.pubkey)
    out_dir = os.path.abspath(os.path.join(a.out, a.run_id))
    # The private key must never sit in the checkout or the output directory (both can end up in evidence/Git).
    if a.ssh_key:
        k = os.path.realpath(a.ssh_key)
        for forbidden in (a.repo, out_dir):
            if k == forbidden or k.startswith(forbidden + os.sep):
                print("ERROR the SSH private key must live outside the repository and the output directory", file=sys.stderr)
                return 2
    try:
        cfg = json.load(open(a.config))
    except (OSError, ValueError):
        print("ERROR the provisioning config is not readable JSON", file=sys.stderr)
        return 2
    catalog_dir = cfg.get("catalog_dir", "")
    if not os.path.isabs(catalog_dir) or not os.path.isdir(catalog_dir):
        print("ERROR config.catalog_dir is not a directory on this host", file=sys.stderr)
        return 2
    if a.stage == "plan":  # print what would run, touch nothing (used by tests and by reviewers)
        print(" ".join(docker_argv("create", a, catalog_dir, 0, out_dir)))
        return 0

    os.makedirs(out_dir, mode=0o755, exist_ok=True)
    criteria = []
    if a.stage == "create":
        rep = pf.run_all(pf.Probe("/"), a.config, 30)
        print(pf.render(rep))
        if rep["verdict"] != "READY":
            print("NOT_RUN: the host is not ready for qualification (preflight above)")
            return 0
    pool_dir = pool_target_dir(cfg.get("pool", ""))
    if not pool_dir:
        print("WARNING the pool directory could not be established; the root and seed volume files cannot be inspected from the container and the root-source and seed-source criteria will FAIL with that reason", file=sys.stderr)
    rc = subprocess.run(docker_argv(a.stage, a, catalog_dir, sock_gid(LIBVIRT_RW_SOCK), out_dir, pool_dir), check=False).returncode  # noqa: S603
    try:
        collect_host_diagnostics(a.stage, a.run_id, out_dir)
    except OSError as e:  # evidence collection must never turn a verdict into a crash
        print("WARNING host diagnostics not written: %s" % type(e).__name__, file=sys.stderr)
    rpath = os.path.join(out_dir, a.stage + "-result.json")
    try:
        res = json.load(open(rpath))
        criteria += [(c["id"], c["status"], c.get("detail", "")) for c in res.get("criteria", [])]
    except (OSError, ValueError):
        res = {}
        criteria.append(("real-libvirt", FAIL, "the container produced no result (exit %d)" % rc))
    if rc != 0 and not any(st == FAIL for _, st, _ in criteria):
        criteria.append(("qualification-stage", FAIL, "Go qualification stage exited %d" % rc))
    if a.stage == "create" and res.get("ipv4") and res.get("login_user"):
        if not a.ssh_key:
            for cid in ("ssh-key-auth", "login-user", "cloud-init-seed"):
                criteria.append((cid, NOT_RUN, "no QUALIFY_SSH_KEY supplied"))
        else:
            known = os.path.join(out_dir, "known_hosts")
            p = subprocess.run(ssh_argv(a, res["ipv4"], res["login_user"], known, REMOTE), capture_output=True, text=True, timeout=300, check=False)  # noqa: S603
            if p.returncode == 0:
                criteria += judge_guest(parse_guest(p.stdout), res["login_user"], res["uuid"], res["vm_name"])
            else:
                for cid in ("ssh-key-auth", "login-user", "cloud-init-seed"):
                    criteria.append((cid, FAIL, "ssh exit %d: %s" % (p.returncode, (p.stderr.strip().splitlines() or ["?"])[-1][:200])))
    if a.stage == "cleanup":
        verdict = cleanup_verdict(criteria)
        text = render(a.run_id, criteria, verdict).replace("RESULT:", "CLEANUP RESULT:")
    else:
        # Criterion 15 (cleanup) is proven by the separate cleanup stage; it is listed as NOT_RUN here and never assumed.
        verdict = overall(criteria, required_extra=())
        text = render(a.run_id, criteria, verdict)
        if verdict == PASS:
            text += "\nCriteria 1-14 PASS. Criterion 15 is proven only by: make docker-qualify-libvirt-cleanup QUALIFY_RUN_ID=%s" % a.run_id
    if not scrub_check(text):
        print("ERROR the report contains private key material; refusing to write it", file=sys.stderr)
        return 2
    print(text)
    for name, body in (("report-%s.txt" % a.stage, text + "\n"), ("report-%s.json" % a.stage, json.dumps({"run_id": a.run_id, "stage": a.stage, "result": verdict,
                       "criteria": [{"id": c, "status": s, "detail": d} for c, s, d in criteria]}, indent=2) + "\n")):
        with open(os.path.join(out_dir, name), "w") as f:
            f.write(body)
    return 0 if verdict in (PASS, NOT_RUN) else 1


if __name__ == "__main__":
    sys.exit(main())
