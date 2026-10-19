#!/usr/bin/env python3
"""Read-only Ubuntu qualification-host preflight.

Answers one question before a real-host qualification run: can this machine plausibly run it? It changes nothing: it reads
files, runs `uname`-class queries and read-only `virsh -r` / `docker version` commands, and writes a report only when --json is
given (a new file, never overwritten). It is NOT host qualification and NOT an evidence record; the verdict is READY or
NOT_READY, each check is PASS, FAIL, WARN or SKIP.

The distribution/architecture/CPU rules reuse the pinned support matrix (the Go capability checker, `capability-check`) when a
built binary is supplied with --capability-check; as a non-root user on a real host that checker reports `unknown` for the
containment probe by design (docs/CAPABILITY.md), so its verdict is shown as information, and the decisive checks here are the
direct ones below.

  python3 tools/qualify_preflight.py [--config /etc/svavyom/provision.json] [--min-free-gib 30] [--json OUT.json]
"""
import argparse
import json
import os
import re
import shutil
import subprocess
import sys

sys.dont_write_bytecode = True

SUPPORTED_UBUNTU = ("24.04",)
PASS, FAIL, WARN, SKIP = "PASS", "FAIL", "WARN", "SKIP"
NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$")


class Probe:
    """Everything that touches the host, behind one object so tests can substitute fixtures."""

    def __init__(self, root="/", run=None):
        self.root = root
        self._run = run or self._real_run

    def path(self, p):
        return os.path.join(self.root, p.lstrip("/"))

    def read(self, p, limit=1 << 20):
        try:
            with open(self.path(p), "rb") as f:
                return f.read(limit).decode("utf-8", "replace")
        except OSError:
            return None

    def stat(self, p):
        try:
            return os.stat(self.path(p))
        except OSError:
            return None

    def which(self, name):
        return shutil.which(name)

    def free_gib(self, p):
        try:
            st = os.statvfs(self.path(p))
            return st.f_bavail * st.f_frsize / (1 << 30)
        except OSError:
            return None

    def access(self, p, mode):
        return os.access(self.path(p), mode)

    @staticmethod
    def _real_run(argv, timeout=15):
        try:
            r = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, check=False)  # noqa: S603 - fixed argv, no shell
            return r.returncode, r.stdout, r.stderr
        except (OSError, subprocess.TimeoutExpired) as e:
            return 127, "", str(e)

    def run(self, argv, timeout=15):
        return self._run(argv, timeout)


def parse_os_release(text):
    out = {}
    for line in (text or "").splitlines():
        if "=" in line and not line.lstrip().startswith("#"):
            k, v = line.split("=", 1)
            out[k.strip()] = v.strip().strip('"')
    return out


def check_os(p):
    r = parse_os_release(p.read("/etc/os-release"))
    if r.get("ID") == "ubuntu" and r.get("VERSION_ID") in SUPPORTED_UBUNTU:
        return PASS, "Ubuntu %s" % r["VERSION_ID"]
    return FAIL, "need Ubuntu %s, found %s %s" % (" or ".join(SUPPORTED_UBUNTU), r.get("ID", "?"), r.get("VERSION_ID", "?"))


def check_arch(p):
    code, out, _ = p.run(["uname", "-m"])
    m = out.strip() if code == 0 else (p.read("/proc/sys/kernel/arch") or "").strip()
    return (PASS, m) if m == "x86_64" else (FAIL, "need x86_64, found %r" % m)


def check_cpu(p):
    flags = set()
    for line in (p.read("/proc/cpuinfo") or "").splitlines():
        if line.startswith("flags"):
            flags.update(line.split(":", 1)[-1].split())
    if "vmx" in flags:
        return PASS, "Intel VT-x (vmx)"
    if "svm" in flags:
        return PASS, "AMD-V (svm)"
    return FAIL, "no vmx/svm CPU flag: virtualization extension absent or hidden (nested virtualization off, or disabled in firmware)"


def check_kvm_device(p):
    st = p.stat("/dev/kvm")
    if st is None:
        return FAIL, "/dev/kvm does not exist"
    import stat as _s
    if not _s.S_ISCHR(st.st_mode):
        return FAIL, "/dev/kvm is not a character device"
    rw = p.access("/dev/kvm", os.R_OK | os.W_OK)
    return (PASS, "/dev/kvm present, usable by this user") if rw else (WARN, "/dev/kvm present but this user cannot open it read-write (qemu runs as its own user; the qualification container needs the device group)")


def check_kvm_modules(p):
    mods = p.read("/proc/modules") or ""
    names = {ln.split()[0] for ln in mods.splitlines() if ln.split()}
    builtin = (p.read("/sys/module/kvm/initstate") is not None)
    has_kvm = "kvm" in names or builtin
    has_arch = bool({"kvm_intel", "kvm_amd"} & names) or p.stat("/sys/module/kvm_intel") is not None or p.stat("/sys/module/kvm_amd") is not None
    if has_kvm and has_arch:
        return PASS, "kvm and kvm_intel/kvm_amd loaded"
    return FAIL, "KVM kernel modules not loaded (kvm=%s, arch module=%s)" % (has_kvm, has_arch)


def check_qemu(p):
    exe = p.which("qemu-system-x86_64")
    if not exe:
        return FAIL, "qemu-system-x86_64 not installed (apt install qemu-system-x86)"
    code, out, _ = p.run([exe, "--version"])
    return PASS, (out.splitlines()[0] if code == 0 and out else exe)


def check_libvirt_installed(p):
    have = [n for n in ("virsh", "libvirtd", "virtqemud") if p.which(n)]
    if "virsh" in have and ("libvirtd" in have or "virtqemud" in have):
        code, out, _ = p.run(["virsh", "--version"])
        return PASS, "libvirt %s (%s)" % (out.strip() if code == 0 else "?", ", ".join(have))
    return FAIL, "libvirt not (fully) installed (apt install libvirt-daemon-system libvirt-clients); found: %s" % (", ".join(have) or "nothing")


def check_libvirt_sockets(p):
    import stat as _s
    rw, ro = p.stat("/var/run/libvirt/libvirt-sock"), p.stat("/var/run/libvirt/libvirt-sock-ro")
    ok = lambda st: st is not None and _s.S_ISSOCK(st.st_mode)  # noqa: E731
    if ok(rw) and ok(ro):
        return PASS, "libvirt-sock and libvirt-sock-ro present"
    return FAIL, "libvirt sockets missing (rw=%s, ro=%s): is libvirtd/virtqemud running?" % (ok(rw), ok(ro))


def check_qemu_system(p):
    code, out, err = p.run(["virsh", "-r", "-c", "qemu:///system", "uri"])
    if code == 0 and "qemu:///system" in out:
        return PASS, "qemu:///system reachable read-only"
    return FAIL, "cannot reach qemu:///system read-only: %s" % (err.strip().splitlines() or ["no output"])[-1]


def check_docker(p):
    if not p.which("docker"):
        return FAIL, "docker not installed"
    code, out, err = p.run(["docker", "version", "--format", "{{.Server.Version}}"])
    return (PASS, "docker server %s" % out.strip()) if code == 0 and out.strip() else (FAIL, "docker daemon not usable by this user: %s" % (err.strip().splitlines() or ["?"])[-1])


def check_storage(p, paths, need_gib):
    if not paths:
        return SKIP, "no paths given (pass --config)"
    worst, parts = PASS, []
    for label, path in paths:
        free = p.free_gib(path)
        if free is None:
            worst = FAIL
            parts.append("%s: not found" % label)
        elif free < need_gib:
            worst = FAIL
            parts.append("%s: %.0f GiB free < %d" % (label, free, need_gib))
        else:
            parts.append("%s: %.0f GiB free" % (label, free))
    return worst, "; ".join(parts)


def libvirt_state(p, kind, name):
    # kind is "net" or "pool"; name already matches NAME_RE (it came from a validated config).
    code, out, err = p.run(["virsh", "-r", "-c", "qemu:///system", kind + "-info", name])
    if code != 0:
        return FAIL, "%s %r not found or unreadable" % (kind, name)
    st = {k.strip(): v.strip() for k, _, v in (ln.partition(":") for ln in out.splitlines()) if _}
    if kind == "net":
        active = st.get("Active", "").lower() == "yes"
    else:
        active = st.get("State", "").lower() == "running"
    return (PASS, "%s %r active" % (kind, name)) if active else (FAIL, "%s %r exists but is not active" % (kind, name))


def load_config(p, path):
    text = p.read(path)
    if text is None:
        return None, "cannot read %s" % path
    try:
        c = json.loads(text)
    except ValueError:
        return None, "%s is not valid JSON" % path
    for k in ("pool", "network"):
        if not isinstance(c.get(k), str) or not NAME_RE.match(c[k]):
            return None, "%s has no valid %r" % (path, k)
    return c, ""


def check_layout(p, cfg_path, cfg):
    """Advisory mirror of the Go trust check (the services enforce the authoritative one at start): root-owned, no group/other write."""
    import stat as _s
    bad = []
    targets = [("provisioning config", cfg_path), ("config directory", os.path.dirname(cfg_path)), ("catalog directory", cfg.get("catalog_dir", "")),
               ("image store", os.path.join(cfg.get("catalog_dir", "/nonexistent"), "store")), ("catalog", os.path.join(cfg.get("catalog_dir", "/nonexistent"), "catalog.json"))]
    for label, path in targets:
        st = p.stat(path)
        if st is None:
            bad.append("%s missing" % label)
        elif st.st_uid != 0 or st.st_mode & 0o022:
            bad.append("%s not root-owned/not closed to group+other writes" % label)
        elif _s.S_ISLNK(st.st_mode):
            bad.append("%s is a symlink" % label)
    return (FAIL, "; ".join(bad)) if bad else (PASS, "operator-owned layout (the services re-check at start)")


def run_all(p, config_path, min_free_gib, capability_check=None, matrix=None):
    results = []

    def add(cid, fn, *a):
        status, detail = fn(p, *a)
        results.append({"id": cid, "status": status, "detail": detail})

    add("ubuntu-release", check_os)
    add("architecture", check_arch)
    add("cpu-virtualization", check_cpu)
    add("dev-kvm", check_kvm_device)
    add("kvm-modules", check_kvm_modules)
    add("qemu", check_qemu)
    add("libvirt-installed", check_libvirt_installed)
    add("libvirt-sockets", check_libvirt_sockets)
    add("qemu-system-uri", check_qemu_system)
    add("docker", check_docker)
    cfg = None
    if config_path:
        cfg, why = load_config(p, config_path)
        if cfg is None:
            results.append({"id": "provisioning-config", "status": FAIL, "detail": why})
    storage = []
    if cfg:
        storage = [("catalog", cfg.get("catalog_dir", "/nonexistent")), ("state", cfg.get("state_dir", "/nonexistent")), ("qualification output", ".")]
    add("free-storage", check_storage, storage, min_free_gib)
    if cfg:
        for cid, kind, key in (("libvirt-network", "net", "network"), ("libvirt-pool", "pool", "pool")):
            status, detail = libvirt_state(p, kind, cfg[key])
            results.append({"id": cid, "status": status, "detail": detail})
        add("trust-layout", lambda pp: check_layout(pp, config_path, cfg))
    else:
        for cid in ("libvirt-network", "libvirt-pool", "trust-layout"):
            results.append({"id": cid, "status": SKIP, "detail": "needs a valid --config"})
    if capability_check and matrix:
        code, out, err = p.run([capability_check, "--root", p.root, "--matrix", matrix])
        verdict = {0: "supported", 10: "unsupported", 11: "unknown"}.get(code, "error")
        results.append({"id": "support-matrix", "status": WARN if verdict in ("unknown", "error") else (PASS if verdict == "supported" else FAIL),
                        "detail": "capability-check verdict %s (non-root on a real host reports unknown for containment by design; informational)" % verdict})
    else:
        results.append({"id": "support-matrix", "status": SKIP, "detail": "capability-check binary not supplied"})
    ready = not any(r["status"] == FAIL for r in results)
    return {"verdict": "READY" if ready else "NOT_READY", "qualification": "none", "checks": results}


def render(rep):
    lines = ["Svavyom qualification-host preflight (read-only; not host qualification)"]
    for r in rep["checks"]:
        lines.append("  %-4s %-20s %s" % (r["status"], r["id"], r["detail"]))
    lines.append("VERDICT: %s" % rep["verdict"])
    return "\n".join(lines)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--config", help="provisioning config (adds storage, network, pool and layout checks)")
    ap.add_argument("--min-free-gib", type=int, default=30)
    ap.add_argument("--json", help="also write the machine-readable report to this NEW file")
    ap.add_argument("--capability-check", help="built capability-check binary (informational)")
    ap.add_argument("--matrix", help="support matrix for capability-check")
    ap.add_argument("--root", default="/", help=argparse.SUPPRESS)
    a = ap.parse_args(argv)
    if a.config and not os.path.isabs(a.config):
        print("ERROR --config must be an absolute path", file=sys.stderr)
        return 2
    rep = run_all(Probe(a.root), a.config, a.min_free_gib, a.capability_check, a.matrix)
    print(render(rep))
    if a.json:
        try:
            fd = os.open(a.json, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
        except OSError as e:
            print("ERROR cannot create %s: %s" % (a.json, e), file=sys.stderr)
            return 2
        with os.fdopen(fd, "w") as f:
            json.dump(rep, f, indent=2)
            f.write("\n")
    return 0 if rep["verdict"] == "READY" else 1


if __name__ == "__main__":
    sys.exit(main())
