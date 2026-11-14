#!/usr/bin/env python3
"""Clean-host qualification of Svavyom (first-release checklist, wave 5). Stdlib only. Drives ONE fresh Ubuntu host over SSH, stage by stage, and records every criterion.

    python3 tools/qualify_clean_host.py --host 203.0.113.10 --key ~/.ssh/KEY --tls-name HOST.example --artifact release-out/svavyom-0.1.0-preview.15 --out DIR --stage facts
    stages: facts (read-only) | prepare (apt: qemu and libvirt) | install (copy the artifact to a root-owned place, preflight, install) | bootstrap (the first administrator)
            | verify (services, API health on the host and from here) | image (an Ubuntu cloud image registered and qualified in the catalog)
            | upgrade (a newer artifact over the installed one, signed or from a root-owned copy; the installer makes its backup first) | vm (tools/qualify_install.py run ON the host: VM create, SSH, console, reboot, resize, snapshot, backup, network, service restart, support bundle)

It needs passwordless sudo for the SSH user on the host (the owner allowed it on the two test hosts) and changes only that host. It never prints a password: the
administrator's password is generated here, written to DIR/admin-password (mode 0600) and sent to the host on standard input. The artifact is installed through the
signed path when --signatures and --public-key are given, else with --allow-unsigned from a root-owned copy. Results: DIR/<run-id>-clean-host-<stage>.json.
"""
import argparse
import base64
import json
import os
import re
import secrets
import shlex
import subprocess
import sys
import time

sys.dont_write_bytecode = True

R = []
STAGES = ["facts", "prepare", "install", "bootstrap", "verify", "image", "vm", "upgrade", "rollback", "reboot", "nightly", "firewall", "features"]
HOST_RE = re.compile(r"^[0-9]{1,3}(\.[0-9]{1,3}){3}$")
NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.-]{0,251}[A-Za-z0-9]$")
RUN_RE = re.compile(r"^qr-[0-9]{8}-[0-9a-f]{6}$")
REMOTE_ARTIFACTS = "/opt/svavyom-artifacts"
MIN_FREE_GIB = 40
MIN_RAM_MIB = 8000


def rec(cid, ok, detail=""):
    R.append({"id": cid, "status": "PASS" if ok else "FAIL", "detail": detail[:300]})
    print("%-5s %s%s" % ("PASS" if ok else "FAIL", cid, ("  " + detail[:200]) if detail else ""), flush=True)
    return ok


def ssh_argv(user, host, key, remote_cmd):
    """The ssh command line for one remote shell command: no password, no agent, host key recorded on first use (the host is a fresh one the owner named)."""
    return ["ssh", "-i", key, "-o", "IdentitiesOnly=yes", "-o", "BatchMode=yes", "-o", "ConnectTimeout=15", "-o", "StrictHostKeyChecking=accept-new",
            "-o", "ServerAliveInterval=15", "%s@%s" % (user, host), "--", "bash", "-c", shlex.quote(remote_cmd)]


def scp_argv(user, host, key, local, remote):
    return ["scp", "-q", "-i", key, "-o", "IdentitiesOnly=yes", "-o", "BatchMode=yes", "-o", "ConnectTimeout=15", "-o", "StrictHostKeyChecking=accept-new", local,
            "%s@%s:%s" % (user, host, remote)]


class Host:
    def __init__(self, user, host, key):
        self.user, self.host, self.key = user, host, key

    def run(self, cmd, timeout=300, stdin=None):
        p = subprocess.run(ssh_argv(self.user, self.host, self.key, cmd), input=stdin, capture_output=True, text=True, timeout=timeout, check=False)  # noqa: S603
        return p.returncode, (p.stdout + p.stderr)

    def get(self, remote, local, timeout=300):
        argv = ["scp", "-q", "-i", self.key, "-o", "IdentitiesOnly=yes", "-o", "BatchMode=yes", "-o", "ConnectTimeout=15", "-o", "StrictHostKeyChecking=accept-new",
                "%s@%s:%s" % (self.user, self.host, remote), local]
        p = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, check=False)  # noqa: S603
        return p.returncode, (p.stdout + p.stderr)

    def put(self, local, remote, timeout=600):
        p = subprocess.run(scp_argv(self.user, self.host, self.key, local, remote), capture_output=True, text=True, timeout=timeout, check=False)  # noqa: S603
        return p.returncode, (p.stdout + p.stderr)


# ---------------------------------------------------------------- judging (pure, tested)

FACTS_CMD = (". /etc/os-release; echo \"os=$ID $VERSION_ID\"; echo \"kernel=$(uname -r)\"; echo \"cpus=$(nproc)\"; "
             "echo \"ram_mib=$(free -m | awk '/Mem:/{print $2}')\"; echo \"free_gib=$(df -BG --output=avail /var/lib 2>/dev/null | tail -1 | tr -dc 0-9)\"; "
             "echo \"kvm=$(test -c /dev/kvm && echo yes || echo no)\"; echo \"virt_cpus=$(grep -c -E 'vmx|svm' /proc/cpuinfo)\"; "
             "echo \"apparmor=$(cat /sys/module/apparmor/parameters/enabled 2>/dev/null || echo no)\"; "
             "echo \"libvirt=$(command -v virsh >/dev/null && echo installed || echo absent)\"; echo \"qemu=$(command -v qemu-system-x86_64 >/dev/null && echo installed || echo absent)\"; "
             "echo \"svavyom=$(test -e /usr/libexec/svavyom && echo present || echo absent)\"; echo \"ufw=$(systemctl is-active ufw 2>/dev/null)\"; "
             "echo \"sudo=$(sudo -n true 2>/dev/null && echo yes || echo no)\"")


def parse_kv(text):
    out = {}
    for ln in text.splitlines():
        k, sep, v = ln.partition("=")
        if sep and re.fullmatch(r"[a-z_]+", k):
            out[k] = v.strip()
    return out


def judge_facts(kv):
    """[(criterion, ok, detail)] for a host that must be fresh Ubuntu 24.04 with KVM, enough room and passwordless sudo, and nothing of Svavyom on it."""
    def num(k):
        m = re.match(r"[0-9]+", kv.get(k, ""))
        return int(m.group(0)) if m else 0
    return [
        ("ubuntu-24.04", kv.get("os") == "ubuntu 24.04", kv.get("os", "?")),
        ("kvm-usable", kv.get("kvm") == "yes" and num("virt_cpus") > 0, "/dev/kvm %s, %d CPUs with a virtualization flag" % (kv.get("kvm", "?"), num("virt_cpus"))),
        ("apparmor-enabled", kv.get("apparmor", "").startswith("Y"), kv.get("apparmor", "?")),
        ("memory", num("ram_mib") >= MIN_RAM_MIB, "%d MiB (at least %d)" % (num("ram_mib"), MIN_RAM_MIB)),
        ("free-space", num("free_gib") >= MIN_FREE_GIB, "%d GiB free under /var/lib (at least %d)" % (num("free_gib"), MIN_FREE_GIB)),
        ("passwordless-sudo", kv.get("sudo") == "yes", kv.get("sudo", "?")),
        ("clean-host", kv.get("svavyom") == "absent" and kv.get("libvirt") == "absent" and kv.get("qemu") == "absent",
         "svavyom %s, libvirt %s, qemu %s" % (kv.get("svavyom", "?"), kv.get("libvirt", "?"), kv.get("qemu", "?"))),
    ]


def remote_install_argv(name, listen, tls_host, signed):
    """The install command line on the host, from the root-owned copy of the artifact. Signed when signatures were copied beside it, else --allow-unsigned."""
    base = "%s/%s" % (REMOTE_ARTIFACTS, name)
    argv = ["sudo", "%s/bin/svavyom-ctl" % base, "install", "--artifact", base, "--create-pool", "--tls-self-signed", tls_host, "--enable-mutation", "--enable-console",
            "--backup-dir", "/var/lib/svavyom/backups", "--listen", listen]
    argv += ["--signatures", "%s/signatures" % REMOTE_ARTIFACTS, "--public-key", "%s/release-signing-key.pub" % REMOTE_ARTIFACTS] if signed else ["--allow-unsigned"]
    return argv


def new_password():
    """A one-off administrator password (letters and digits, 24 characters): the shape the API accepts, never printed."""
    return "".join(secrets.choice("ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789") for _ in range(24))


# ---------------------------------------------------------------- stages

def stage_facts(h, a):
    rc, out = h.run(FACTS_CMD, timeout=60)
    rec("ssh", rc == 0, "reached %s as %s" % (a.host, a.user))
    if rc != 0:
        return
    kv = parse_kv(out)
    for cid, ok, detail in judge_facts(kv):
        rec(cid, ok, detail)


def stage_prepare(h, a):
    cmd = ("export DEBIAN_FRONTEND=noninteractive; sudo apt-get update -qq && sudo apt-get install -y -qq qemu-system-x86 libvirt-daemon-system libvirt-clients "
           "&& sudo systemctl enable --now libvirtd && echo PREPARED")
    rc, out = h.run(cmd, timeout=1500)
    rec("packages-installed", rc == 0 and "PREPARED" in out, "qemu-system-x86, libvirt-daemon-system, libvirt-clients; libvirtd enabled" if rc == 0 else out[-200:])
    rc, out = h.run("sudo virsh -c qemu:///system list --all; sudo virsh -c qemu:///system net-list --all", timeout=60)
    rec("libvirt-answers", rc == 0, "virsh reaches qemu:///system")
    rec("default-network", re.search(r"^\s*default\s+active", out, re.M) is not None, "the libvirt 'default' NAT network is active" if "default" in out else "no default network: " + out[-120:])
    rc, out = h.run("qemu-system-x86_64 --version | head -1; virsh --version", timeout=30)
    rec("versions", rc == 0, out.replace("\n", "; ")[:160])


def tar_artifact(path, dest):
    name = os.path.basename(os.path.normpath(path))
    subprocess.run(["tar", "-C", os.path.dirname(os.path.abspath(path)), "-czf", dest, name], check=True)  # noqa: S603,S607
    return name


def put_artifact(h, a):
    """Copy the artifact (and, when given, its signatures and the public key) to a place only root can change on the host, and check every digest there. Returns the
    artifact's directory name, or None after recording the failure."""
    tmp = os.path.join(a.out, "%s-artifact.tgz" % a.run_id)
    name = tar_artifact(a.artifact, tmp)
    rc, out = h.put(tmp, "/tmp/%s.tgz" % name)
    os.remove(tmp)
    if not rec("artifact-copied", rc == 0, out[-120:] if rc else "copied to the host"):
        return None
    cmd = ("sudo install -d -m 0755 -o root -g root %s && sudo tar -C %s -xzf /tmp/%s.tgz && sudo chown -R root:root %s/%s && sudo chmod -R go-w %s/%s && rm -f /tmp/%s.tgz "
           "&& cd %s/%s && sudo sha256sum --quiet -c SHA256SUMS && echo VERIFIED") % (REMOTE_ARTIFACTS, REMOTE_ARTIFACTS, name, REMOTE_ARTIFACTS, name, REMOTE_ARTIFACTS, name, name, REMOTE_ARTIFACTS, name)
    rc, out = h.run(cmd, timeout=120)
    if not rec("artifact-root-owned-and-intact", rc == 0 and "VERIFIED" in out, "under %s, root-owned, every digest matches SHA256SUMS" % REMOTE_ARTIFACTS if rc == 0 else out[-200:]):
        return None
    if a.signatures and a.public_key:
        h.put(a.public_key, "/tmp/k.pub")
        h.run("sudo install -m 0644 -o root -g root /tmp/k.pub %s/release-signing-key.pub && rm -f /tmp/k.pub" % REMOTE_ARTIFACTS)
        sigtmp = os.path.join(a.out, "%s-sigs.tgz" % a.run_id)
        subprocess.run(["tar", "-C", os.path.dirname(os.path.abspath(a.signatures)), "-czf", sigtmp, os.path.basename(os.path.normpath(a.signatures))], check=True)  # noqa: S603,S607
        h.put(sigtmp, "/tmp/sigs.tgz")
        os.remove(sigtmp)
        h.run("sudo rm -rf %s/signatures && sudo mkdir -p %s/signatures && sudo tar -C %s/signatures --strip-components=1 -xzf /tmp/sigs.tgz && sudo chown -R root:root %s/signatures && rm -f /tmp/sigs.tgz" % ((REMOTE_ARTIFACTS,) * 4))
    return name


def remote_upgrade_argv(name, listen, signed, nightly=""):
    """The upgrade command on the host from the root-owned copy of the NEW artifact: the installed options are repeated (the installer says to), the signature or --allow-unsigned."""
    base = "%s/%s" % (REMOTE_ARTIFACTS, name)
    argv = ["sudo", "%s/bin/svavyom-ctl" % base, "upgrade", "--artifact", base, "--enable-mutation", "--enable-console", "--backup-dir", "/var/lib/svavyom/backups", "--listen", listen]
    argv += ["--signatures", "%s/signatures" % REMOTE_ARTIFACTS, "--public-key", "%s/release-signing-key.pub" % REMOTE_ARTIFACTS] if signed else ["--allow-unsigned"]
    if nightly:  # the nightly boot check (HH:MM, host time): it needs its credential and timer, which only an install or an upgrade sets up
        argv += ["--enable-nightly-boot", nightly]
    return argv


def stage_upgrade(h, a):
    before = h.run("cat /usr/libexec/svavyom/VERSION", timeout=30)[1].strip()
    name = put_artifact(h, a)
    if not name:
        return
    signed = bool(a.signatures and a.public_key)
    cmd = " ".join(shlex.quote(x) for x in remote_upgrade_argv(name, a.listen, signed, a.nightly))
    rc, plan = h.run(cmd + "; echo EXIT=$?", timeout=300)
    rec("upgrade-plan", "EXIT=0" in plan and "PLAN" in plan, "the plan was printed and nothing was changed" if "EXIT=0" in plan else plan[-300:])
    rc, out = h.run(cmd + " --apply; echo EXIT=$?", timeout=1200)
    ok = "EXIT=0" in out and "upgraded" in out
    rec("upgrade-applied", ok, ("upgraded %s through the %s path" % (before, "signed" if signed else "--allow-unsigned (root-owned copy)")) if ok else out[-500:])
    if signed:
        rec("signature-checked", "signature: valid" in out, "the installer said the signature is valid" if "signature: valid" in out else "the installer did not report a valid signature")
    m = re.search(r"backup (\S+) is kept for `svavyom-ctl rollback`", out)
    rec("rollback-backup-recorded", m is not None, ("backup " + m.group(1)) if m else "the installer named no backup")
    with open(os.path.join(a.out, "%s-upgrade-backup-id" % a.run_id), "w") as f:
        f.write((m.group(1) if m else "") + "\n")


def stage_install(h, a):
    name = put_artifact(h, a)
    if not name:
        return
    signed = bool(a.signatures and a.public_key)
    ctl = "%s/%s/bin/svavyom-ctl" % (REMOTE_ARTIFACTS, name)
    rc, out = h.run("sudo %s preflight; echo EXIT=$?" % ctl, timeout=120)
    m = re.search(r"(?m)^RESULT:\s*(PASS|NOT_READY|FAIL)\s*$", out)
    rec("preflight", "EXIT=0" in out and m is not None and m.group(1) == "PASS", ("the host preflight says " + m.group(1)) if m else out[-200:])
    cmd = " ".join(shlex.quote(x) for x in remote_install_argv(name, a.listen, a.tls_name, signed))
    rc, plan = h.run(cmd + "; echo EXIT=$?", timeout=300)
    rec("install-plan", "EXIT=0" in plan and "PLAN" in plan, "the plan was printed and nothing was changed" if "EXIT=0" in plan else plan[-300:])
    rc, out = h.run(cmd + " --apply; echo EXIT=$?", timeout=900)
    rec("install-applied", "EXIT=0" in out, ("installed " + name + (" through the signed path" if signed else " with --allow-unsigned from a root-owned copy")) if "EXIT=0" in out else out[-400:])
    if signed:
        rec("signature-checked", "signature: valid" in out, "the installer said the signature is valid" if "signature: valid" in out else "the installer did not report a valid signature")


def stage_bootstrap(h, a):
    pw_path = os.path.join(a.out, "%s-admin-password" % a.run_id)
    if os.path.exists(pw_path):
        pw = open(pw_path).read().strip()
    else:
        pw = new_password()
        fd = os.open(pw_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(pw + "\n")
    cmd = ("sudo systemctl stop svavyom-api && sudo -u svavyom-api /usr/libexec/svavyom/api bootstrap-admin --db /var/lib/svavyom/api/svavyom.db --username admin; "
           "rc=$?; sudo systemctl start svavyom-api; echo BOOTSTRAP_EXIT=$rc")
    rc, out = h.run(cmd, timeout=120, stdin=pw + "\n")
    rec("admin-created", "BOOTSTRAP_EXIT=0" in out or "already" in out.lower(), "the administrator 'admin' exists (password in %s, mode 0600)" % os.path.basename(pw_path) if "BOOTSTRAP_EXIT=0" in out else out[-200:])
    assert pw not in out


def stage_verify(h, a):
    rc, out = h.run("sudo /usr/libexec/svavyom/svavyom-ctl status; echo EXIT=$?", timeout=120)
    rec("services-and-health", "RESULT: PASS" in out, "svavyom-ctl status: PASS" if "RESULT: PASS" in out else out[-300:])
    rc, out = h.run("cat /usr/libexec/svavyom/VERSION", timeout=30)
    rec("installed-version", out.strip() == a.version, "installed %s" % out.strip())
    rc, out = h.run("curl -sk -o /dev/null -w '%{http_code}' https://127.0.0.1:8443/healthz", timeout=30)
    rec("api-https-on-the-host", out.strip() == "200", "GET https://127.0.0.1:8443/healthz -> %s" % out.strip())
    p = subprocess.run(["curl", "-sk", "-o", "/dev/null", "-w", "%{http_code}", "--max-time", "12", "https://%s:8443/healthz" % a.host], capture_output=True, text=True, check=False)  # noqa: S603,S607
    rec("api-https-from-outside", p.stdout.strip() == "200", "GET https://%s:8443/healthz from the qualifying machine -> %s (a firewall may need the port)" % (a.host, p.stdout.strip() or "no answer"))
    rc, out = h.run("openssl s_client -connect 127.0.0.1:8443 -servername %s </dev/null 2>/dev/null | openssl x509 -noout -subject -issuer 2>/dev/null" % a.tls_name, timeout=30)
    rec("certificate-is-the-self-signed-one", "svavyom" in out.lower() or a.tls_name in out, out.replace("\n", "; ")[:200] or "no certificate read")


IMAGE_URL = "https://cloud-images.ubuntu.com/noble/current"
IMAGE_FILE = "noble-server-cloudimg-amd64.img"
IMAGE_ID = "ubuntu-24.04"
WORKDIR = "/var/tmp/svavyom-qual"


def image_commands(run_id):
    """The commands that put an Ubuntu 24.04 cloud image in the catalog as the administrator would: download, check the published digest, register, verify, qualify
    (the evidence names this run: the image is qualified by the VM this run then boots). Nothing here takes a value from the host."""
    api = "sudo /usr/libexec/svavyom/api"
    cfg = "--provision-config /etc/svavyom/provision.json"
    return [
        ("image-downloaded", "cd /var/tmp && curl -fsSL -o %s %s/%s && curl -fsSL -o SHA256SUMS.cloud %s/SHA256SUMS && grep %s SHA256SUMS.cloud | sed 's/ \\*/  /' | sha256sum -c - && echo DIGEST_OK"
         % (IMAGE_FILE, IMAGE_URL, IMAGE_FILE, IMAGE_URL, IMAGE_FILE), "DIGEST_OK"),
        ("image-registered", "%s register-image %s --id %s --display-name 'Ubuntu 24.04' --distribution Ubuntu --version 24.04 --media disk --login-user ubuntu --cloud-init "
         "--min-disk-gib 10 --source /var/tmp/%s && echo REGISTERED" % (api, cfg, IMAGE_ID, IMAGE_FILE), "REGISTERED"),
        ("image-verified", "%s image-state %s --id %s --state verified && echo STATE_OK" % (api, cfg, IMAGE_ID), "STATE_OK"),
        ("image-qualified", "%s image-state %s --id %s --state qualified --evidence %s && echo STATE_OK" % (api, cfg, IMAGE_ID, run_id), "STATE_OK"),
    ]


def stage_image(h, a):
    for cid, cmd, want in image_commands(a.run_id):
        rc, out = h.run(cmd, timeout=1800)
        if not rec(cid, rc == 0 and want in out, "ok" if want in out and rc == 0 else out[-250:]):
            return
    h.run("rm -f /var/tmp/%s /var/tmp/SHA256SUMS.cloud" % IMAGE_FILE, timeout=60)


def vm_run_command(run_id, phase="all"):
    return ("cd %s && python3 qualify_install.py --base https://127.0.0.1:8443 --insecure-tls --password-file pw --pubkey key.pub --ssh-key key --image %s --run-id %s --out . "
            "--phase %s; echo EXIT=$?" % (WORKDIR, IMAGE_ID, run_id, phase))


def vm_setup(h, a):
    """Put the on-host harness, a disposable SSH key and the administrator's password (mode 0600, from this run's file) in a private directory on the host."""
    pw_path = os.path.join(a.out, "%s-admin-password" % a.run_id)
    if not os.path.isfile(pw_path):
        rec("admin-password", False, "no password file from the bootstrap stage of this run")
        return False
    pw = open(pw_path).read().strip()
    here = os.path.dirname(os.path.abspath(__file__))
    h.run("rm -rf %s && install -d -m 0700 %s && ssh-keygen -q -t ed25519 -N '' -f %s/key" % (WORKDIR, WORKDIR, WORKDIR), timeout=60)
    h.run("umask 077; cat > %s/pw" % WORKDIR, timeout=30, stdin=pw + "\n")
    rc, out = h.put(os.path.join(here, "qualify_install.py"), "%s/qualify_install.py" % WORKDIR)
    return rec("harness-copied", rc == 0, "tools/qualify_install.py is on the host" if rc == 0 else out[-150:])


def vm_phase(h, a, phase, prefix="vm:", timeout=3600):
    """Run one phase of the on-host harness and record each of its criteria as prefix+id. Returns the list of its results (empty when no result file came back)."""
    h.run(vm_run_command(a.run_id, phase), timeout=timeout)
    local = os.path.join(a.out, "%s-install-%s.json" % (a.run_id, phase))
    grc, gout = h.get("%s/%s-install.json" % (WORKDIR, a.run_id), local)
    if grc != 0 or not os.path.isfile(local):
        rec(prefix + "harness-result", False, "no result file came back (phase %s)" % phase)
        return []
    res = json.load(open(local)).get("results", [])
    for x in res:
        rec(prefix + x["id"], x["status"] == "PASS", x.get("detail", ""))
    return res


def vm_teardown(h):
    h.run("shred -u %s/pw %s/key 2>/dev/null; rm -rf %s" % (WORKDIR, WORKDIR, WORKDIR), timeout=60)


def stage_vm(h, a):
    if not vm_setup(h, a):
        return
    vm_phase(h, a, "all")
    vm_teardown(h)


def boot_id(h):
    try:
        rc, out = h.run("cat /proc/sys/kernel/random/boot_id", timeout=20)
    except subprocess.TimeoutExpired:
        return ""
    return out.strip() if rc == 0 else ""


def wait_for(fn, seconds, every=10):
    end = time.time() + seconds
    while time.time() < end:
        v = fn()
        if v:
            return v
        time.sleep(every)
    return None


def judge_after_reboot(status_out, net_out, pool_out, units_out):
    """[(criterion, ok, detail)] for a host that has just rebooted: the services are up through their own units, libvirt's default network and the Svavyom pool came back by themselves."""
    units = dict(ln.split(None, 1) for ln in units_out.splitlines() if " " in ln)
    return [
        ("services-up-after-reboot", "RESULT: PASS" in status_out, "svavyom-ctl status: PASS" if "RESULT: PASS" in status_out else status_out[-200:]),
        ("units-enabled-and-active", all(v.strip() == "enabled active" for k, v in units.items() if k != "svavyom-offsite"), "; ".join("%s %s" % (k, v.strip()) for k, v in sorted(units.items()))[:250]),
        ("libvirt-default-network-back", "Active:         yes" in net_out and "Autostart:      yes" in net_out, re.sub(r"\s+", " ", net_out)[:120]),
        ("svavyom-pool-back", "State:          running" in pool_out and "Autostart:      yes" in pool_out, re.sub(r"\s+", " ", pool_out)[:120]),
    ]


UNITS = ("svavyom-api", "svavyom-agent", "svavyom-mutation", "svavyom-console", "svavyom-offsite")
UNITS_CMD = "for u in %s; do echo \"$u $(systemctl is-enabled $u 2>&1) $(systemctl is-active $u 2>&1)\"; done" % " ".join(UNITS)


def stage_reboot(h, a):
    """A VM running, the HOST rebooted, then: the services and libvirt objects come back by themselves, the VM is still there with its data (what Svavyom does with a
    running VM at a host reboot is recorded, not judged), and the harness cleans up."""
    if not vm_setup(h, a):
        return
    pre = vm_phase(h, a, "up", prefix="pre:")
    before = boot_id(h)
    rec("boot-id-read", bool(before), "the host's boot id before the reboot was read")
    t0 = time.time()
    try:
        h.run("sudo systemctl reboot", timeout=30)
    except subprocess.TimeoutExpired:
        pass
    time.sleep(30)
    after = wait_for(lambda: (lambda b: b if b and b != before else None)(boot_id(h)), 900)
    rec("host-rebooted", bool(after), "the host came back with a new boot id after %d seconds" % (time.time() - t0) if after else "the host did not come back within 15 minutes")
    if not after:
        return
    ok = wait_for(lambda: "RESULT: PASS" in h.run("sudo /usr/libexec/svavyom/svavyom-ctl status", timeout=120)[1], 300, every=15)
    rc, status = h.run("sudo /usr/libexec/svavyom/svavyom-ctl status; true", timeout=120)
    net = h.run("sudo virsh -r -c qemu:///system net-info default", timeout=60)[1]
    pool = h.run("sudo virsh -r -c qemu:///system pool-info svavyom", timeout=60)[1]
    units = h.run(UNITS_CMD, timeout=60)[1]
    for cid, good, detail in judge_after_reboot(status, net, pool, units):
        rec(cid, good, detail)
    p = subprocess.run(["curl", "-sk", "-o", "/dev/null", "-w", "%{http_code}", "--max-time", "12", "https://%s:8443/healthz" % a.host], capture_output=True, text=True, check=False)  # noqa: S603,S607
    rec("api-https-from-outside-after-reboot", p.stdout.strip() == "200", "GET https://%s:8443/healthz -> %s" % (a.host, p.stdout.strip() or "no answer"))
    vm_phase(h, a, "afterboot", prefix="post:")
    vm_phase(h, a, "down", prefix="post:")
    vm_teardown(h)


def backup_id_from_listing(text):
    """The newest backup id in `svavyom-ctl backups` output: the ids start with a UTC stamp, so the largest sorts last."""
    ids = re.findall(r"\b(20[0-9]{6}T[0-9]{6}Z-[0-9A-Za-z.+-]+-to-[0-9A-Za-z.+-]+)\b", text)
    return sorted(set(ids))[-1] if ids else ""


def rollback_target(backup_id):
    """The version a rollback from this backup returns to: the part between the stamp and `-to-`."""
    m = re.fullmatch(r"20[0-9]{6}T[0-9]{6}Z-(.+)-to-(.+)", backup_id or "")
    return m.group(1) if m else ""


def stage_rollback(h, a):
    """Roll the installation back to the backup the last upgrade made, check it is the earlier version and healthy, then (with --artifact) upgrade again."""
    rc, ver = h.run("cat /usr/libexec/svavyom/VERSION", timeout=30)
    before = ver.strip()
    rc, listing = h.run("sudo /usr/libexec/svavyom/svavyom-ctl backups", timeout=60)
    bid = backup_id_from_listing(listing)
    want = rollback_target(bid)
    if not rec("rollback-backup-found", bool(bid) and bool(want), "the newest backup is %s (returns to %s)" % (bid, want) if bid else "no upgrade backup is listed"):
        return
    ctl = "sudo /usr/libexec/svavyom/svavyom-ctl rollback --backup %s" % bid
    rc, plan = h.run(ctl + "; echo EXIT=$?", timeout=300)
    if "refusing" in plan:
        # the upgrade moved a database schema: the old version cannot read it, so the plan without the database copy is refused (that is the designed safety)
        rec("rollback-refused-without-the-database-copy", "EXIT=0" not in plan and "pre-upgrade database copy" in plan, "refused, and it names the pre-upgrade copy as the only way back")
        rc, plan = h.run(ctl + " --restore-db; echo EXIT=$?", timeout=300)
    rec("rollback-plan", "EXIT=0" in plan, "the plan was printed and nothing was changed" if "EXIT=0" in plan else plan[-300:])
    rc, now = h.run("cat /usr/libexec/svavyom/VERSION", timeout=30)
    rec("rollback-plan-changed-nothing", now.strip() == before, "still %s after the plan" % now.strip())
    rc, out = h.run(ctl + (" --restore-db" if a.restore_db else "") + " --apply; echo EXIT=$?", timeout=1200)
    rec("rollback-applied", "EXIT=0" in out, "rolled back from %s" % before if "EXIT=0" in out else out[-500:])
    rc, ver = h.run("cat /usr/libexec/svavyom/VERSION", timeout=30)
    rec("rollback-version", ver.strip() == want, "installed %s, expected %s" % (ver.strip(), want))
    ok = wait_for(lambda: "RESULT: PASS" in h.run("sudo /usr/libexec/svavyom/svavyom-ctl status", timeout=120)[1], 180, every=10)
    rec("services-and-health-after-rollback", bool(ok), "svavyom-ctl status: PASS" if ok else "status is not PASS 3 minutes after the rollback")
    if vm_setup(h, a):
        vm_phase(h, a, "check", prefix="rolled-back:", timeout=600)
        vm_teardown(h)
    if a.artifact:
        stage_upgrade(h, a)
        rc, ver = h.run("cat /usr/libexec/svavyom/VERSION", timeout=30)
        rec("upgraded-again", ver.strip() == a.version, "installed %s after the second upgrade" % ver.strip())
        if vm_setup(h, a):
            vm_phase(h, a, "check", prefix="upgraded-again:", timeout=600)
            vm_teardown(h)


def stage_features(h, a):
    """The installed service's console features that are not about VMs (System data, saved SSH keys, users and passwords), driven through the API on the host."""
    if not vm_setup(h, a):
        return
    vm_phase(h, a, "features", prefix="features:", timeout=900)
    vm_teardown(h)


def stage_nightly(h, a):
    """The nightly boot check, run now: it creates, boots and deletes a disposable VM through the API as its own operator account, and records the result."""
    rc, out = h.run("sudo test -f /etc/svavyom/nightly-credential && echo CRED || echo NOCRED", timeout=60)
    rec("nightly-enabled", "CRED" in out and "NOCRED" not in out, "the nightly check is set up (credential present)" if "NOCRED" not in out else "not enabled: install or upgrade with --enable-nightly-boot HH:MM")
    t0 = time.time()
    rc, out = h.run("sudo /usr/libexec/svavyom/svavyom-ctl nightly-boot; echo EXIT=$?", timeout=1800)
    rec("nightly-boot-run", "EXIT=0" in out and re.search(r"\bpass\b", out, re.I) is not None, ("passed in %d seconds" % (time.time() - t0)) if "EXIT=0" in out else out[-300:])
    rc, left = h.run("sudo virsh -r -c qemu:///system list --all --name | grep -c -i nightly || true", timeout=60)
    rec("nightly-left-nothing", left.strip() in ("0", ""), "no nightly VM is left on the host")


def firewall_rules(h):
    # the rules, not the packet counters (those change with every packet): ufw's own view, then the kernel's rules in iptables and nftables syntax
    return h.run("sudo ufw status verbose; sudo iptables -S 2>/dev/null | md5sum; sudo nft list ruleset 2>/dev/null | sed -E 's/counter packets [0-9]+ bytes [0-9]+/counter/' | md5sum", timeout=60)[1]


WATCHDOG = "svq-ufw-watchdog"


def ufw_prepare_command():
    """Save ufw's files and whether the firewall itself is ACTIVE (`ufw status`, not the service: on Ubuntu the ufw service reports active while the firewall is off), allow ssh and the
    API FIRST, and arm a timer on the host that switches ufw off after 20 minutes unless this run cancels it, so a run that dies cannot leave the host unreachable."""
    return ("sudo rm -rf /var/tmp/ufw-before && sudo cp -a /etc/ufw /var/tmp/ufw-before && (sudo ufw status | head -1 > /var/tmp/ufw-was); "
            "sudo systemd-run --quiet --on-active=20m --unit=%s /usr/sbin/ufw --force disable && "
            "sudo ufw allow 22/tcp && sudo ufw allow 8443/tcp && sudo ufw default deny incoming && sudo ufw default deny routed && sudo ufw --force enable" % WATCHDOG)


def ufw_restore_command(was_active):
    """Put ufw back exactly as it was: switch it off, bring the saved files back, and switch it on again ONLY if it was active before AND ssh stays allowed in what was saved."""
    cmd = "sudo ufw --force disable; sudo rm -rf /etc/ufw && sudo cp -a /var/tmp/ufw-before /etc/ufw"
    if was_active:
        cmd += " && sudo ufw allow 22/tcp && sudo ufw --force enable"
    return cmd + "; rm -rf /var/tmp/ufw-before /var/tmp/ufw-was"


def stage_firewall(h, a):
    """ufw switched on (deny incoming and routed, with only ssh and the API allowed): svavyom-ctl firewall-check says what it sees and changes no rule, the API still
    answers, and a VM still gets an address and answers SSH. The firewall is put back exactly as it was; a watchdog timer on the host undoes the test if this run dies."""
    if not vm_setup(h, a):
        return
    h.run(ufw_prepare_command(), timeout=120)
    was_active = "Status: active" in h.run("cat /var/tmp/ufw-was", timeout=30)[1]
    try:
        active = h.run("sudo ufw status | head -1", timeout=30)[1]
        rec("ufw-active", "Status: active" in active, active.strip())
        before = firewall_rules(h)
        rc, js = h.run("sudo /usr/libexec/svavyom/svavyom-ctl firewall-check --json", timeout=120)
        try:
            findings = json.loads(js).get("findings", [])
        except ValueError:
            findings = None
        rec("firewall-check-ran", findings is not None, "findings: %s" % (", ".join(f["code"] for f in findings) or "none") if findings is not None else js[-200:])
        rec("firewall-check-changed-no-rule", firewall_rules(h) == before, "the ufw and kernel rules are the same before and after svavyom-ctl firewall-check")
        p = subprocess.run(["curl", "-sk", "-o", "/dev/null", "-w", "%{http_code}", "--max-time", "12", "https://%s:8443/healthz" % a.host], capture_output=True, text=True, check=False)  # noqa: S603,S607
        rec("api-answers-with-ufw-on", p.stdout.strip() == "200", "GET https://%s:8443/healthz -> %s" % (a.host, p.stdout.strip() or "no answer"))
        vm_phase(h, a, "up", prefix="ufw-on:")
        vm_phase(h, a, "down", prefix="ufw-on:")
    finally:
        h.run(ufw_restore_command(was_active), timeout=120)
        back = h.run("sudo ufw status | head -1; echo reachable", timeout=30)[1]
        rec("ufw-restored", ("Status: active" in back) == was_active and "reachable" in back, "the firewall is back as it was (%s) and the host is still reachable: %s" % ("active" if was_active else "inactive", back.splitlines()[0].strip()))
        h.run("sudo systemctl stop %s.timer 2>/dev/null; true" % WATCHDOG, timeout=30)  # the host is reachable again: the watchdog is no longer needed
    vm_teardown(h)


FUNCS = {"facts": stage_facts, "prepare": stage_prepare, "install": stage_install, "bootstrap": stage_bootstrap, "verify": stage_verify, "image": stage_image, "vm": stage_vm, "upgrade": stage_upgrade, "rollback": stage_rollback, "reboot": stage_reboot, "nightly": stage_nightly, "firewall": stage_firewall, "features": stage_features}


def validate(a):
    out = []
    if not HOST_RE.fullmatch(a.host or ""):
        out.append("--host must be an IPv4 address")
    if not NAME_RE.fullmatch(a.tls_name or ""):
        out.append("--tls-name is not a host name")
    if not RUN_RE.fullmatch(a.run_id or ""):
        out.append("run id must look like qr-YYYYMMDD-xxxxxx")
    if not a.key or not os.path.isfile(a.key):
        out.append("--key not found")
    if a.stage not in STAGES:
        out.append("unknown stage")
    if getattr(a, "nightly", "") and not re.fullmatch(r"([01][0-9]|2[0-3]):[0-5][0-9]", a.nightly):
        out.append("--nightly must be a time of day written HH:MM")
    if a.stage == "install" and not (a.artifact and os.path.isfile(os.path.join(a.artifact, "MANIFEST.json"))):
        out.append("--artifact must be a release artifact directory")
    if bool(a.signatures) != bool(a.public_key):
        out.append("--signatures and --public-key go together")
    return out


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--host", required=True)
    ap.add_argument("--user", default="inuser")
    ap.add_argument("--key", required=True)
    ap.add_argument("--stage", required=True, choices=STAGES)
    ap.add_argument("--artifact", default="")
    ap.add_argument("--signatures", default="")
    ap.add_argument("--public-key", default="")
    ap.add_argument("--tls-name", required=True, help="the host name the self-signed certificate is made for")
    ap.add_argument("--listen", default="0.0.0.0:8443")
    ap.add_argument("--out", required=True)
    ap.add_argument("--nightly", default="", help="upgrade stage: also enable the nightly boot check at HH:MM (host time)")
    ap.add_argument("--restore-db", action="store_true", help="rollback stage: also put the database copy made by the upgrade back")
    ap.add_argument("--run-id", default="qr-" + time.strftime("%Y%m%d") + "-" + secrets.token_hex(3))
    a = ap.parse_args(argv)
    a.version = ""
    if a.artifact and os.path.isfile(os.path.join(a.artifact, "VERSION")):
        a.version = open(os.path.join(a.artifact, "VERSION")).read().strip()
    bad = validate(a)
    if bad:
        for b in bad:
            print("ERROR", b)
        return 2
    os.makedirs(a.out, exist_ok=True)
    FUNCS[a.stage](Host(a.user, a.host, a.key), a)
    fails = [x["id"] for x in R if x["status"] != "PASS"]
    verdict = "PASS" if R and not fails else "FAIL"
    with open(os.path.join(a.out, "%s-clean-host-%s.json" % (a.run_id, a.stage)), "w") as f:
        json.dump({"run_id": a.run_id, "host": a.host, "stage": a.stage, "results": R, "verdict": verdict}, f, indent=1)
    print("RESULT", verdict, fails or "")
    return 0 if verdict == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
