#!/usr/bin/env python3
"""Clean-host qualification of Svavyom (first-release checklist, wave 5). Stdlib only. Drives ONE fresh Ubuntu host over SSH, stage by stage, and records every criterion.

    python3 tools/qualify_clean_host.py --host 203.0.113.10 --key ~/.ssh/KEY --tls-name HOST.example --artifact release-out/svavyom-0.1.0-preview.15 --out DIR --stage facts
    stages: facts (read-only) | prepare (apt: qemu and libvirt) | install (copy the artifact to a root-owned place, preflight, install) | bootstrap (the first administrator)
            | verify (services, API health on the host and from here)

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
STAGES = ["facts", "prepare", "install", "bootstrap", "verify"]
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


def stage_install(h, a):
    tmp = os.path.join(a.out, "%s-artifact.tgz" % a.run_id)
    name = tar_artifact(a.artifact, tmp)
    rc, out = h.put(tmp, "/tmp/%s.tgz" % name)
    os.remove(tmp)
    if not rec("artifact-copied", rc == 0, out[-120:] if rc else "copied to the host"):
        return
    cmd = ("sudo install -d -m 0755 -o root -g root %s && sudo tar -C %s -xzf /tmp/%s.tgz && sudo chown -R root:root %s/%s && sudo chmod -R go-w %s/%s && rm -f /tmp/%s.tgz "
           "&& cd %s/%s && sudo sha256sum --quiet -c SHA256SUMS && echo VERIFIED") % (REMOTE_ARTIFACTS, REMOTE_ARTIFACTS, name, REMOTE_ARTIFACTS, name, REMOTE_ARTIFACTS, name, name, REMOTE_ARTIFACTS, name)
    rc, out = h.run(cmd, timeout=120)
    if not rec("artifact-root-owned-and-intact", rc == 0 and "VERIFIED" in out, "under %s, root-owned, every digest matches SHA256SUMS" % REMOTE_ARTIFACTS if rc == 0 else out[-200:]):
        return
    signed = bool(a.signatures and a.public_key)
    if signed:
        for local, remote in ((a.public_key, "%s/release-signing-key.pub" % REMOTE_ARTIFACTS),):
            rc, out = h.put(local, "/tmp/k.pub")
            h.run("sudo install -m 0644 -o root -g root /tmp/k.pub %s && rm -f /tmp/k.pub" % remote)
        sigtmp = os.path.join(a.out, "%s-sigs.tgz" % a.run_id)
        subprocess.run(["tar", "-C", os.path.dirname(os.path.abspath(a.signatures)), "-czf", sigtmp, os.path.basename(os.path.normpath(a.signatures))], check=True)  # noqa: S603,S607
        h.put(sigtmp, "/tmp/sigs.tgz")
        os.remove(sigtmp)
        h.run("sudo rm -rf %s/signatures && sudo mkdir -p %s/signatures && sudo tar -C %s/signatures --strip-components=1 -xzf /tmp/sigs.tgz && sudo chown -R root:root %s/signatures && rm -f /tmp/sigs.tgz" % ((REMOTE_ARTIFACTS,) * 4))
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


FUNCS = {"facts": stage_facts, "prepare": stage_prepare, "install": stage_install, "bootstrap": stage_bootstrap, "verify": stage_verify}


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
