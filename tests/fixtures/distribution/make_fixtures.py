#!/usr/bin/env python3
"""Generate the M0-E02-S05 fixture roots (data only; reviewed and committed).

Each root is a minimal filesystem tree the capability checker reads with
--root. Special files (FIFO, socket), unreadable files and oversized inputs
are created at test time, never committed. Run from the repository root:
  python3 tests/fixtures/distribution/make_fixtures.py
"""
import json
import os
import shutil
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOTS = HERE / "roots"

CPU_FLAGS = "fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush mmx fxsr sse sse2 ht syscall nx lm constant_tsc pni ssse3 sse4_1 sse4_2 x2apic popcnt aes xsave avx"


def os_release(id_, version=None, name=None, extra=""):
    lines = ['PRETTY_NAME="%s"' % (name or id_), "ID=%s" % id_]
    if version is not None:
        lines.append('VERSION_ID="%s"' % version)
    return "\n".join(lines) + "\n" + extra


def base(id_="debian", version="13", kernel="6.12.48+deb13-amd64", vmx=True):
    flags = CPU_FLAGS + (" vmx" if vmx else "")
    cpu = "".join("processor\t: %d\nvendor_id\t: GenuineIntel\nmodel name\t: Fixture CPU\nflags\t\t: %s\n\n" % (i, flags) for i in range(2))
    return {
        "usr/lib/os-release": os_release(id_, version),
        "etc/os-release": ("symlink", "../usr/lib/os-release"),
        "etc/hostname": "fixture-secret-hostname\n",
        "etc/machine-id": "fixture-machine-id-not-real\n",
        "proc/sys/kernel/arch": "x86_64\n",
        "proc/cpuinfo": cpu,
        "proc/sys/kernel/osrelease": kernel + "\n",
        "proc/self/mountinfo": ("25 1 259:2 / / rw,relatime shared:1 - ext4 /dev/nvme0n1p2 rw\n"
                                "30 25 0:26 / /sys/fs/cgroup rw,nosuid,nodev,noexec shared:4 - cgroup2 cgroup2 rw\n"
                                "22 25 0:21 / /proc rw,nosuid,nodev,noexec shared:12 - proc proc rw\n"),
        "proc/self/uid_map": "         0          0 4294967295\n",
        "proc/1/environ": "HOME=/\0TERM=linux\0BOOT_IMAGE=/vmlinuz\0",
        "proc/1/cgroup": "0::/init.scope\n",
        "proc/modules": "nf_tables 380928 0 - Live 0x0000000000000000\nx_tables 65536 0 - Live 0x0000000000000000\n",
        "sys/fs/cgroup/cgroup.controllers": "cpuset cpu io memory hugetlb pids rdma misc\n",
        "run/systemd/system/.fixture": "",
        "sys/module/nf_tables/.fixture": "",
        "sys/module/apparmor/parameters/enabled": "Y\n",
        "sys/kernel/security/lsm": "lockdown,capability,landlock,yama,apparmor\n",
        "sys/class/dmi/id/sys_vendor": "Dell Inc.\n",
        "usr/sbin/nft": "",
        "var/lib/dpkg/status": ("Package: base-files\nStatus: install ok installed\nVersion: 13.8\n\n"
                                "Package: systemd\nStatus: install ok installed\nVersion: 257.8-1\n"),
    }


def variant(**changes):
    """Return a base tree with changes: value None deletes the path."""
    def build(b=None):
        tree = b or base()
        for k, v in changes.items():
            if v is None:
                tree = {p: c for p, c in tree.items() if not (p == k or p.startswith(k + "/"))}
            else:
                tree[k] = v
        return tree
    return build


def no_nf(tree):
    tree = {p: c for p, c in tree.items() if not p.startswith("sys/module/nf_tables")}
    tree["proc/modules"] = "x_tables 65536 0 - Live 0x0000000000000000\n"
    return tree


FIXTURES = {
    # supported (matrix conformance only; qualification: none)
    "debian-13": (lambda: base(), "supported"),
    "ubuntu-24.04": (lambda: base("ubuntu", "24.04", "6.8.0-45-generic"), "supported"),
    "ubuntu-26.04": (lambda: base("ubuntu", "26.04", "6.17.0-5-generic"), "supported"),
    "proxmox-like": (lambda: dict(base(kernel="6.8.12-4-pve"), **{"etc/pve/.fixture": ""}), "supported"),
    "nftables-builtin": (lambda: dict(no_nf(base()), **{
        "lib/modules/6.12.48+deb13-amd64/modules.builtin": "kernel/net/netfilter/nf_tables.ko\n"}), "supported"),
    # unsupported
    "ubuntu-22.04": (lambda: base("ubuntu", "22.04", "5.15.0-119-generic"), "unsupported"),
    "debian-12": (lambda: base("debian", "12", "6.1.0-25-amd64"), "unsupported"),
    "debian-sid": (lambda: dict(base(), **{"usr/lib/os-release": os_release("debian", None, "Debian GNU/Linux trixie/sid")}), "unsupported"),
    "almalinux-9": (lambda: dict(base("almalinux", "9.4", "5.14.0-427.el9.x86_64"), **{"sys/fs/selinux/enforce": "1\n"}), "unsupported"),
    "rocky-9": (lambda: dict(base("rocky", "9.4", "5.14.0-427.el9.x86_64"), **{"sys/fs/selinux/enforce": "1\n"}), "unsupported"),
    "derivative-pop": (lambda: dict(base(), **{"usr/lib/os-release": os_release("pop", "24.04", "Pop!_OS 24.04", 'ID_LIKE="ubuntu debian"\n')}), "unsupported"),
    "no-cpu-virt": (lambda: base(vmx=False), "unsupported"),
    "apparmor-disabled": (variant(**{"sys/module/apparmor/parameters/enabled": "N\n"}), "unsupported"),
    "apparmor-not-in-lsm": (variant(**{"sys/kernel/security/lsm": "lockdown,capability,landlock,yama\n"}), "unsupported"),
    "cgroup-hybrid": (variant(**{"proc/self/mountinfo": "25 1 259:2 / / rw - ext4 /dev/sda2 rw\n30 25 0:26 / /sys/fs/cgroup ro - tmpfs tmpfs ro\n"}), "unsupported"),
    "no-systemd": (variant(**{"run/systemd": None}), "unsupported"),
    "kernel-below-floor": (lambda: base(kernel="6.1.0-25-amd64"), "unsupported"),
    "vm-guest": (lambda: dict(base(), **{"proc/cpuinfo": base()["proc/cpuinfo"].replace(" vmx", " vmx hypervisor")}), "unsupported"),
    "dmi-guest": (variant(**{"sys/class/dmi/id/sys_vendor": "QEMU\n"}), "unsupported"),
    "arch-arm64": (variant(**{"proc/sys/kernel/arch": "aarch64\n"}), "unsupported"),
    # unknown
    "nftables-undetermined": (lambda: no_nf(base()), "unknown"),
    "docker-container": (variant(**{".dockerenv": ""}), "unknown"),
    "podman-container": (variant(**{"run/.containerenv": ""}), "unknown"),
    "lxc-container": (variant(**{"run/systemd/container": "lxc\n", "proc/1/cgroup": "0::/\n"}), "unknown"),
    "userns-container": (variant(**{"proc/self/uid_map": "         0     100000      65536\n"}), "unknown"),
    "environ-container": (variant(**{"proc/1/environ": "container=systemd-nspawn\0HOME=/\0"}), "unknown"),
    "overlay-root": (variant(**{"proc/self/mountinfo": "25 1 0:40 / / rw - overlay overlay rw\n30 25 0:26 / /sys/fs/cgroup rw - cgroup2 cgroup2 rw\n"}), "unknown"),
    "osrelease-duplicate": (variant(**{"usr/lib/os-release": "ID=debian\nID=ubuntu\nVERSION_ID=13\n"}), "unknown"),
    "osrelease-nul": (variant(**{"usr/lib/os-release": "ID=debian\nVERSION_ID=\"13\0\"\n"}), "unknown"),
    "osrelease-nonutf8": (variant(**{"usr/lib/os-release": b"ID=debian\nVERSION_ID=\"13\xff\"\n"}), "unknown"),
    "osrelease-longline": (variant(**{"usr/lib/os-release": "ID=debian\nVERSION_ID=13\nX=" + "a" * 5000 + "\n"}), "unknown"),
    "osrelease-badquote": (variant(**{"usr/lib/os-release": "ID=debian\nVERSION_ID=\"13\n"}), "unknown"),
    "symlink-escape": (variant(**{"etc/os-release": ("symlink", "../../../../../etc/passwd"), "usr/lib/os-release": None}), "unknown"),
    "symlink-absolute": (variant(**{"etc/os-release": ("symlink", "/usr/lib/os-release")}), "unknown"),
    "symlink-loop": (variant(**{"etc/os-release": ("symlink", "os-release")}), "unknown"),
    "missing-cpuinfo": (variant(**{"proc/cpuinfo": None}), "unknown"),
}


def write_tree(root, tree):
    for rel, content in sorted(tree.items()):
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, tuple) and content[0] == "symlink":
            os.symlink(content[1], p)
        elif isinstance(content, bytes):
            p.write_bytes(content)
        else:
            p.write_bytes(content.encode("utf-8"))


def main():
    if ROOTS.exists():
        shutil.rmtree(ROOTS)
    expected = {}
    for name, (build, verdict) in sorted(FIXTURES.items()):
        write_tree(ROOTS / name, build())
        expected[name] = verdict
    (HERE / "expected-verdicts.json").write_text(json.dumps(expected, indent=2, sort_keys=True) + "\n")
    print("%d fixture roots" % len(FIXTURES))


if __name__ == "__main__":
    main()
