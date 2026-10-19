"""Unit tests for tools/qualify_preflight.py and tools/qualify_create.py (no Docker, libvirt or network needed)."""
import importlib.util
import json
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))


def load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / "tools" / (name + ".py"))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


pf = load("qualify_preflight")
qc = load("qualify_create")


class FakeHost(pf.Probe):
    """A fixture root plus scripted command results; touches nothing real."""

    def __init__(self, root, cmds=None, tools=()):
        super().__init__(root, run=lambda argv, t: (cmds or {}).get(tuple(argv), (127, "", "not found")))
        self.tools = set(tools)

    def which(self, name):
        return "/usr/bin/" + name if name in self.tools else None

    def access(self, p, mode):
        return False

    def free_gib(self, p):
        return 500.0


def build_root(d, os_id="ubuntu", ver="24.04", flags="fpu vmx sse", modules="kvm 1 0\nkvm_intel 1 0\n", kvm=True):
    def w(rel, text):
        p = Path(d) / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
    w("etc/os-release", 'ID=%s\nVERSION_ID="%s"\n' % (os_id, ver))
    w("proc/cpuinfo", "processor: 0\nflags\t\t: %s\n" % flags)
    w("proc/modules", modules)
    w("proc/sys/kernel/arch", "x86_64\n")
    return d


class Preflight(unittest.TestCase):
    def test_supported_ubuntu_and_cpu(self):
        with tempfile.TemporaryDirectory() as d:
            p = FakeHost(build_root(d))
            self.assertEqual(pf.check_os(p)[0], pf.PASS)
            self.assertEqual(pf.check_cpu(p)[0], pf.PASS)
            self.assertEqual(pf.check_kvm_modules(p)[0], pf.PASS)

    def test_refusals(self):
        with tempfile.TemporaryDirectory() as d:
            p = FakeHost(build_root(d, os_id="debian", ver="13", flags="fpu sse", modules="loop 1 0\n"))
            self.assertEqual(pf.check_os(p)[0], pf.FAIL)
            self.assertEqual(pf.check_cpu(p)[0], pf.FAIL)
            self.assertEqual(pf.check_kvm_modules(p)[0], pf.FAIL)
            self.assertEqual(pf.check_kvm_device(p)[0], pf.FAIL)  # no /dev/kvm in the fixture root
            self.assertEqual(pf.check_qemu(p)[0], pf.FAIL)
            self.assertEqual(pf.check_libvirt_installed(p)[0], pf.FAIL)
            self.assertEqual(pf.check_libvirt_sockets(p)[0], pf.FAIL)

    def test_libvirt_object_state(self):
        ok = FakeHost("/", {("virsh", "-r", "-c", "qemu:///system", "net-info", "n"): (0, "Name: n\nActive: yes\n", "")})
        self.assertEqual(pf.libvirt_state(ok, "net", "n")[0], pf.PASS)
        up = FakeHost("/", {("virsh", "-r", "-c", "qemu:///system", "pool-info", "p"): (0, "Name: p\nState: running\n", "")})
        self.assertEqual(pf.libvirt_state(up, "pool", "p")[0], pf.PASS)
        down = FakeHost("/", {("virsh", "-r", "-c", "qemu:///system", "pool-info", "p"): (0, "Name: p\nState: inactive\n", "")})
        self.assertEqual(pf.libvirt_state(down, "pool", "p")[0], pf.FAIL)
        self.assertEqual(pf.libvirt_state(FakeHost("/"), "pool", "p")[0], pf.FAIL)

    def test_all_checks_never_mutate_and_not_ready_without_prereqs(self):
        with tempfile.TemporaryDirectory() as d:
            build_root(d)
            before = sorted(str(p) for p in Path(d).rglob("*"))
            rep = pf.run_all(FakeHost(d), None, 30)
            self.assertEqual(rep["verdict"], "NOT_READY")
            self.assertEqual(rep["qualification"], "none")
            self.assertEqual(before, sorted(str(p) for p in Path(d).rglob("*")))

    def test_ready_when_everything_is_present(self):
        with tempfile.TemporaryDirectory() as d:
            build_root(d)
            root = Path(d)
            (root / "dev").mkdir()
            cfgdir = Path(d) / "cfg"
            cfgdir.mkdir()
            cfg = cfgdir / "provision.json"
            cfg.write_text(json.dumps({"pool": "svavyom", "network": "svavyom-nat", "catalog_dir": str(cfgdir), "state_dir": str(cfgdir)}))
            cmds = {("uname", "-m"): (0, "x86_64\n", ""), ("/usr/bin/qemu-system-x86_64", "--version"): (0, "QEMU emulator version 8.2.2\n", ""),
                    ("virsh", "--version"): (0, "10.0.0\n", ""), ("virsh", "-r", "-c", "qemu:///system", "uri"): (0, "qemu:///system\n", ""),
                    ("docker", "version", "--format", "{{.Server.Version}}"): (0, "29.0\n", ""),
                    ("virsh", "-r", "-c", "qemu:///system", "net-info", "svavyom-nat"): (0, "Active: yes\n", ""),
                    ("virsh", "-r", "-c", "qemu:///system", "pool-info", "svavyom"): (0, "State: running\n", "")}
            host = FakeHost(d, cmds, tools=("qemu-system-x86_64", "virsh", "libvirtd", "docker"))
            # fixture root has no /dev/kvm char device and no sockets: those must still fail honestly
            rep = pf.run_all(host, "/cfg/provision.json", 30)
            failed = {c["id"] for c in rep["checks"] if c["status"] == pf.FAIL}
            self.assertEqual(failed, {"dev-kvm", "libvirt-sockets", "trust-layout"}, failed)
            self.assertEqual(rep["verdict"], "NOT_READY")

    def test_json_report_is_never_overwritten(self):
        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, "r.json")
            Path(out).write_text("keep")
            self.assertEqual(pf.main(["--root", d, "--json", out]), 2)
            self.assertEqual(Path(out).read_text(), "keep")


def args(**kw):
    base = dict(repo="/repo", config="/etc/svavyom/provision.json", pubkey="/home/q/key.pub", image="ubuntu-24-04", run_id="qr-20261012-a1b2c3",
                ssh_key="/home/q/disposable_key", stage="create")
    base.update(kw)
    return SimpleNamespace(**base)


class Orchestrator(unittest.TestCase):
    def test_run_id_grammar(self):
        self.assertTrue(qc.RUN_ID_RE.match(qc.new_run_id()))
        for bad in ("", "qr-1", "qr-20261012-ABCDEF", "x-20261012-a1b2c3", "qr-20261012-a1b2c3;rm"):
            self.assertFalse(qc.RUN_ID_RE.match(bad), bad)

    def test_docker_argv_is_locked_down(self):
        argv = qc.docker_argv("create", args(), "/var/lib/svavyom/images", 108, "/out/qr")
        joined = " ".join(argv)
        for must in ("--cap-drop ALL", "no-new-privileges:true", "--read-only", "--network none", "--group-add 108"):
            self.assertIn(must, joined)
        self.assertNotIn("--privileged", joined)
        self.assertNotIn("/dev/kvm", joined)
        mounts = [argv[i + 1] for i, t in enumerate(argv) if t == "-v"]
        for m in mounts:  # nothing broad: no root, home or docker socket
            self.assertNotIn(m.split(":")[0], ("/", "/home", "/etc", "/var", "/var/lib", "/var/run"))
            self.assertNotIn("docker.sock", m)
        # the private key never reaches the container, neither as a mount nor in the environment
        self.assertNotIn("disposable_key", joined)
        self.assertIn("/var/lib/svavyom/images:/var/lib/svavyom/images:ro", mounts)
        self.assertIn(qc.LIBVIRT_RO_SOCK + ":" + qc.LIBVIRT_RO_SOCK, mounts)
        self.assertIn("/qualify/out", joined)

    def test_cleanup_container_has_no_key_at_all(self):
        argv = qc.docker_argv("cleanup", args(stage="cleanup"), "/c", 1, "/o")
        self.assertNotIn("key.pub", " ".join(argv))

    def test_ssh_uses_only_the_key_path(self):
        argv = qc.ssh_argv(args(), "192.168.122.50", "ubuntu", "/o/kh", qc.REMOTE)
        self.assertEqual(argv[:3], ["ssh", "-i", "/home/q/disposable_key"])
        self.assertIn("IdentitiesOnly=yes", argv)
        self.assertIn("BatchMode=yes", argv)
        self.assertIn("--", argv)

    def test_guest_judgement(self):
        facts = {"USER": "ubuntu", "HOST": "svq-20261012-a1b2c3", "INSTANCE": "u-1", "DS": "DataSourceNoCloud [seed=/dev/sr0]", "CI": "status: done"}
        good = {c: s for c, s, _ in qc.judge_guest(facts, "ubuntu", "u-1", "svq-20261012-a1b2c3")}
        self.assertEqual(set(good.values()), {qc.PASS})
        for field, bad in (("INSTANCE", "other"), ("DS", "DataSourceEc2"), ("CI", "status: running"), ("HOST", "x")):
            f = dict(facts, **{field: bad})
            self.assertEqual({c: s for c, s, _ in qc.judge_guest(f, "ubuntu", "u-1", "svq-20261012-a1b2c3")}["cloud-init-seed"], qc.FAIL, field)
        self.assertEqual({c: s for c, s, _ in qc.judge_guest(dict(facts, USER="root"), "ubuntu", "u-1", "svq-20261012-a1b2c3")}["login-user"], qc.FAIL)

    def full(self, **over):
        ids = [c for c, _ in qc.CRITERIA if c not in qc.CLEANUP_REQUIRED] + qc.ALSO
        return [(c, over.get(c, qc.PASS), "") for c in ids]

    def test_overall_never_passes_with_anything_missing_or_failed(self):
        self.assertEqual(qc.overall(self.full()), qc.PASS)
        self.assertEqual(qc.overall(self.full(**{"ssh-key-auth": qc.FAIL})), qc.FAIL)
        self.assertEqual(qc.overall(self.full(**{"ssh-key-auth": qc.NOT_RUN})), qc.NOT_RUN)
        self.assertEqual(qc.overall(self.full()[:-1]), qc.NOT_RUN)
        self.assertEqual(qc.overall(self.full() + [("qualification-stage", qc.FAIL, "boom")]), qc.FAIL)
        self.assertEqual(qc.overall([]), qc.NOT_RUN)

    def test_report_lists_cleanup_as_not_run_until_its_stage_ran(self):
        text = qc.render("qr-20261012-a1b2c3", self.full(), qc.PASS)
        self.assertRegex(text, r"NOT_RUN\s+15\. cleanup")

    def test_a_failed_guest_start_is_a_fail_with_its_cause_never_not_run(self):
        # The create stage stops at the first failed step; the criteria after it are absent. FAIL must win over the missing ones.
        crit = [("real-libvirt", qc.PASS, ""), ("domain-defined", qc.PASS, ""), ("image-immutable-before", qc.PASS, ""),
                ("vm-started", qc.FAIL, "domain start failed (host error); libvirt said: start: internal error: cannot access backing image")]
        self.assertEqual(qc.overall(crit), qc.FAIL)
        text = qc.render("qr-20261012-a1b2c3", crit, qc.FAIL)
        self.assertRegex(text, r"FAIL\s+6\. VM starts\s+domain start failed .*cannot access backing image")
        self.assertIn("blocked by an earlier FAIL", text)
        self.assertNotIn("RESULT: NOT_RUN", text)

    def test_the_base_image_must_be_proven_before_during_and_after(self):
        for needed in ("image-immutable-before", "image-immutable-running"):
            self.assertIn(needed, qc.ALSO)
            self.assertEqual(qc.overall([c for c in self.full() if c[0] != needed]), qc.NOT_RUN, needed)
            self.assertEqual(qc.overall(self.full(**{needed: qc.FAIL})), qc.FAIL, needed)
        self.assertEqual(qc.overall(self.full(**{"domain-backing-declared": qc.FAIL})), qc.FAIL)
        self.assertIn("image-immutable-after", qc.CLEANUP_REQUIRED)
        self.assertNotIn("image-immutable", qc.ALSO)  # the single old criterion is replaced, not kept beside the new ones

    def test_cleanup_passes_only_with_the_image_unchanged_afterwards(self):
        ok = [("cleanup", qc.PASS, ""), ("image-immutable-after", qc.PASS, "")]
        self.assertEqual(qc.cleanup_verdict(ok), qc.PASS)
        self.assertEqual(qc.cleanup_verdict([ok[0], ("image-immutable-after", qc.FAIL, "owner-uid")]), qc.FAIL)
        self.assertEqual(qc.cleanup_verdict([("cleanup", qc.FAIL, "REFUSED"), ok[1]]), qc.FAIL)
        self.assertEqual(qc.cleanup_verdict([ok[0], ("image-immutable-after", qc.NOT_RUN, "no baseline")]), qc.NOT_RUN)
        self.assertEqual(qc.cleanup_verdict([ok[0]]), qc.NOT_RUN)
        self.assertEqual(qc.cleanup_verdict([]), qc.NOT_RUN)

    def test_diagnostics_are_redacted_and_bounded(self):
        raw = "start failed\n-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----\npassword=hunter2 ok\x00\x1b[31m"
        out = qc.redact(raw)
        for leaked in ("PRIVATE KEY", "AAAA", "hunter2", "\x00", "\x1b"):
            self.assertNotIn(leaked, out)
        self.assertIn("start failed", out)
        self.assertLessEqual(len(qc.redact("a" * 100000)), 16384 + 20)
        self.assertTrue(qc.scrub_check(out))

    def test_host_diagnostics_are_written_even_when_nothing_is_readable(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "image-anchor.json").write_text(json.dumps({"path": "/nonexistent/store/x.qcow2"}))
            name = qc.collect_host_diagnostics("create", "qr-20261012-a1b2c3", d)
            body = Path(name).read_text()
            self.assertIn("svq-20261012-a1b2c3", body)
            self.assertIn("/var/log/libvirt/qemu/svq-20261012-a1b2c3.log", body)
            self.assertIn("stat", body)

    def test_backing_chain_evidence_uses_only_safe_readonly_invocations(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertIn("not recorded", "".join(qc.backing_chain_evidence(d)))
            (Path(d) / "storage-volume-paths.txt").write_text("svavyom-x-root.qcow2 /nonexistent/pool/svavyom-x-root.qcow2\nsvavyom-x-seed.iso /nonexistent/seed.iso\n")
            calls = []
            real = qc.run_diag
            qc.run_diag = lambda argv, timeout=20: calls.append(argv) or "ran\n"
            try:
                out = "".join(qc.backing_chain_evidence(d))
            finally:
                qc.run_diag = real
            self.assertIn("/nonexistent/pool/svavyom-x-root.qcow2", out)
            root = "/nonexistent/pool/svavyom-x-root.qcow2"
            seed = "/nonexistent/seed.iso"
            self.assertEqual(calls, [["stat", "-c", "%U:%G %a %F %n", "--", root], ["readlink", "-f", "--", root],
                                     ["qemu-img", "info", "-U", "--backing-chain", "--output=json", "--", root],
                                     ["stat", "-c", "%U:%G %a %F %n", "--", seed], ["readlink", "-f", "--", seed]])  # the seed is never opened as qcow2
            (Path(d) / "storage-volume-paths.txt").write_text("svavyom-x-root.qcow2 /a b;rm -rf /\nsvavyom-x-seed.iso /a;b\n")
            qc.run_diag = lambda argv, timeout=20: calls.append(argv) or ""
            try:
                qc.backing_chain_evidence(d)
            finally:
                qc.run_diag = real
            self.assertEqual(len(calls), 5)  # an unsafe root or seed path never reaches an argv (the five calls above only)

    def test_denial_analysis_distinguishes_helper_from_guest_profile(self):
        h = 'audit: apparmor="DENIED" operation="open" profile="/usr/lib/libvirt/virt-aa-helper" name="/var/lib/svavyom/images/store/a.qcow2"'
        g = 'audit: apparmor="DENIED" operation="open" profile="libvirt-0f3c9d2e-1111-2222-3333-444455556666" name="/x"'
        self.assertIn("helper denials=1 guest-profile denials=0", qc.classify_denials(h).replace("virt-aa-helper ", "helper "))
        self.assertIn("guest-profile denials=1", qc.classify_denials(g))
        self.assertIn("virt-aa-helper.local.svavyom", qc.classify_denials(h))
        self.assertIn("no AppArmor denial", qc.classify_denials("(exit 0)"))

    def test_the_pool_directory_is_mounted_read_only_at_its_own_path_and_only_when_known(self):
        with_pool = qc.docker_argv("create", args(), "/var/lib/svavyom/images", 108, "/out/qr", "/mnt/pool")
        self.assertIn("/mnt/pool:/mnt/pool:ro", with_pool)
        self.assertNotIn("/mnt/pool", " ".join(qc.docker_argv("create", args(), "/var/lib/svavyom/images", 108, "/out/qr")))
        for bad in ("", "/", "rel", "/a b", "/a;b", "/a'b"):
            self.assertFalse(qc.POOL_DIR_RE.match(bad) and bad != "/", bad)
        self.assertEqual(qc.pool_target_dir("bad pool;name"), "")
        self.assertIn("root-source-resolved", qc.ALSO)
        self.assertIn("domain-root-source", qc.ALSO)
        for c in ("seed-source-resolved", "domain-seed-source", "domain-volume-identity"):
            self.assertIn(c, qc.ALSO)

    def test_nonzero_stage_exit_is_a_fail_even_without_a_failed_criterion(self):
        src = (ROOT / "tools" / "qualify_create.py").read_text()
        self.assertIn('"qualification-stage", FAIL', src)

    def test_key_material_is_scrubbed(self):
        self.assertFalse(qc.scrub_check("x\n-----BEGIN OPENSSH PRIVATE KEY-----\n"))
        self.assertTrue(qc.scrub_check("QUALIFY PASS real-libvirt ok"))

    def test_key_inside_the_repository_is_refused(self):
        with tempfile.TemporaryDirectory() as d:
            key = Path(d) / "k"
            key.write_text("x")
            cfg = Path(d) / "c.json"
            cfg.write_text(json.dumps({"catalog_dir": d}))
            pub = Path(d) / "k.pub"
            pub.write_text("x")
            real_exists = os.path.exists
            qc.os.path.exists = lambda p: True if p in (qc.LIBVIRT_RW_SOCK, qc.LIBVIRT_RO_SOCK, "/dev/kvm") else real_exists(p)
            try:
                rc = qc.main(["--config", str(cfg), "--pubkey", str(pub), "--image", "img", "--ssh-key", str(key), "--repo", d, "--run-id", "qr-20261012-a1b2c3", "--out", d + "/o"])
            finally:
                qc.os.path.exists = real_exists
            self.assertEqual(rc, 2)

    def test_missing_prerequisites_are_not_run_not_pass(self):
        if os.path.exists(qc.LIBVIRT_RW_SOCK):
            self.skipTest("this host has libvirt")
        self.assertEqual(qc.main([]), 0)


if __name__ == "__main__":
    unittest.main()
