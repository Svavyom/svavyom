"""Static checks of the Ubuntu deployment package (packages/ubuntu): the units, sysusers, tmpfiles and the rendered configuration.

No systemd is needed. These tests pin the trust model: four separate non-root identities, the API with no libvirt access, only the
mutation and console units with the libvirt group, every trust anchor read-only to all of them, runtime state separate and writable.
"""
import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.dont_write_bytecode = True
PKG = Path(__file__).resolve().parents[1] / "packages" / "ubuntu"
ANCHORS = ("/etc/svavyom", "/usr/libexec/svavyom", "/var/lib/svavyom/images")
UNITS = ("svavyom-api", "svavyom-agent", "svavyom-mutation", "svavyom-console")


def parse(path):
    """Minimal systemd unit parser: {section: {key: [values...]}}, honouring line continuation and comments."""
    out, section, buf = {}, None, ""
    for raw in path.read_text().splitlines():
        line = raw.rstrip()
        if buf:
            buf += " " + line.strip().rstrip("\\").strip()
            if not line.endswith("\\"):
                k, _, v = buf.partition("=")
                out[section].setdefault(k.strip(), []).append(v.strip())
                buf = ""
            continue
        if not line.strip() or line.lstrip().startswith(("#", ";")):
            continue
        m = re.match(r"^\[(\w+)\]$", line)
        if m:
            section = m.group(1)
            out[section] = {}
            continue
        if line.endswith("\\"):
            buf = line.rstrip("\\").strip()
            continue
        k, _, v = line.partition("=")
        out[section].setdefault(k.strip(), []).append(v.strip())
    return out


def render():
    d = tempfile.mkdtemp()
    out = os.path.join(d, "out")
    env = dict(os.environ, SVAVYOM_TEST_IDS="990 990 991 991 992 992 110 993 993")
    subprocess.run(["sh", str(PKG / "render-units.sh"), out], check=True, env=env, capture_output=True)
    return Path(out)


class Units(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.out = render()
        cls.u = {n: parse(cls.out / "systemd" / (n + ".service")) for n in UNITS}

    def svc(self, n, key):
        return self.u[n]["Service"].get(key, [])

    def test_every_service_is_non_root_with_its_own_identity(self):
        users = [self.svc(n, "User")[0] for n in UNITS]
        self.assertEqual(sorted(users), ["svavyom-api", "svavyom-con", "svavyom-mut", "svavyom-ro"])
        for n in UNITS:
            self.assertNotIn(self.svc(n, "User")[0], ("root", "0"))
            self.assertEqual(self.svc(n, "Group")[0], self.svc(n, "User")[0])

    def test_only_the_mutation_and_console_units_hold_the_libvirt_group(self):
        self.assertEqual(self.svc("svavyom-mutation", "SupplementaryGroups"), ["libvirt"])
        self.assertEqual(self.svc("svavyom-console", "SupplementaryGroups"), ["libvirt"])
        for n in ("svavyom-api", "svavyom-agent"):
            self.assertEqual([g for g in self.svc(n, "SupplementaryGroups") if g], [], n)

    def test_hardening_baseline(self):
        for n in UNITS:
            for k, v in (("NoNewPrivileges", "yes"), ("PrivateTmp", "yes"), ("PrivateDevices", "yes"), ("ProtectSystem", "strict"), ("ProtectHome", "yes"),
                         ("RestrictNamespaces", "yes"), ("LockPersonality", "yes"), ("RestrictSUIDSGID", "yes"), ("ProtectKernelTunables", "yes")):
                self.assertEqual(self.svc(n, k), [v], "%s %s" % (n, k))
            self.assertEqual(self.svc(n, "CapabilityBoundingSet"), [""], n)
            self.assertEqual(self.svc(n, "Restart"), ["on-failure"], n)
            self.assertTrue(self.svc(n, "RestrictAddressFamilies"), n)

    def test_api_host_facts_exception_is_exactly_this_narrow(self):
        # The API reads host facts from /proc and lstats the /dev/kvm node (host summary); the other units keep ProcSubset=pid. See the unit's comment.
        self.assertEqual(self.svc("svavyom-api", "ProcSubset"), [])
        self.assertEqual(self.svc("svavyom-api", "ProtectProc"), ["invisible"])
        self.assertEqual(self.svc("svavyom-api", "BindReadOnlyPaths"), ["-/dev/kvm"])
        for n in ("svavyom-agent", "svavyom-mutation", "svavyom-console"):
            self.assertEqual(self.svc(n, "ProcSubset"), ["pid"], n)
            self.assertEqual(self.svc(n, "BindReadOnlyPaths"), [], n)

    def test_address_families(self):
        self.assertIn("AF_INET", self.svc("svavyom-api", "RestrictAddressFamilies")[0])
        for n in ("svavyom-agent", "svavyom-mutation", "svavyom-console"):
            self.assertEqual(self.svc(n, "RestrictAddressFamilies"), ["AF_UNIX"], n)
            self.assertEqual(self.svc(n, "PrivateNetwork"), ["yes"], n)

    def test_trust_anchors_are_never_writable_and_state_is_separate(self):
        for n in UNITS:
            rw = " ".join(self.svc(n, "ReadWritePaths")).split()
            ro = " ".join(self.svc(n, "ReadOnlyPaths")).split()
            for a in ANCHORS:
                self.assertNotIn(a, rw, "%s must not be able to write %s" % (n, a))
                self.assertIn(a, ro, "%s must list %s read-only" % (n, a))
            for p in rw:
                self.assertFalse(any(p == a or p.startswith(a + "/") for a in ANCHORS), "%s writable %s" % (n, p))
        self.assertEqual(self.svc("svavyom-api", "ReadWritePaths"), ["/var/lib/svavyom/api"])
        self.assertEqual(sorted(" ".join(self.svc("svavyom-mutation", "ReadWritePaths")).split()), ["/run/svavyom/mutation", "/var/lib/svavyom/state"])
        self.assertEqual(self.svc("svavyom-agent", "ReadWritePaths"), ["/run/svavyom/agent"])
        self.assertEqual(self.svc("svavyom-console", "ReadWritePaths"), ["/run/svavyom/console"])  # memory only: nothing of a console reaches disk

    def test_services_cannot_see_each_others_state(self):
        for n, hidden in (("svavyom-api", "/var/lib/svavyom/state"), ("svavyom-agent", "/var/lib/svavyom/api"), ("svavyom-mutation", "/var/lib/svavyom/api"),
                    ("svavyom-console", "/var/lib/svavyom/api"), ("svavyom-console", "/var/lib/svavyom/state")):
            self.assertIn(hidden, " ".join(self.svc(n, "InaccessiblePaths")).split(), n)

    def test_api_has_no_libvirt_socket_and_mutation_is_opt_in(self):
        exec_ = self.svc("svavyom-api", "ExecStart")[0]
        self.assertNotIn("libvirt", exec_)
        self.assertNotIn("--experimental-mutation", exec_)
        self.assertNotIn("--experimental-console", exec_)  # the interactive console is a separate opt-in
        self.assertIn("--console-socket /run/svavyom/console/console.sock", exec_)  # boot output can be read by default
        con = (self.out / "systemd" / "svavyom-api.service.d" / "experimental-console.conf.example").read_text() if (self.out / "systemd" / "svavyom-api.service.d" / "experimental-console.conf.example").exists() else (PKG / "systemd" / "svavyom-api.service.d" / "experimental-console.conf.example").read_text()
        self.assertIn("--experimental-console", con)
        self.assertNotIn("--insecure-dev-single-identity", con)
        drop = (self.out / "systemd" / "svavyom-api.service.d" / "experimental-mutation.conf.example").read_text()
        self.assertIn("--experimental-mutation", drop)
        self.assertNotIn("--insecure-dev-single-identity", exec_ + drop)

    def test_helper_is_not_its_own_service(self):
        self.assertFalse(list((PKG / "systemd").glob("*helper*")))
        self.assertIn("/usr/libexec/svavyom/mutation-helper", self.svc("svavyom-mutation", "ExecStart")[0])

    def test_console_broker_is_its_own_unit_with_a_peer_allowlist_and_no_other_listener(self):
        exec_ = self.svc("svavyom-console", "ExecStart")[0]
        self.assertIn("/usr/libexec/svavyom/console-broker", exec_)
        self.assertIn("--allow-uid 990", exec_)  # only the API identity may connect
        self.assertIn("--socket /run/svavyom/console/console.sock", exec_)
        self.assertNotIn("--listen", exec_)
        self.assertEqual(self.svc("svavyom-console", "PrivateNetwork"), ["yes"])

    def test_no_insecure_flag_anywhere_in_the_deployment(self):
        for f in PKG.rglob("*"):
            if f.is_file():
                self.assertNotIn("insecure-dev-single-identity", f.read_text(), f)

    def test_rendered_provision_config_is_a_valid_trust_declaration(self):
        c = json.loads((self.out / "etc" / "provision.json").read_text())
        self.assertEqual((c["domain_type"], c["libvirt_uri"]), ("kvm", "qemu:///system"))
        t = c["trust"]
        self.assertEqual(t["deploy_uid"], 0)
        self.assertEqual({r["name"] for r in t["runtime_identities"]}, {"api", "agent", "mutation", "console"})
        for r in t["runtime_identities"]:
            self.assertNotEqual(r["uid"], 0)
        mut = [r for r in t["runtime_identities"] if r["name"] == "mutation"][0]
        self.assertIn(110, mut["gids"], "the libvirt group the mutation unit holds must be declared as a runtime group")
        con = [r for r in t["runtime_identities"] if r["name"] == "console"][0]
        self.assertEqual((con["uid"], 110 in con["gids"]), (993, True), "the console broker is a declared runtime identity that holds the libvirt group")
        self.assertTrue(c["catalog_dir"].startswith("/var/lib/svavyom/") and not c["catalog_dir"].startswith("/tmp"))

    def test_tmpfiles_layout_matches_the_documented_table(self):
        rows = {}
        for ln in (PKG / "tmpfiles.d" / "svavyom.conf").read_text().splitlines():
            p = ln.split()
            if len(p) >= 5 and p[0] == "d":
                rows[p[1]] = (p[2], p[3], p[4])
        for anchor in ("/etc/svavyom", "/var/lib/svavyom", "/var/lib/svavyom/images", "/var/lib/svavyom/images/store"):
            self.assertEqual(rows[anchor][1:], ("root", "root"), anchor)
            self.assertEqual(int(rows[anchor][0], 8) & 0o022, 0, anchor)
        self.assertEqual(rows["/var/lib/svavyom/api"], ("0700", "svavyom-api", "svavyom-api"))
        self.assertEqual(rows["/var/lib/svavyom/state"], ("0700", "svavyom-mut", "svavyom-mut"))
        self.assertEqual(rows["/run/svavyom/agent"][1], "svavyom-ro")
        self.assertEqual(rows["/run/svavyom/mutation"][1], "svavyom-mut")
        self.assertEqual(rows["/run/svavyom/console"], ("2750", "svavyom-con", "svavyom-api"))
        for p in rows:
            self.assertFalse(p.startswith("/tmp"), p)

    def test_sysusers_defines_four_nologin_users_and_no_libvirt_membership(self):
        text = (PKG / "sysusers.d" / "svavyom.conf").read_text()
        lines = [ln for ln in text.splitlines() if ln and not ln.startswith("#")]
        self.assertEqual(len(lines), 4)
        for ln in lines:
            self.assertTrue(ln.startswith("u svavyom-") and ln.endswith("/usr/sbin/nologin"), ln)
        self.assertFalse([ln for ln in lines if ln.startswith("m ")])

    def test_apparmor_fragment_is_the_helper_override_and_grants_only_read_of_the_immutable_base_images(self):
        rules = [l.strip() for l in (PKG / "apparmor" / "virt-aa-helper.local.svavyom").read_text().splitlines() if l.strip() and not l.strip().startswith("#")]
        self.assertEqual(rules, ["/var/lib/svavyom/images/store/*.qcow2 r,"])  # one rule: read, on published images only
        cfg = (PKG / "etc" / "provision.json.in").read_text()
        self.assertIn('"catalog_dir": "/var/lib/svavyom/images"', cfg.replace("  ", " ").replace('"catalog_dir":"', '"catalog_dir": "'))
        text = (PKG / "apparmor" / "virt-aa-helper.local.svavyom").read_text()
        for forbidden in ("deny", "audit", "capability", "/**", "/pool", "ix", "px", "ux", "mrw", " w", " a,"):
            self.assertNotIn(forbidden, "\n".join(rules), forbidden)
        self.assertIn("/etc/apparmor.d/local/usr.lib.libvirt.virt-aa-helper", text)  # the supported helper override
        self.assertNotIn("local/abstractions", text.replace("never", ""))  # not the guest-global abstraction
        self.assertIn("Never edit /etc/apparmor.d/usr.lib.libvirt.virt-aa-helper", text)  # package-managed policy is not modified
        self.assertFalse((PKG / "apparmor" / "libvirt-qemu.local.svavyom").exists())
        for f in PKG.rglob("*"):  # nothing installs an override by default
            if f.is_file() and f.suffix in (".sh", ".in", ".spec", ".rules") or f.name in ("rules", "postinst", "control"):
                self.assertNotIn("apparmor.d/local", f.read_text(errors="replace"), str(f))

    def test_render_refuses_to_overwrite_and_to_use_root(self):
        env = dict(os.environ, SVAVYOM_TEST_IDS="990 990 991 991 992 992 110 993 993")
        r = subprocess.run(["sh", str(PKG / "render-units.sh"), str(self.out)], env=env, capture_output=True, text=True)
        self.assertNotEqual(r.returncode, 0)
        d = tempfile.mkdtemp()
        env0 = dict(os.environ, SVAVYOM_TEST_IDS="0 990 991 991 992 992 110 993 993")
        r = subprocess.run(["sh", str(PKG / "render-units.sh"), os.path.join(d, "o")], env=env0, capture_output=True, text=True)
        self.assertNotEqual(r.returncode, 0)


if __name__ == "__main__":
    unittest.main()
