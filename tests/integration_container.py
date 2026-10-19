"""Container-safety integration test (story M0-E02-S02 AC04, tier T1).

Runs on the host (needs Docker Compose; never privileged): `make test-container`.
Checks the rendered compose configuration and the live container.
"""
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
UID, GID = os.getuid(), os.getgid()
ENV = {**os.environ, "HOST_UID": str(UID), "HOST_GID": str(GID)}
COMPOSE = ["docker", "compose", "--env-file", "toolchain/versions.env"]


def compose(*args, env=None):
    return subprocess.run([*COMPOSE, *args], cwd=ROOT, env=env or ENV, capture_output=True, text=True,
                          timeout=600, check=False)


class ContainerSafety(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        proc = compose("config", "--format", "json")
        if proc.returncode != 0:
            raise RuntimeError(proc.stderr)
        services = json.loads(proc.stdout)["services"]
        cls.svc = services["dev"]
        cls.offline = services["dev-offline"]

    def test_host_is_not_root(self):
        self.assertNotEqual(UID, 0, "run as a non-root host user; the container inherits this UID")

    def test_static_configuration(self):
        svc = self.svc
        self.assertEqual(svc.get("user"), "%d:%d" % (UID, GID))
        self.assertEqual(svc.get("cap_drop"), ["ALL"])
        self.assertFalse(svc.get("cap_add"))
        self.assertIn("no-new-privileges:true", svc.get("security_opt", []))
        self.assertFalse(svc.get("privileged", False))
        self.assertTrue(svc.get("read_only"))
        self.assertNotIn(svc.get("network_mode"), ("host",))
        self.assertNotIn(svc.get("pid"), ("host",))
        self.assertNotIn(svc.get("ipc"), ("host",))
        self.assertFalse(svc.get("devices"))
        volumes = svc.get("volumes", [])
        self.assertEqual(len(volumes), 3, volumes)
        for vol in volumes:
            self.assertEqual(vol["type"], "bind")
            self.assertNotIn("docker.sock", vol["source"])
            # Long-syntax binds default to false; config output omits false values.
            self.assertIsNot(vol.get("bind", {}).get("create_host_path"), True, vol)
        checkout = [v for v in volumes if v["target"] == "/workspace/cloud-platform"]
        self.assertEqual(len(checkout), 1)
        self.assertTrue(checkout[0].get("read_only"), checkout[0])
        gitdir = [v for v in volumes if v["target"] == "/workspace/cloud-platform/.git"]
        self.assertEqual(len(gitdir), 1)
        self.assertTrue(gitdir[0].get("read_only"), gitdir[0])
        docs = [v for v in volumes if v["target"] == "/workspace/cloud-product-docs"]
        self.assertEqual(len(docs), 1)
        self.assertTrue(docs[0].get("read_only"), docs[0])

    def test_dev_offline_has_identical_hardening_and_no_network(self):
        # M0-E02-S06 (DR-010 D4 = A): the browser tier runs with the same hardening as dev, and no network.
        diff = {k for k in set(self.svc) | set(self.offline) if self.svc.get(k) != self.offline.get(k)}
        self.assertEqual(diff, {"network_mode", "networks"})
        self.assertEqual(self.offline.get("network_mode"), "none")
        proc = compose("run", "--rm", "--no-deps", "dev-offline", "sh", "-c",
                       "grep -E '^(CapEff|NoNewPrivs):' /proc/self/status; cat /proc/net/route | wc -l; "
                       "python3 -c \"import socket;socket.create_connection(('1.1.1.1',443),3)\" 2>/dev/null && echo NET || echo NONET")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertRegex(proc.stdout, r"CapEff:\s+0000000000000000")
        self.assertRegex(proc.stdout, r"NoNewPrivs:\s+1")
        self.assertIn("NONET", proc.stdout)

    def test_runtime_restrictions(self):
        script = ("id -u; id -g; grep -E '^(CapEff|NoNewPrivs):' /proc/self/status; "
                  "touch /workspace/cloud-product-docs/.write-probe 2>/dev/null && echo DOCS_WRITABLE || echo DOCS_READONLY; "
                  "touch /write-probe 2>/dev/null && echo ROOTFS_WRITABLE || echo ROOTFS_READONLY; "
                  "test -S /var/run/docker.sock && echo SOCKET_PRESENT || echo SOCKET_ABSENT; "
                  "(mkdir -p .git/hooks && touch .git/hooks/post-checkout) 2>/dev/null && echo GITDIR_WRITABLE || echo GITDIR_READONLY; "
                  "(touch compose.yaml Makefile) 2>/dev/null && echo CHECKOUT_WRITABLE || echo CHECKOUT_READONLY")
        proc = compose("run", "--rm", "--no-deps", "dev", "sh", "-c", script)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        lines = proc.stdout.split()
        self.assertEqual(lines[0], str(UID))
        self.assertEqual(lines[1], str(GID))
        out = proc.stdout
        self.assertRegex(out, r"CapEff:\s+0000000000000000")
        self.assertRegex(out, r"NoNewPrivs:\s+1")
        self.assertIn("DOCS_READONLY", out)
        self.assertIn("ROOTFS_READONLY", out)
        self.assertIn("SOCKET_ABSENT", out)
        self.assertIn("GITDIR_READONLY", out)
        self.assertIn("CHECKOUT_READONLY", out)


    def test_missing_docs_repo_is_not_created_on_host(self):
        with tempfile.TemporaryDirectory() as tmp:
            missing = Path(tmp) / "no-such-docs"
            proc = compose("run", "--rm", "--no-deps", "dev", "true",
                           env={**ENV, "DOCS_REPO_HOST": str(missing)})
            self.assertNotEqual(proc.returncode, 0, proc.stdout)
            self.assertFalse(missing.exists(), "bind source was auto-created on the host")


if __name__ == "__main__":
    unittest.main(verbosity=2)
