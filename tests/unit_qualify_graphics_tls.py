"""The qualification clients speak to the installation's own API on loopback over http or https (finding N7 of the 2026-11-14 plan: clean hosts serve HTTPS with a
self-signed certificate). https is reached without verifying the certificate, which is only sound on loopback, so every other address is refused before anything is sent."""
import importlib.util
import ssl
import sys
import unittest
import urllib.request
from pathlib import Path
from types import SimpleNamespace

sys.dont_write_bytecode = True
TOOLS = Path(__file__).resolve().parent.parent / "tools"


def load(name):
    spec = importlib.util.spec_from_file_location(name, TOOLS / (name + ".py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


g = load("qualify_graphics")
media = load("qualify_media_service")
win = load("qualify_windows_service")


class LoopbackBase(unittest.TestCase):
    def test_http_and_https_on_loopback_are_accepted(self):
        self.assertEqual(g.loopback_base("http://127.0.0.1:8443"), ("http", "127.0.0.1", 8443))
        self.assertEqual(g.loopback_base("https://127.0.0.1:8443"), ("https", "127.0.0.1", 8443))
        self.assertEqual(g.loopback_base("https://localhost:9443"), ("https", "localhost", 9443))

    def test_everything_else_is_refused(self):
        for bad in ("https://203.0.113.5:8443", "https://example.org:8443", "http://127.0.0.1", "ftp://127.0.0.1:8443", "https://127.0.0.1:8443/x", "https://127.0.0.1.evil.org:8443", "", None):
            with self.assertRaises(ValueError, msg=str(bad)):
                g.loopback_base(bad)


class Clients(unittest.TestCase):
    def test_an_https_api_carries_an_https_handler_that_does_not_verify_and_an_http_one_does_not(self):
        s = g.Api("https://127.0.0.1:8443", __file__, "u")
        https = [h for h in s.op.handlers if isinstance(h, urllib.request.HTTPSHandler)]
        self.assertTrue(https)
        ctx = https[0]._context
        self.assertEqual((ctx.verify_mode, ctx.check_hostname), (ssl.CERT_NONE, False))
        p = g.Api("http://127.0.0.1:8443", __file__, "u")
        self.assertEqual((p.scheme, p.port), ("http", 8443))

    def test_an_api_on_another_address_is_refused_before_a_request(self):
        with self.assertRaises(ValueError):
            g.Api("https://203.0.113.5:8443", __file__, "u")

    def test_the_media_and_windows_service_runs_accept_https_loopback_and_refuse_a_remote_address(self):
        for mod, kw in ((media, dict(boot_image="alpine-virt", data_image="virtio-win")), (win, dict(image="windowsserver2019-iso", driver_image="virtio-win"))):
            ok = SimpleNamespace(run_id="qr-20261031-a1b2c3", base="https://127.0.0.1:8443", password_file=__file__, user="certify", **kw)
            self.assertFalse([p for p in mod.problems(ok) if "--base" in p], mod.__name__)
            remote = SimpleNamespace(**dict(vars(ok), base="https://203.0.113.5:8443"))
            self.assertTrue([p for p in mod.problems(remote) if "--base" in p], mod.__name__)


if __name__ == "__main__":
    unittest.main()
