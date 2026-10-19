"""Tests for tools/check_frontend.py (story M0-E02-S06 AC02, tier T0, simulated).

Each forbidden construct in a temporary source tree fails with exactly its code; the committed frontend source
passes; a production bundle with gallery markers, external URLs, source maps or no CSP fails.
"""
import importlib.util
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("check_frontend", ROOT / "tools" / "check_frontend.py")
cf = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cf)

BAD = {
    "RAW_HTML": ['<div dangerouslySetInnerHTML={{ __html: x }} />', "el.innerHTML = x;", "document.write(x);"],
    "DYNAMIC_CODE": ["eval(code);", "const f = new Function('a', 'b');", 'setTimeout("alert(1)", 10);'],
    "STRING_HANDLER": ['<button onClick="doIt()">x</button>', '<a onclick="x()">y</a>'],
    "POSITIVE_TABINDEX": ["<div tabIndex={2} />", '<div tabindex="1"></div>'],
    "INLINE_STYLE": ["<p style={{ color: 'red' }}>x</p>", '<p style="color:red">x</p>'],
    "BROWSER_STORAGE": ["localStorage.setItem('k', v);", "sessionStorage.clear();", "indexedDB.open('db');", "document.cookie = 'a=b';"],
    "CONSOLE": ["console.log(response);", "console.error(err);"],
    "ABSOLUTE_URL": ['const u = "https://api.example.com/v1";', "fetchLater('http://x');"],
}
CSP = '<meta http-equiv="Content-Security-Policy" content="default-src \'self\'">'


def tree(files):
    tmp = tempfile.TemporaryDirectory()
    for rel, text in files.items():
        p = Path(tmp.name) / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
    return tmp


class Source(unittest.TestCase):
    def test_committed_frontend_source_passes(self):
        self.assertEqual(cf.check_source(ROOT / "frontend" / "src"), [])

    def test_each_forbidden_construct_fails_with_its_code(self):
        for code, snippets in BAD.items():
            for snippet in snippets:
                with tree({"x/View.tsx": "export const A = 1;\n" + snippet + "\n"}) as d:
                    got = {f[0] for f in cf.check_source(d)}
                    self.assertIn(code, got, snippet)

    def test_comment_markers_inside_strings_do_not_hide_code(self):
        with tree({"a/B.tsx": 'const a = "//"; eval(x);\nconst b = `/*`; console.log(y);\n'}) as d:
            self.assertEqual({f[0] for f in cf.check_source(d)}, {"DYNAMIC_CODE", "CONSOLE"})

    def test_network_only_in_the_client_module(self):
        with tree({"api/client.ts": "fetch(path);\n", "views/V.tsx": "fetch('/api/v1/vms');\n", "views/W.ts": "new WebSocket(u);\n"}) as d:
            got = sorted((f[0], f[1].split(":")[0]) for f in cf.check_source(d))
            self.assertEqual(got, [("DIRECT_FETCH", "views/V.tsx"), ("DIRECT_FETCH", "views/W.ts")])

    def test_comments_and_tests_are_not_scanned(self):
        with tree({"a/B.tsx": "// console.log(x) in a comment\n/* eval(x) */\nexport const ok = 1;\n",
                   "a/B.test.tsx": "console.log('tests may log');\n"}) as d:
            self.assertEqual(cf.check_source(d), [])

    def test_cli_exit_codes(self):
        with tree({"a/B.tsx": "eval(x);\n"}) as d:
            self.assertEqual(cf.main(["--source", d]), 1)
        with tree({"a/B.tsx": "export const ok = 1;\n"}) as d:
            self.assertEqual(cf.main(["--source", d]), 0)
        self.assertEqual(cf.main(["--source", "/nonexistent-dir"]), 2)


class Bundle(unittest.TestCase):
    def good(self, **extra):
        files = {"index.html": "<!doctype html><html><head>%s</head></html>" % CSP,
                 "assets/index.js": 'x="https://react.dev/errors/"+e;y="http://www.w3.org/2000/svg";'}
        files.update(extra)
        return tree(files)

    def test_clean_bundle_passes(self):
        with self.good() as d:
            self.assertEqual(cf.check_bundle(d), [])

    def test_bundle_findings(self):
        cases = {
            "CSP_MISSING": {"index.html": "<html><head></head></html>"},
            "GALLERY_IN_BUNDLE": {"assets/g.js": "const m='__GALLERY_MARKER__';"},
            "EXTERNAL_URL": {"assets/t.js": "fetch('https://telemetry.example.com/beacon')"},
            "SOURCE_MAP": {"assets/index.js.map": "{}"},
        }
        for code, extra in cases.items():
            with self.good(**extra) as d:
                self.assertIn(code, {f[0] for f in cf.check_bundle(d)}, code)
        with self.good(**{"gallery.html": "<html></html>"}) as d:
            self.assertIn("GALLERY_IN_BUNDLE", {f[0] for f in cf.check_bundle(d)})

    def test_lookalike_allowlisted_url_is_still_a_finding(self):
        with self.good(**{"assets/x.js": "u='https://react.dev.evil.example/x'; v='https://react.dev/errorsX';"
                                          "w='http://www.w3.org/2000/svg/../../track'"}) as d:
            urls = [f[2] for f in cf.check_bundle(d) if f[0] == "EXTERNAL_URL"]
            self.assertIn("https://react.dev.evil.example/x", urls)
            self.assertIn("http://www.w3.org/2000/svg/../../track", urls)

    def test_websocket_and_protocol_relative_urls_are_findings(self):
        with self.good(**{"assets/w.js": "new WebSocket('wss://evil.example/s');a='//cdn.example.com/x.js';"}) as d:
            urls = " ".join(f[2] for f in cf.check_bundle(d) if f[0] == "EXTERNAL_URL")
            self.assertIn("wss://evil.example/s", urls)
            self.assertIn("cdn.example.com", urls)


if __name__ == "__main__":
    unittest.main()
