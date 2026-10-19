"""Tests for tools/check_threats.py (story M0-E01-S02, tier T0, simulated)."""
import copy
import contextlib
import importlib.util
import io
import json
import os
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("check_threats", ROOT / "tools" / "check_threats.py")
ct = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ct)

THREATS = ROOT / "contracts" / "threats"
INTERFACES = ROOT / "contracts" / "interfaces"
FIXTURES = ROOT / "tests" / "fixtures" / "threats" / "negative-mutations.json"
DECISION = "decisions/DR-099-test-acceptance.md"
# What the pinned Go toolchain reports for the committed backend (hermetic stand-in for go_inventory;
# RealGoInventory checks the real thing wherever go is installed, e.g. inside make check).
INVENTORY = {"backend/cmd/api/main_test.go": frozenset({"TestHealthzReturnsScaffoldStatus", "TestUnsupportedRequestsAreRejected",
                                                       "TestUncleanPathIsNeverServedDirectly",
                                                       "TestServerIsLoopbackOnlyWithHeaderTimeout"})}
DECISIONS = {"decisions/DR-098-other.md": "Approved: accept T-API-RX only.", DECISION: "Approved: accept T-API-R (repudiation on the scaffold) until M1-E04-S04."}


def owner_stories():
    register = json.loads((THREATS / "threat-register.json").read_text())
    return {t["owner_story"]: "proposed" for t in register["threats"] if "owner_story" in t}


def load_docs():
    return {name: json.loads((THREATS / ("%s.json" % name)).read_text()) for name in ct.THREAT_FILES}


def run_check(docs, stories=None, root=ROOT, decisions=None, inventory=INVENTORY):
    with tempfile.TemporaryDirectory() as tmp:
        for name, doc in docs.items():
            Path(tmp, "%s.json" % name).write_text(json.dumps(doc))
        return ct.check(root, tmp, INTERFACES, owner_stories() if stories is None else stories,
                        DECISIONS if decisions is None else decisions, inventory)


def threat(docs, tid):
    return next(t for t in docs["threat-register"]["threats"] if t["id"] == tid)


def mitigation(docs, mid):
    return next(m for m in docs["mitigations"]["mitigations"] if m["id"] == mid)


def apply(docs, mutation):
    docs = copy.deepcopy(docs)
    for m in mutation["ops"]:
        op = m["op"]
        if op == "remove_threat":
            docs["threat-register"]["threats"] = [t for t in docs["threat-register"]["threats"] if t["id"] != m["id"]]
        elif op == "remove_mitigation":
            docs["mitigations"]["mitigations"] = [x for x in docs["mitigations"]["mitigations"] if x["id"] != m["id"]]
        elif op == "set_threat":
            threat(docs, m["id"])[m["key"]] = m["value"]
        elif op == "delete_threat_key":
            del threat(docs, m["id"])[m["key"]]
        elif op == "set_mitigation":
            mitigation(docs, m["id"])[m["key"]] = m["value"]
        elif op == "delete_field":
            del docs["data-classes"]["fields"][m["field"]]
        elif op == "set_field":
            docs["data-classes"]["fields"][m["field"]] = m["value"]
        elif op == "set_class_rule":
            docs["data-classes"]["classes"][m["class"]][m["key"]] = m["value"]
        else:
            raise AssertionError("unknown op %s" % op)
    return docs


def link(docs, tid, mid):
    threat(docs, tid)["mitigations"].append(mid)
    mitigation(docs, mid)["threats"].append(tid)


def unlink(docs, tid, mid):
    threat(docs, tid)["mitigations"].remove(mid)
    mitigation(docs, mid)["threats"].remove(tid)


def codes(findings):
    return sorted({f[0] for f in findings})


def removals(node, path=()):
    """Yield every path whose removal (dict key or list element) is a single-removal mutant."""
    if isinstance(node, dict):
        for key, value in node.items():
            yield path + (key,)
            yield from removals(value, path + (key,))
    elif isinstance(node, list):
        for i, value in enumerate(node):
            yield path + (i,)
            yield from removals(value, path + (i,))


def remove(docs, path):
    docs = copy.deepcopy(docs)
    node = docs
    for part in path[:-1]:
        node = node[part]
    del node[path[-1]]
    return docs


class Committed(unittest.TestCase):
    def test_committed_contracts_pass(self):
        self.assertEqual(run_check(load_docs()), [])

    def test_every_boundary_and_stride_category_covered(self):
        register = load_docs()["threat-register"]["threats"]
        inventory = json.loads((INTERFACES / "inventory.json").read_text())
        pairs = {(t["boundary"], t["category"]) for t in register}
        for b in inventory["boundaries"]:
            for cat in ct.STRIDE:
                self.assertIn((b, cat), pairs)

    def test_only_scaffold_threats_are_mitigated(self):
        docs = load_docs()
        mitigated = {t["id"] for t in docs["threat-register"]["threats"] if t["status"] == "mitigated"}
        self.assertEqual(mitigated, {"T-API-S-REMOTE", "T-API-E-ENDPOINTS"})

    def test_idempotency_key_is_credential(self):
        fields = load_docs()["data-classes"]["fields"]
        self.assertEqual(fields["operation.idempotency_key"], "credential")
        self.assertEqual(fields["request.submit_operation.idempotency_key"], "credential")


class NegativeFixtures(unittest.TestCase):
    """AC02: each fixture fails with exactly its expected code."""

    def test_fixture_file_covers_all_ten_codes(self):
        mutations = json.loads(FIXTURES.read_text())["mutations"]
        self.assertEqual({m["expect"] for m in mutations}, set(ct.FINDING_CODES) - {"CONTRACT_INVALID"})
        self.assertEqual(len(mutations), 10)

    def test_each_fixture_fails_with_expected_code(self):
        docs = load_docs()
        for m in json.loads(FIXTURES.read_text())["mutations"]:
            with self.subTest(expect=m["expect"]):
                self.assertEqual(codes(run_check(apply(docs, m))), [m["expect"]])


class SingleRemovals(unittest.TestCase):
    """AC01: removing any entry or reference (any dict key or list element) exits 1 with a typed finding."""

    def test_every_single_removal_is_detected(self):
        docs = load_docs()
        count, survivors = 0, []
        for name in ct.THREAT_FILES:
            for path in removals(docs[name]):
                count += 1
                mutated = dict(docs)
                mutated[name] = remove(docs, (name,) + path)[name]
                findings = run_check(mutated)
                if not findings:
                    survivors.append((name,) + path)
                for code, _, _ in findings:
                    self.assertIn(code, ct.FINDING_CODES)
        self.assertGreater(count, 900)
        self.assertEqual(survivors, [])


class RuntimeEvidence(unittest.TestCase):
    """Review F1: runtime evidence is a real test of implemented code on that boundary."""

    def setUp(self):
        self.docs = load_docs()
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp)

    def write(self, rel, content):
        path = self.tmp / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)

    def test_runtime_test_parsing(self):
        go = "backend/cmd/api/x_test.go"
        self.write("backend/go.mod", "module example.invalid/x\n")
        self.write(go, 'package main\nimport "testing"\nfunc TestReal(t *testing.T) { t.Log("ok") }\n'
                       '// func TestLineComment(t *testing.T) {}\n/*\nfunc TestBlock(t *testing.T) {}\n*/\n'
                       'var s = "/* not a comment"\nfunc TestAfterString(t *testing.T) { t.Log(s) }\n'
                       'var r = `\nfunc TestInRaw(t *testing.T) {}\n`\nfunc helper(t *testing.T) {}\n'
                       'func TestNoT() {}\n')
        self.write("backend/cmd/api/tagged_test.go", "//go:build never\n\npackage main\nfunc TestTagged(t *testing.T) {}\n")
        self.write("backend/cmd/api/legacy_test.go", "// +build ignore\n\npackage main\nfunc TestLegacy(t *testing.T) {}\n")
        self.write("tests/integration_x.py", "import unittest\nclass C(unittest.TestCase):\n    def test_in_class(self): pass\n"
                                             "def test_top(): pass\n# def test_commented(): pass\n")
        self.write("tests/unit_x.py", "def test_unit(): pass\n")
        self.write("tests/integration_bad.py", "def test_x(:\n")
        (self.tmp / "backend/cmd/link").symlink_to(self.tmp / "backend/cmd/api")
        names = {"TestReal", "TestAfterString", "TestLineComment", "TestBlock", "TestInRaw", "helper", "TestNoT"}
        inventory = {go: frozenset(names), "backend/cmd/link/x_test.go": frozenset(names)}
        expect = {"%s::TestReal" % go: go, "%s::TestAfterString" % go: go,
                  "%s::TestLineComment" % go: None, "%s::TestBlock" % go: None, "%s::TestInRaw" % go: None,
                  "%s::helper" % go: None, "%s::TestNoT" % go: None, "%s::TestMissing" % go: None,
                  "backend/cmd/api/tagged_test.go::TestTagged": None, "backend/cmd/api/legacy_test.go::TestLegacy": None,
                  "backend/cmd/link/x_test.go::TestReal": None, "backend/cmd/api/../api/x_test.go::TestReal": None,
                  "./backend/cmd/api/x_test.go::TestReal": None, "backend//cmd/api/x_test.go::TestReal": None,
                  "tests/integration_x.py::test_in_class": "tests/integration_x.py",
                  "tests/integration_x.py::test_top": "tests/integration_x.py",
                  "tests/integration_x.py::test_commented": None, "tests/integration_x.py::C": None,
                  "tests/integration_bad.py::test_x": None, "tests/unit_x.py::test_unit": None,
                  "backend/cmd/api/x_test.go": None, None: None, 7: None}
        for ref, want in expect.items():
            with self.subTest(ref=ref):
                self.assertEqual(ct.runtime_test(self.tmp, ref, inventory), want)

    def test_go_evidence_requires_the_go_inventory(self):
        # Review cycle 4 / sponsor item 11: only tests the Go toolchain itself lists count.
        ref = "backend/cmd/api/main_test.go::TestHealthzReturnsScaffoldStatus"
        self.assertEqual(ct.runtime_test(ROOT, ref, INVENTORY), "backend/cmd/api/main_test.go")
        for inventory in (None, {}, {"backend/cmd/api/main_test.go": frozenset()},
                          {"backend/cmd/api/other_test.go": INVENTORY["backend/cmd/api/main_test.go"]}):
            with self.subTest(inventory=inventory):
                self.assertIsNone(ct.runtime_test(ROOT, ref, inventory))
        self.assertEqual(codes(run_check(self.docs, inventory=None)), ["EVIDENCE_MISSING", "RUNTIME_CLAIM"])

    def test_not_implemented_boundary_cannot_be_mitigated(self):
        # Even a real, passing API test does not mitigate a host-agent threat.
        docs = copy.deepcopy(self.docs)
        t = threat(docs, "T-AGENT-S")
        t["status"] = "mitigated"
        del t["owner_story"]
        mitigation(docs, "M-AGENT-AUTHN")["evidence"] = {"test_id": "backend/cmd/api/main_test.go::TestHealthzReturnsScaffoldStatus"}
        self.assertIn("RUNTIME_CLAIM", codes(run_check(docs)))

    def test_runtime_test_must_be_under_boundary_code_path(self):
        with mock.patch.dict(ct.RUNTIME_PATHS, {"browser-api": ("backend/internal/api/",)}):
            self.assertEqual(codes(run_check(self.docs)), ["RUNTIME_CLAIM"])
        with mock.patch.dict(ct.RUNTIME_PATHS, clear=True):
            self.assertEqual(codes(run_check(self.docs)), ["RUNTIME_CLAIM"])

    def test_mitigated_with_design_evidence_only_is_runtime_claim(self):
        docs = copy.deepcopy(self.docs)
        t = threat(docs, "T-API-S")
        t["status"] = "mitigated"
        del t["owner_story"]
        self.assertEqual(codes(run_check(docs)), ["RUNTIME_CLAIM"])

    def test_contract_checker_test_is_not_runtime_evidence(self):
        docs = copy.deepcopy(self.docs)
        mitigation(docs, "M-API-SURFACE-LOOPBACK")["evidence"] = {"test_id": "tests/unit_check_interfaces.py::test_usage_error"}
        self.assertEqual(codes(run_check(docs)), ["EVIDENCE_MISSING", "RUNTIME_CLAIM"])

    def test_missing_runtime_test(self):
        docs = copy.deepcopy(self.docs)
        mitigation(docs, "M-API-SURFACE-LOOPBACK")["evidence"] = {"test_id": "backend/cmd/api/main_test.go::TestDoesNotExist"}
        self.assertEqual(codes(run_check(docs)), ["EVIDENCE_MISSING", "RUNTIME_CLAIM"])

    def test_every_mitigation_of_a_mitigated_threat_must_be_runtime(self):
        # Review cycle 2 N1a: one runtime test must not launder design-only controls.
        docs = copy.deepcopy(self.docs)
        mitigation(docs, "M-API-SURFACE-CLEANPATH")["evidence"] = {"test_id": "backend/cmd/api/main_test.go::TestGone"}
        self.assertEqual(codes(run_check(docs)), ["EVIDENCE_MISSING", "RUNTIME_CLAIM"])
        for tid in ("T-API-S", "T-API-E-IDOR", "T-API-R", "T-API-T-REPLAY", "T-ROW-API-RESTART"):
            with self.subTest(tid=tid):
                docs = copy.deepcopy(self.docs)
                t = threat(docs, tid)
                t["status"] = "mitigated"
                del t["owner_story"]
                link(docs, tid, "M-API-SURFACE-LOOPBACK")
                self.assertEqual(codes(run_check(docs)), ["RUNTIME_CLAIM"])

    def test_skip_and_empty_bodies(self):
        self.write("backend/p/a_test.go", 'package p\nimport "testing"\nfunc TestRuns(t *testing.T) {\n\tif false {\n\t\tt.Fatal("x")\n\t}\n}\n'
                                         'func TestSkip(t *testing.T) {\n\tt.Skip("later")\n}\n'
                                         'func TestSkipNow(t *testing.T) { t.SkipNow() }\n'
                                         'func TestEmpty(t *testing.T) {\n\t// nothing\n}\n')
        rel = "backend/p/a_test.go"
        inventory = {rel: frozenset({"TestRuns", "TestSkip", "TestSkipNow", "TestEmpty"})}
        self.assertEqual(ct.runtime_test(self.tmp, rel + "::TestRuns", inventory), rel)
        for name in ("TestSkip", "TestSkipNow", "TestEmpty"):
            self.assertIsNone(ct.runtime_test(self.tmp, "%s::%s" % (rel, name), inventory), name)

    def test_unreadable_test_file_is_rejected_not_a_crash(self):
        self.write("backend/p/a_test.go", "package p\n")
        with mock.patch.object(Path, "read_text", side_effect=PermissionError):
            self.assertIsNone(ct.runtime_test(self.tmp, "backend/p/a_test.go::TestX", {"backend/p/a_test.go": {"TestX"}}))


class GoInventory(unittest.TestCase):
    def test_json_stream(self):
        self.assertEqual(ct.json_stream(b' {"a": 1}\n{"b": [2]} '), [{"a": 1}, {"b": [2]}])
        self.assertEqual(ct.json_stream(b""), [])
        with self.assertRaises(ValueError):
            ct.json_stream(b'{"a": ')

    def test_unavailable_go_fails_closed(self):
        with self.assertRaises(ct.GoInventoryError):
            ct.go_inventory(ROOT, go=str(ROOT / "no-such-go"))

    def test_go_failure_and_malformed_output_fail_closed(self):
        fail = subprocess.CompletedProcess([], 1, b"", b"build failed")
        with mock.patch.object(ct.subprocess, "run", return_value=fail), self.assertRaises(ct.GoInventoryError):
            ct.go_inventory(ROOT)
        bad = subprocess.CompletedProcess([], 0, b"{not json", b"")
        with mock.patch.object(ct.subprocess, "run", return_value=bad), self.assertRaises(ct.GoInventoryError):
            ct.go_inventory(ROOT)
        with mock.patch.object(ct.subprocess, "run", side_effect=subprocess.TimeoutExpired("go", 1)), \
                self.assertRaises(ct.GoInventoryError):
            ct.go_inventory(ROOT)

    def test_inventory_mapping(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            for rel, text in (("backend/p/a_test.go", "package p\n"), ("backend/p/x_test.go", "package p_test\n"),
                              ("backend/m/m_test.go", "package m\n// func TestMain(m *testing.M) {}\n"
                                                      "func TestMain(m *testing.M) { m.Run() }\n"),
                              ("backend/real/r_test.go", "package real\n")):
                (root / rel).parent.mkdir(parents=True, exist_ok=True)
                (root / rel).write_text(text)
            (root / "backend/link").symlink_to(root / "backend/real")
            listing = "".join(json.dumps(p) for p in (
                {"Dir": str(root / "backend/p"), "ImportPath": "m/p", "TestGoFiles": ["a_test.go"], "XTestGoFiles": ["x_test.go"]},
                {"Dir": str(root / "backend/m"), "ImportPath": "m/m", "TestGoFiles": ["m_test.go"]},
                {"Dir": str(root / "backend/link"), "ImportPath": "m/link", "TestGoFiles": ["r_test.go"]},
                {"Dir": "/elsewhere", "ImportPath": "m/q", "TestGoFiles": ["q_test.go"]}))
            events = "".join(json.dumps(e) + "\n" for e in (
                {"Action": "output", "Package": "m/p", "Output": "TestA\n"},
                {"Action": "output", "Package": "m/p", "Output": "TestB\n"},
                {"Action": "output", "Package": "m/p", "Output": "BenchmarkC\n"},
                {"Action": "output", "Package": "m/p", "Output": "Testlower\n"},
                {"Action": "output", "Package": "m/p", "Output": "ok  \tm/p\t0.01s\n"},
                {"Action": "pass", "Package": "m/p", "Output": "TestHidden\n"},
                {"Action": "output", "Package": "m/m", "Output": "TestM\n"},
                {"Action": "output", "Package": "m/link", "Output": "TestR\n"}))
            outs = iter([listing.encode(), events.encode()])
            calls = []

            def fake_run(argv, **kw):
                calls.append(argv)
                return subprocess.CompletedProcess([], 0, next(outs), b"")
            with mock.patch.object(ct.subprocess, "run", side_effect=fake_run):
                inventory = ct.go_inventory(root)
        self.assertEqual(inventory, {"backend/p/a_test.go": frozenset({"TestA", "TestB"}),
                                     "backend/p/x_test.go": frozenset({"TestA", "TestB"}),
                                     "backend/m/m_test.go": frozenset()})  # TestMain package: no evidence; symlink skipped
        self.assertEqual(calls[0][1:3], ["list", "-race"])
        self.assertEqual(calls[1][1:4], ["test", "-race", "-count=1"])

    def test_build_failure_reports_build_output(self):
        out = json.dumps({"Action": "build-output", "Output": "p/a_test.go:3: undefined: x\n"}).encode()
        with mock.patch.object(ct.subprocess, "run", return_value=subprocess.CompletedProcess([], 1, out, b"")), \
                self.assertRaisesRegex(ct.GoInventoryError, "undefined: x"):
            ct.go_inventory(ROOT)

    def test_flags_match_the_go_test_gate(self):
        # Review cycle 5 C5-1: the inventory must list exactly what make go-test runs.
        makefile = (ROOT / "Makefile").read_text()
        flags = re.search(r"^GO_TEST_FLAGS := (.*)$", makefile, re.M).group(1).split()
        env = dict(kv.split("=", 1) for kv in re.search(r"^GO_ENV := (.*)$", makefile, re.M).group(1).split())
        self.assertEqual(tuple(flags), ct.GO_TEST_FLAGS)
        self.assertEqual(env, ct.GO_ENV)
        self.assertIn("\tcd backend && $(GO_ENV) go test $(GO_TEST_FLAGS) ./...\n", makefile)
        self.assertTrue(set(ct.GO_BUILD_FLAGS) <= set(ct.GO_TEST_FLAGS))

@unittest.skipUnless(shutil.which("go"), "needs the Go toolchain (present in the pinned dev container / make check)")
class RealGoInventory(unittest.TestCase):
    """Differential check against the real toolchain: every way a test file can be skipped by `go test ./...`."""

    def test_only_tests_go_runs_are_evidence(self):
        body = 'import "testing"\n\nfunc TestX(t *testing.T) {\n\tif false {\n\t\tt.Fatal("x")\n\t}\n}\n'
        files = {
            "go.mod": "module example.invalid/probe\n\ngo 1.25\n\nignore ./ignored\n",
            "ok/ok.go": "package ok\n", "ok/ok_test.go": "package ok\n\n" + body,
            "ok/ext_test.go": "package ok_test\n\n" + body.replace("TestX", "TestExt"),
            "ok/os_plan9_test.go": "package ok\n\n" + body.replace("TestX", "TestPlan9"),
            "ok/dotted_plan9.x_test.go": "package ok\n\n" + body.replace("TestX", "TestDotted"),
            "ok/tag_test.go": "//go:build ignore\n\npackage ok\n\n" + body.replace("TestX", "TestTag"),
            "ok/_hidden_test.go": "package ok\n\n" + body.replace("TestX", "TestHidden"),
            "doc/doc_test.go": "package documentation\n\n" + body,
            "ignored/i.go": "package ignored\n", "ignored/i_test.go": "package ignored\n\n" + body,
            "testdata/t_test.go": "package testdata\n\n" + body,
            "nested/go.mod": "module example.invalid/nested\n\ngo 1.25\n", "nested/n_test.go": "package nested\n\n" + body,
            "norace/n.go": "package norace\n",
            "norace/n_test.go": "//go:build !race\n\npackage norace\n\n" + body,
            "gated/g.go": "package gated\n",
            "gated/g_test.go": 'package gated\n\nimport (\n\t"flag"\n\t"os"\n\t"testing"\n)\n\n'
                               'func TestMain(m *testing.M) {\n\tif flag.Lookup("test.list") != nil && '
                               'flag.Lookup("test.list").Value.String() != "" {\n\t\tos.Exit(m.Run())\n\t}\n'
                               '\tos.Exit(0)\n}\n\n' + body.split("\n\n", 1)[1],
            "silent/s.go": "package silent\n",
            "silent/s_test.go": 'package silent\n\nimport (\n\t"os"\n\t"testing"\n)\n\n'
                                'func TestMain(m *testing.M) { os.Exit(0) }\n\n'
                                'func TestX(t *testing.T) {\n\tif false {\n\t\tt.Fatal("x")\n\t}\n}\n',
        }
        with tempfile.TemporaryDirectory() as tmp:
            for rel, content in files.items():
                path = Path(tmp, "backend", rel)
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(content)
            Path(tmp, "backend/linked").mkdir()
            Path(tmp, "backend/linked/l.go").write_text("package linked\n")
            Path(tmp, "backend/_x").mkdir()
            Path(tmp, "backend/_x/hidden_test.go").write_text("package linked\n\n" + body)
            Path(tmp, "backend/linked/l_test.go").symlink_to(Path(tmp, "backend/_x/hidden_test.go"))
            gated = files["gated/g_test.go"].replace("package gated", "package %s")
            for pkg, main_file in (("plusname", "main+_test.go"), ("symmain", "main_test.go")):
                Path(tmp, "backend", pkg).mkdir()
                Path(tmp, "backend", pkg, "p.go").write_text("package %s\n" % pkg)
                Path(tmp, "backend", pkg, "p_test.go").write_text("package %s\n\n" % pkg + body)
                if pkg == "plusname":
                    Path(tmp, "backend", pkg, main_file).write_text(gated.split("func TestX")[0] % pkg)
                else:
                    Path(tmp, "backend/_tm").mkdir()
                    Path(tmp, "backend/_tm/m_test.go").write_text(gated.split("func TestX")[0] % pkg)
                    Path(tmp, "backend", pkg, main_file).symlink_to(Path(tmp, "backend/_tm/m_test.go"))
            inventory = ct.go_inventory(tmp)
            accepted = {rel for rel in files if rel.endswith("_test.go")
                        for name in ("TestX", "TestExt", "TestPlan9", "TestDotted", "TestTag", "TestHidden")
                        if ct.runtime_test(Path(tmp), "backend/%s::%s" % (rel, name), inventory)}
            self.assertIsNone(ct.runtime_test(Path(tmp), "backend/linked/l_test.go::TestX", inventory))
            self.assertIsNone(ct.runtime_test(Path(tmp), "backend/_x/hidden_test.go::TestX", inventory))
            self.assertNotIn("backend/linked/l_test.go", inventory)
            self.assertEqual(inventory.get("backend/gated/g_test.go"), frozenset())
            self.assertNotIn("backend/norace/n_test.go", inventory)
            # Review cycle 6 C6-1: a TestMain in a file the checker cannot scan still disqualifies the package.
            self.assertEqual(inventory.get("backend/plusname/p_test.go"), frozenset())
            self.assertEqual(inventory.get("backend/symmain/p_test.go"), frozenset())
        self.assertEqual(accepted, {"ok/ok_test.go", "ok/ext_test.go"})

class Rules(unittest.TestCase):
    """Review F2-F6 rules."""

    def setUp(self):
        self.docs = load_docs()

    def test_required_controls_per_kind(self):
        for tid, mid in (("T-API-I", "M-REDACT"), ("T-API-I", "M-API-OWN"), ("T-AGENT-T-REPLAY", "M-AGENT-IDEMP"),
                         ("T-OPM-E-IDOR", "M-OPM-AUTHZ"), ("T-LIBVIRT-E-REMOTE", "M-LIBVIRT-LOCAL"),
                         ("T-PAAS-T-IMAGE", "M-PAAS-DIGEST"), ("T-API-S-REMOTE", "M-API-SURFACE-LOOPBACK")):
            with self.subTest(tid=tid, mid=mid):
                docs = copy.deepcopy(self.docs)
                unlink(docs, tid, mid)
                self.assertIn("MITIGATION_DANGLING", codes(run_check(docs)))

    def test_references_must_be_mirrored(self):
        docs = copy.deepcopy(self.docs)
        mitigation(docs, "M-REDACT")["threats"].append("T-API-S")
        self.assertEqual(codes(run_check(docs)), ["MITIGATION_DANGLING"])
        docs = copy.deepcopy(self.docs)
        threat(docs, "T-API-S")["mitigations"].append("M-REDACT")
        self.assertEqual(codes(run_check(docs)), ["MITIGATION_DANGLING"])

    def test_extra_mirrored_mitigation_is_allowed(self):
        docs = copy.deepcopy(self.docs)
        link(docs, "T-API-S", "M-API-AUDIT")
        self.assertEqual(run_check(docs), [])

    def test_error_category_must_be_returned_by_boundary(self):
        docs = copy.deepcopy(self.docs)
        mitigation(docs, "M-LIBVIRT-AUTHN")["error_category"] = "unauthenticated"
        self.assertEqual(codes(run_check(docs)), ["EVIDENCE_MISSING"])
        docs = copy.deepcopy(self.docs)
        link(docs, "T-PAAS-T-REPLAY", "M-API-IDEMP")  # conflict is not a paas category
        self.assertEqual(codes(run_check(docs)), ["EVIDENCE_MISSING"])

    def test_design_evidence_must_specify_the_control_on_the_boundary(self):
        for mid, field in (("M-API-AUTHN", "inventory.boundaries.api-operation-manager.security.peer_auth"),
                           ("M-API-AUTHN", "inventory.boundaries.browser-api.security.authz_model"),
                           ("M-API-SCHEMA", "request-schemas.categories.typed_libvirt_call"),
                           ("M-API-SCHEMA", "request-schemas.categories.health"),
                           ("M-API-AUTHN", "inventory"), ("M-API-AUTHN", "inventory.boundaries.nope"),
                           ("M-ROW-AGENT-TIMEOUT", "failure-matrix.rows.agent-timeout.retry_responsibility")):
            with self.subTest(mid=mid, field=field):
                docs = copy.deepcopy(self.docs)
                mitigation(docs, mid)["evidence"] = {"contract_field": field}
                self.assertIn("EVIDENCE_MISSING", codes(run_check(docs)))

    def test_false_or_empty_design_evidence(self):
        interfaces = {"x": {"f": False, "e": "", "l": [], "d": {}, "n": None, "ok": "v", "t": True}}
        for key, want in (("f", False), ("e", False), ("l", False), ("d", False), ("n", False), ("ok", True), ("t", True)):
            self.assertEqual(ct.meaningful(ct.resolve_field(interfaces, "x.%s" % key)), want, key)
        self.assertIsNone(ct.resolve_field(interfaces, "x"))
        self.assertIsNone(ct.resolve_field(interfaces, "x.ok.deeper"))
        self.assertIsNone(ct.resolve_field(interfaces, "y.ok"))

    def test_bad_evidence_shapes(self):
        for evidence in ({"fixture": "../etc/passwd"}, {"fixture": "tests/fixtures/../../tools/check_threats.py"},
                         {"fixture": "tools/check_threats.py"}, {"fixture": "tests/fixtures/threats/none.json"},
                         {"test_id": "tools/check_threats.py::main"}, {"test_id": "x", "fixture": "y"}, {},
                         {"url": "https://example.invalid"}, "inventory"):
            with self.subTest(evidence=evidence):
                docs = copy.deepcopy(self.docs)
                mitigation(docs, "M-API-AUTHN")["evidence"] = evidence
                self.assertIn("EVIDENCE_MISSING", codes(run_check(docs)))
        docs = copy.deepcopy(self.docs)
        mitigation(docs, "M-API-AUTHN")["evidence"] = {"fixture": "tests/fixtures/threats/negative-mutations.json"}
        self.assertEqual(run_check(docs), [])
        mitigation(docs, "M-API-AUTHN")["error_category"] = "teapot"
        self.assertEqual(codes(run_check(docs)), ["EVIDENCE_MISSING"])

    def test_kind_category_and_shape(self):
        cases = [("kind", "replay", "T-API-S"), ("kind", "nonsense", "T-API-S"), ("description", "short", "T-API-S"),
                 ("likelihood", "extreme", "T-API-S"), ("boundary", "nope", "T-API-S"), ("extra", 1, "T-API-S"),
                 ("failure_row", "api-restart", "T-API-S"), ("owner_story", "M1-E04-S04", "T-API-S-REMOTE")]
        for key, value, tid in cases:
            with self.subTest(key=key, value=value):
                docs = copy.deepcopy(self.docs)
                threat(docs, tid)[key] = value
                self.assertIn("CONTRACT_INVALID", codes(run_check(docs)))
        for key, value in (("control", "magic"), ("description", ""), ("extra", 1)):
            with self.subTest(mitigation_key=key):
                docs = copy.deepcopy(self.docs)
                mitigation(docs, "M-API-AUTHN")[key] = value
                self.assertIn("CONTRACT_INVALID", codes(run_check(docs)))

    def test_ids_must_be_well_formed_and_unique(self):
        docs = copy.deepcopy(self.docs)
        docs["threat-register"]["threats"].append(copy.deepcopy(threat(docs, "T-API-S")))
        self.assertIn("CONTRACT_INVALID", codes(run_check(docs)))
        docs = copy.deepcopy(self.docs)
        docs["mitigations"]["mitigations"].append(copy.deepcopy(mitigation(docs, "M-REDACT")))
        self.assertIn("CONTRACT_INVALID", codes(run_check(docs)))
        for bad in ("t-api-s", "X-API-S", 5, None):
            with self.subTest(bad=bad):
                docs = copy.deepcopy(self.docs)
                threat(docs, "T-API-S")["id"] = bad
                self.assertIn("CONTRACT_INVALID", codes(run_check(docs)))

    def test_required_kinds_per_boundary(self):
        for kind in ct.REQUIRED_KINDS:
            with self.subTest(kind=kind):
                docs = copy.deepcopy(self.docs)
                for t in docs["threat-register"]["threats"]:
                    if t["boundary"] == "host-agent-libvirt" and t["kind"] == kind:
                        t["kind"] = {"injection": "supply_chain", "replay": "supply_chain", "authz_bypass": "local_privilege"}[kind]
                self.assertIn("THREAT_MISSING", codes(run_check(docs)))

    def test_failure_row_must_exist(self):
        docs = copy.deepcopy(self.docs)
        threat(docs, "T-ROW-AGENT-TIMEOUT")["failure_row"] = "no-such-row"
        self.assertIn("ROW_UNREFERENCED", codes(run_check(docs)))

    def test_planned_owner_must_be_open(self):
        for status in ("verified", "done", None):
            with self.subTest(status=status):
                stories = dict(owner_stories(), **{"M1-E04-S04": status})
                self.assertIn("THREAT_UNOWNED", codes(run_check(self.docs, stories=stories)))
        docs = copy.deepcopy(self.docs)
        threat(docs, "T-API-S")["owner_story"] = "not-a-story"
        self.assertIn("THREAT_UNOWNED", codes(run_check(docs, stories=dict(owner_stories(), **{"not-a-story": "ready"}))))

    def test_accepted_needs_human_date_and_decision(self):
        def accepted(**kw):
            docs = copy.deepcopy(self.docs)
            t = threat(docs, "T-API-R")
            del t["owner_story"]
            t.update(status="accepted", accepted_by="Product Sponsor", accepted_on="2026-10-05", acceptance_ref=DECISION)
            t.update(kw)
            return codes(run_check(docs))
        self.assertEqual(accepted(), [])
        for name in ("Dhanraj", "Talbot Henderson", "Jane Abbott-Smith", "Ai Nakamura", "Haiku Lee", "Bo"):
            self.assertEqual(accepted(accepted_by=name), [], name)
        for kw in ({"accepted_on": "2026-02-30"}, {"accepted_on": "9999-99-99"}, {"accepted_on": "20261005"},
                   {"accepted_by": "Claude Opus"}, {"accepted_by": "GPT assistant bot"}, {"accepted_by": "Opus 5.5 model"},
                   {"accepted_by": "Anthropic Model"}, {"accepted_by": "claude_code"}, {"accepted_by": "ClaudeOpus"},
                   {"accepted_by": "Opus5"}, {"accepted_by": "C1aude"}, {"accepted_by": "A"}, {"accepted_by": "  "},
                   {"accepted_by": 7}, {"acceptance_ref": "decisions/DR-404-missing.md"},
                   {"acceptance_ref": "decisions/DR-098-other.md"}):
            with self.subTest(kw=kw):
                self.assertEqual(accepted(**kw), ["ACCEPTANCE_UNOWNED"])

    def test_data_class_rules(self):
        for cls, key, value in (("secret", "encrypted_at_rest", False), ("credential", "exportable", True),
                                ("secret", "redacted", False)):
            with self.subTest(cls=cls, key=key):
                docs = copy.deepcopy(self.docs)
                docs["data-classes"]["classes"][cls][key] = value
                self.assertEqual(codes(run_check(docs)), ["CREDENTIAL_LOGGABLE"])
        docs = copy.deepcopy(self.docs)
        docs["data-classes"]["classes"]["public"]["loggable"] = "yes"
        self.assertEqual(codes(run_check(docs)), ["CONTRACT_INVALID"])
        docs = copy.deepcopy(self.docs)
        del docs["data-classes"]["classes"]["public"]
        self.assertEqual(codes(run_check(docs)), ["CONTRACT_INVALID"])

    def test_redacted_field_must_be_protected(self):
        docs = copy.deepcopy(self.docs)
        docs["data-classes"]["fields"]["operation.idempotency_key"] = "operational"
        self.assertEqual(codes(run_check(docs)), ["CREDENTIAL_LOGGABLE"])

    def test_field_inventory(self):
        for mutate in (lambda f: f.pop("request.envelope.transport"), lambda f: f.update({"operation.not_a_field": "public"}),
                       lambda f: f.update({"operation.id": "topsecret"})):
            docs = copy.deepcopy(self.docs)
            mutate(docs["data-classes"]["fields"])
            self.assertEqual(codes(run_check(docs)), ["FIELD_UNCLASSIFIED"])

    def test_malformed_and_duplicate_inputs_are_typed(self):
        with tempfile.TemporaryDirectory() as tmp:
            shutil.copytree(THREATS, tmp, dirs_exist_ok=True)
            Path(tmp, "mitigations.json").write_text('{"schema": 1, "schema": 1}')
            self.assertEqual(codes(ct.check(ROOT, tmp, INTERFACES, owner_stories())), ["CONTRACT_INVALID"])
        for mutate in (lambda d: d["threat-register"].update(threats=5), lambda d: d["mitigations"].update(mitigations={}),
                       lambda d: d["data-classes"].update(schema=2), lambda d: d["data-classes"].update(fields=[]),
                       lambda d: d["threat-register"].update(description=" "),
                       lambda d: d["threat-register"]["threats"].append("x"),
                       lambda d: d["mitigations"]["mitigations"].append(None)):
            docs = copy.deepcopy(self.docs)
            mutate(docs)
            self.assertIn("CONTRACT_INVALID", codes(run_check(docs)))


class PinnedChecks(unittest.TestCase):
    """Review cycle 2 N3: pin checks that earlier source mutants showed were untested."""

    def setUp(self):
        self.docs = load_docs()

    def test_orphan_mitigation(self):
        docs = copy.deepcopy(self.docs)
        mitigation(docs, "M-REDACT")["threats"] = []
        self.assertIn("MITIGATION_DANGLING", codes(run_check(docs)))
        docs = copy.deepcopy(self.docs)
        docs["mitigations"]["mitigations"].append(dict(copy.deepcopy(mitigation(docs, "M-REDACT")), id="M-SPARE", threats=[]))
        self.assertEqual(codes(run_check(docs)), ["MITIGATION_DANGLING"])

    def test_row_mitigation_must_cite_its_own_row(self):
        docs = copy.deepcopy(self.docs)
        mitigation(docs, "M-ROW-AGENT-TIMEOUT")["evidence"] = {"contract_field": "failure-matrix.rows.agent-unavailable.idempotency"}
        self.assertIn("ROW_UNREFERENCED", codes(run_check(docs)))

    def test_empty_fixture_is_not_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "tests/fixtures").mkdir(parents=True)
            Path(tmp, "tests/fixtures/empty.json").write_text("")
            Path(tmp, "tests/fixtures/full.json").write_text("{}")
            docs = copy.deepcopy(self.docs)
            mitigation(docs, "M-API-AUTHN")["evidence"] = {"fixture": "tests/fixtures/empty.json"}
            self.assertIn(("EVIDENCE_MISSING", "M-API-AUTHN"), [f[:2] for f in run_check(docs, root=Path(tmp))])
            mitigation(docs, "M-API-AUTHN")["evidence"] = {"fixture": "tests/fixtures/full.json"}
            findings = run_check(docs, root=Path(tmp))
            self.assertNotIn(("EVIDENCE_MISSING", "M-API-AUTHN"), [f[:2] for f in findings])

    def test_python_integration_name_must_be_test_prefixed(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "tests").mkdir()
            Path(tmp, "tests/integration_y.py").write_text("def helper(): pass\ndef test_ok(): pass\n")
            self.assertIsNone(ct.runtime_test(Path(tmp), "tests/integration_y.py::helper"))
            self.assertEqual(ct.runtime_test(Path(tmp), "tests/integration_y.py::test_ok"), "tests/integration_y.py")

    def test_redaction_match_is_nfkc_casefolded(self):
        self.assertEqual(ct.normalise("\uff21PI-\uff2bEY"), "api_key")
        interfaces = {name: json.loads((INTERFACES / ("%s.json" % name)).read_text()) for name in ct.INTERFACE_FILES}
        doc = copy.deepcopy(self.docs["data-classes"])
        interfaces["request-schemas"]["categories"]["get_app"] = ["id", "\uff34OKEN"]
        doc["fields"]["request.get_app.\uff34OKEN"] = "operational"
        self.assertEqual(codes(ct.check_data_classes(interfaces, doc)), ["CREDENTIAL_LOGGABLE"])
        doc["fields"]["request.get_app.\uff34OKEN"] = "secret"
        self.assertEqual(ct.check_data_classes(interfaces, doc), [])

    def test_extra_data_classes_key(self):
        docs = copy.deepcopy(self.docs)
        docs["data-classes"]["extra"] = 1
        self.assertEqual(codes(run_check(docs)), ["CONTRACT_INVALID"])

    def test_duplicate_json_keys_in_every_file(self):
        for name in ct.THREAT_FILES:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as tmp:
                shutil.copytree(THREATS, tmp, dirs_exist_ok=True)
                raw = Path(tmp, "%s.json" % name).read_text()
                Path(tmp, "%s.json" % name).write_text(raw.replace('"schema": 1,', '"schema": 1, "schema": 1,', 1))
                self.assertEqual(codes(ct.check(ROOT, tmp, INTERFACES, owner_stories(), DECISIONS)), ["CONTRACT_INVALID"])

    def test_short_top_level_description(self):
        docs = copy.deepcopy(self.docs)
        docs["mitigations"]["description"] = "x"
        self.assertEqual(codes(run_check(docs)), ["CONTRACT_INVALID"])

class Main(unittest.TestCase):
    def run_main(self, argv, context, inventory_fn=lambda root, go: INVENTORY):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            rc = ct.main(argv, context=context, inventory_fn=inventory_fn)
        return rc, out.getvalue()

    def test_main_ok_and_findings(self):
        ctx = lambda repo: (owner_stories(), {})
        self.assertEqual(self.run_main(["--docs-repo", "x"], ctx), (0, "OK threats: register, mitigations and data classes valid\n"))
        rc, out = self.run_main(["--docs-repo", "x"], lambda repo: ({}, {}))
        self.assertEqual(rc, 1)
        self.assertIn("ERROR THREAT_UNOWNED T-API-S:", out)

    def test_main_fails_closed_without_go(self):
        def broken(root, go):
            raise ct.GoInventoryError("go list exited 1")
        rc, out = self.run_main(["--docs-repo", "x", "--go", "/no/go"], lambda repo: (owner_stories(), {}), broken)
        self.assertEqual(rc, 2)
        self.assertIn("ERROR USAGE GO_INVENTORY_UNAVAILABLE", out)

    def test_docs_context_refuses_unusable_repo(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = io.StringIO()
            with contextlib.redirect_stdout(out), self.assertRaises(SystemExit) as cm:
                ct.docs_context(tmp)
            self.assertEqual(cm.exception.code, 2)
            self.assertIn("ERROR USAGE", out.getvalue())

    @unittest.skipUnless(os.environ.get("DOCS_REPO"), "needs DOCS_REPO (set by make threats)")
    def test_docs_context_reads_pinned_backlog_and_decisions(self):
        stories, decisions = ct.docs_context(os.environ["DOCS_REPO"])
        self.assertIn("M0-E01-S02", stories)
        self.assertTrue(all(ct.DECISION_RE.fullmatch(d) for d in decisions))


if __name__ == "__main__":
    unittest.main()
