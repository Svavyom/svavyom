"""Tests for tools/check_evidence.py (story M0-E02-S04 AC01/AC02, tier T0, simulated).

Hermetic: each test builds a throwaway docs repo and platform repo (tests/fixtures/evidence/harness.py);
Go toolchain calls are stubbed (the real Go inventory is exercised by make check / unit_check_threats).
"""
import contextlib
import hashlib
import importlib.util
import io
import json
import os
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location("evidence_harness", ROOT / "tests" / "fixtures" / "evidence" / "harness.py")
h = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(h)
ce, ec = h.ce, h.ec
PY = h.PY_UNIT + "::Demo.test_ok"
GO = h.GO_UNIT + "::TestDemo"
LV = h.GO_LV + "::TestLV"


class Base(unittest.TestCase):
    def setUp(self):
        self.w = h.World()
        self.addCleanup(self.w.close)
        self.w.patch(self)

    def assertOnly(self, code):
        self.assertEqual(self.w.codes(), [code])


class Positive(Base):
    def test_empty_world_passes(self):
        self.assertEqual(self.w.codes(), [])

    def test_valid_records_of_every_result_pass(self):
        self.w.record()
        self.w.record(tests=(GO,))
        self.w.record(tests=(LV,), tier="simulated_libvirt", acs=("AC02",))
        self.w.record(result="FAIL", outcome="fail")
        self.w.record(result="NOT_RUN", log=False)
        self.w.record(result="BLOCKED", log=False)
        self.w.record(gate="go-test", acs=("AC01",))
        findings, (ctx, records) = self.w.run()
        self.assertEqual(findings, [])
        self.assertEqual({s for _, _, s in records}, {"current"})

    def test_report_states_and_no_done_or_hosted_wording(self):
        self.w.record()
        self.w.record(tests=(LV,), tier="simulated_libvirt", acs=("AC02",), result="FAIL", outcome="fail")
        findings, ctx_records = self.w.run()
        self.assertEqual(findings, [])
        text = ce.report(ctx_records)
        self.assertIn("M9-E01-S01-AC01 (unverified, unit) | EVIDENCED_LOCAL", text)
        self.assertIn(PY + " -> ", text)  # story -> AC -> test -> evidence (review M5)
        self.assertIn("M9-E01-S01-AC02 (unverified, integration) | FAILING", text)
        self.assertIn("M9-E01-S01-AC03 (unverified, guest-integration) | MISSING", text)
        self.assertIn("Flag (not a failure)", text)  # M9-E01-S02 is verified without evidence
        for word in ("| done", "hosted", "G0 ", "G1 "):
            self.assertNotIn(word, text)

    def test_human_provenance_is_unverified_without_docs_record(self):
        def human(r):
            r.update(run_by="human", run_by_name="Some Human")
        rec = self.w.record(mutate=human)
        findings, ctx_records = self.w.run()
        self.assertEqual(findings, [])
        self.assertIn("human (unverified)", ce.report(ctx_records))
        def pin(text):
            h.write(self.w.docs, "merges/m.md", text)
            h.commit(self.w.docs)
            h.write(self.w.root, "docs-lock.json", {"schema": 1, "docs_repo": "cloud-product-docs",
                                                     "commit": h.git(self.w.docs, "rev-parse", "HEAD")})
            h.commit(self.w.root)
        pin("REJECTED: %s was not run by a human\n" % rec["id"])  # a mere mention does not confirm (review N5)
        self.assertIn("human (unverified)", ce.report(self.w.run()[1]))
        pin("EVIDENCE-CONFIRMED: %s\n" % rec["id"])
        self.assertNotIn("human (unverified)", ce.report(self.w.run()[1]))

    def test_checker_writes_nothing(self):
        self.w.record()
        def snapshot():
            out = {}
            for p in sorted(self.w.tmp.rglob("*")):
                if p.is_file():
                    out[str(p)] = hashlib.sha256(p.read_bytes()).hexdigest()
            return out
        before = snapshot()
        self.w.run()
        self.assertEqual(snapshot(), before)


class Stale(Base):
    def test_dependency_change_is_stale_not_failure(self):
        self.w.record(commit_it=True)
        h.write(self.w.root, "tests/unit_demo.py", "import unittest\nclass Demo(unittest.TestCase):\n"
                                                   "    def test_ok(self):\n        self.assertTrue(True)\n")
        h.commit(self.w.root, "change test")
        findings, (_, records) = self.w.run()
        self.assertEqual(findings, [])
        self.assertTrue(records[0][2].startswith("stale"))

    def test_unrelated_change_keeps_go_record_current_and_dep_change_stales_it(self):
        self.w.record(tests=(GO,), commit_it=True)
        h.write(self.w.root, "backend/other/x.go", "package other\n")
        h.commit(self.w.root)
        self.assertEqual(self.w.run()[1][1][0][2], "current")
        h.write(self.w.root, "backend/pkg/demo.go", "package pkg\n")
        h.commit(self.w.root)
        self.assertTrue(self.w.run()[1][1][0][2].startswith("stale"))

    def test_ac_text_change_is_stale(self):
        self.w.record(commit_it=True)
        acc = json.loads((self.w.docs / "backlog/acceptance.json").read_text())
        acc[0]["then"] = "changed"
        h.write(self.w.docs, "backlog/acceptance.json", acc)
        sha = h.commit(self.w.docs)
        h.write(self.w.root, "docs-lock.json", {"schema": 1, "docs_repo": "cloud-product-docs", "commit": sha})
        h.commit(self.w.root)
        findings, (_, records) = self.w.run()
        self.assertEqual(findings, [])
        self.assertIn("text changed", records[0][2])

    def test_files_read_but_not_imported_stale_records(self):
        # Review M2: Python records depend on every path; Go records on everything outside backend/ and their deps.
        py = self.w.record(commit_it=True)
        go = self.w.record(tests=(GO,), commit_it=True)
        h.write(self.w.root, "contracts/interfaces/x.json", "{}")
        h.commit(self.w.root, "contract change read at runtime")
        states = {r["id"]: s for _, r, s in self.w.run()[1][1]}
        self.assertTrue(states[py["id"]].startswith("stale"))
        self.assertTrue(states[go["id"]].startswith("stale"))

    def test_go_testdata_and_subdirs_stale(self):
        go = self.w.record(tests=(GO,), commit_it=True)
        h.write(self.w.root, "backend/pkg/testdata/in.txt", "x")
        h.commit(self.w.root)
        self.assertTrue(self.w.run()[1][1][0][2].startswith("stale"))

    def test_uncommitted_dependency_change_stales(self):
        self.w.record(commit_it=True)
        h.write(self.w.root, "docs/notes.md", "uncommitted")
        self.assertTrue(self.w.run()[1][1][0][2].startswith("stale"))

    def test_removed_go_package_is_stale_not_environment_error(self):
        # Review M3: append-only records must never wedge the gate.
        self.w.record(tests=(GO,), commit_it=True)
        h.git(self.w.root, "mv", "backend/pkg", "backend/pkg2")
        classes = json.loads(json.dumps(h.CLASSES))
        classes["rules"][2]["glob"] = "backend/pkg2/*_test.go"
        h.write(self.w.root, ec.CLASSES_PATH, classes)
        h.commit(self.w.root, "move package")
        findings, (_, records) = self.w.run()
        self.assertEqual(findings, [])
        self.assertTrue(records[0][2].startswith("stale"))

    def test_gate_record_is_not_staled_by_evidence_only_commits(self):
        self.w.record(gate="go-test", commit_it=True)
        self.w.record(commit_it=True)
        self.assertEqual([s for _, _, s in self.w.run()[1][1]], ["current", "current"])


class Negative(Base):
    """AC02: one hostile fixture per finding code (and the specific overstatement cases)."""

    def test_overstated_simulated_as_real_kvm_or_hardware(self):
        for tier in ("nested_kvm", "bare_metal", "hardware_matrix", "emulated_vm"):
            with self.subTest(tier=tier):
                w = h.World()
                self.addCleanup(w.close)
                w.patch(self)
                w.record(tests=(LV,), tier=tier, acs=("AC03",))
                self.assertIn("EVIDENCE_OVERSTATED", w.codes())

    def test_overstated_simulated_libvirt_for_guest_or_bare_metal_ac(self):
        for ac in ("AC03", "AC04"):
            with self.subTest(ac=ac):
                w = h.World()
                self.addCleanup(w.close)
                w.patch(self)
                w.record(tests=(LV,), tier="simulated_libvirt", acs=(ac,))
                self.assertEqual(w.codes(), ["EVIDENCE_OVERSTATED"])

    def test_overstated_tier_differs_from_classification(self):
        self.w.record(tests=(PY,), tier="container_integration", acs=("AC02",))
        self.assertOnly("EVIDENCE_OVERSTATED")

    def test_overstated_relabelled_environment_class(self):
        self.w.record(mutate=lambda r: r.update(environment_class="nested", cost_class="T2"))
        self.assertOnly("EVIDENCE_OVERSTATED")

    def test_hosted_claims(self):
        for mutate in (lambda r: r.update(origin="hosted"),
                       lambda r: r["environment"].update(kind="hosted_ci"),
                       lambda r: r.update(ci_run_url="https://ci.example.invalid/run/1")):
            w = h.World()
            self.addCleanup(w.close)
            w.patch(self)
            w.record(mutate=mutate)
            self.assertEqual(w.codes(), ["EVIDENCE_HOSTED_CLAIM"])

    def test_unbound_command_not_running_cited_test(self):
        self.w.record(mutate=lambda r: r.update(command=["true"]))
        self.assertOnly("EVIDENCE_UNBOUND")

    def test_unbound_log_missing_cited_test(self):
        self.w.record(mutate_log=lambda t: "\n".join(l for l in t.splitlines() if "evidence_test" not in l))
        self.assertOnly("EVIDENCE_UNBOUND")

    def test_unbound_pass_with_skipped_test(self):
        self.w.record(outcome="skip")
        self.assertOnly("EVIDENCE_UNBOUND")

    def test_unbound_go_test_behind_unset_tag_or_testmain(self):
        # The Go-authoritative inventory (sponsor item 11) does not list it: unset build tag or TestMain package.
        self.w.inventory["unit"] = {h.GO_UNIT: frozenset()}
        self.w.record(tests=(GO,))
        self.assertOnly("EVIDENCE_UNBOUND")

    def test_spoofed_result_lines_in_tool_output_do_not_count(self):
        # Runner output passthrough is prefixed; a tool printing an evidence line verbatim is not the runner.
        self.w.record(mutate_log=lambda t: t.replace('{"evidence_test"', '| {"evidence_test"'))
        self.assertOnly("EVIDENCE_UNBOUND")

    def test_mismatch_docs_revision(self):
        self.w.record(mutate=lambda r: r["revision"].update(docs="0" * 40))
        self.assertOnly("EVIDENCE_MISMATCH")

    def test_mismatch_unknown_platform_revision(self):
        self.w.record(mutate=lambda r: r["revision"].update(platform="1" * 40))
        self.assertOnly("EVIDENCE_MISMATCH")

    def test_mismatch_unclean_tree(self):
        self.w.record(mutate=lambda r: r["revision"].update(tree_clean=False))
        self.assertIn("EVIDENCE_MISMATCH", self.w.codes())

    def test_mismatch_environment_differs_from_runner_line(self):
        self.w.record(env_line={"os": "Ubuntu", "kernel": "6.0", "arch": "x86_64", "apt_versions_sha256": "b" * 64})
        self.assertOnly("EVIDENCE_MISMATCH")

    def test_tampered_log(self):
        rec = self.w.record()
        (self.w.root / rec["log"]["path"]).write_text("altered\n")
        self.assertOnly("EVIDENCE_TAMPERED")

    def test_missing_log(self):
        rec = self.w.record()
        (self.w.root / rec["log"]["path"]).unlink()
        self.assertOnly("EVIDENCE_TAMPERED")

    def test_status_invalid_cases(self):
        cases = [dict(result="NOT_RUN"),  # NOT_RUN with a log
                 dict(result="BLOCKED", log=False, mutate=lambda r: r.update(blocker="WHATEVER")),
                 dict(result="PASS", mutate=lambda r: r.update(exit_code=1)),
                 dict(result="NOT_RUN", log=False, mutate=lambda r: r.update(exit_code=0))]
        for case in cases:
            w = h.World()
            self.addCleanup(w.close)
            w.patch(self)
            w.record(**case)
            self.assertIn("EVIDENCE_STATUS_INVALID", w.codes(), case)

    def test_not_run_or_blocked_never_evidence(self):
        self.w.record(result="BLOCKED", log=False)
        self.w.record(result="NOT_RUN", log=False)
        findings, ctx_records = self.w.run()
        self.assertEqual(findings, [])
        self.assertNotIn("EVIDENCED_LOCAL", ce.report(ctx_records).split("M9-E01-S01-AC01")[1].split("\n")[0])

    def test_duplicate_record(self):
        rec = self.w.record()
        h.write(self.w.root, "evidence/records/copy.json", json.dumps(rec))
        self.assertOnly("EVIDENCE_DUPLICATE")  # exactly one code (review M6)

    def test_history_rewritten_fail_deleted_later(self):
        rec = self.w.record(result="FAIL", outcome="fail", commit_it=True)
        (self.w.root / ("evidence/records/%s.json" % rec["id"])).unlink()
        (self.w.root / rec["log"]["path"]).unlink()
        h.commit(self.w.root, "drop the failure")
        self.assertOnly("EVIDENCE_HISTORY_REWRITTEN")

    def test_history_rewritten_uncommitted_edit(self):
        rec = self.w.record(commit_it=True)
        p = self.w.root / ("evidence/records/%s.json" % rec["id"])
        p.write_text(p.read_text() + " ")
        self.assertIn("EVIDENCE_HISTORY_REWRITTEN", self.w.codes())

    def test_untraceable(self):
        def cite(ref):
            return lambda r: (r["subject"].update(tests=[ref]), r.update(command=ec.expected_command({"tests": [ref]}, "unit")))
        cases = [(lambda r: r.update(story="M9-E01-S09"), None),
                 (lambda r: r.update(acceptance=["M9-E01-S02-AC01"]), None),
                 (cite("tests/unit_absent.py::Demo.test_ok"), ("tests/unit_demo.py", "tests/unit_absent.py")),
                 (cite("not a ref"), (PY, "not a ref"))]
        for mutate, swap in cases:
            w = h.World()
            self.addCleanup(w.close)
            w.patch(self)
            w.record(mutate=mutate, mutate_log=(lambda t, s=swap: t.replace(*s)) if swap else None)
            self.assertEqual(w.codes(), ["EVIDENCE_UNTRACEABLE"])  # exactly that code (review cycle 2 N-d)

    def test_invalid_records(self):
        rec = self.w.record()
        cases = [lambda: self.w.rewrite(rec, id="EV-0000000000000000"),
                 lambda: h.write(self.w.root, "evidence/records/%s.json" % rec["id"], '{"schema": 1, "schema": 1}'),
                 lambda: h.write(self.w.root, "evidence/records/%s.json" % rec["id"], json.dumps(dict(rec, extra=1))),
                 lambda: h.write(self.w.root, "evidence/records/notes.txt", "x"),
                 lambda: h.write(self.w.root, "evidence/logs/orphan.log", "x")]
        for make in cases:
            with self.subTest(make=make):
                h.write(self.w.root, "evidence/records/%s.json" % rec["id"], json.dumps(rec))
                for extra in ("evidence/records/notes.txt", "evidence/logs/orphan.log"):
                    (self.w.root / extra).unlink(missing_ok=True)
                make()
                self.assertIn("EVIDENCE_INVALID", self.w.codes())

    def test_test_unclassified_and_not_discovered(self):
        h.write(self.w.root, "backend/new/x_test.go", "package new\n")
        self.assertIn("TEST_UNCLASSIFIED", self.w.codes())
        (self.w.root / "backend/new/x_test.go").unlink()
        h.write(self.w.root, "scripts/check_test.sh", "#!/bin/sh\n")
        self.assertIn("TEST_UNCLASSIFIED", self.w.codes())

    def test_test_ambiguous(self):
        classes = json.loads(json.dumps(h.CLASSES))
        classes["rules"].append({"id": "overlap", "glob": "tests/*.py", "tier": "unit", "kinds": ["functional"]})
        h.write(self.w.root, ec.CLASSES_PATH, classes)
        self.assertIn("TEST_AMBIGUOUS", self.w.codes())

    def test_contract_invalid_rule_above_t1_or_unmatched(self):
        for rule in ({"id": "kvm", "glob": "tests/unit_*.py", "tier": "nested_kvm", "kinds": ["functional"]},
                     {"id": "nothing", "glob": "nowhere/*_test.go", "tier": "unit", "kinds": ["functional"]},
                     {"id": "badkind", "glob": "x", "tier": "unit", "kinds": ["magic"]}):
            with self.subTest(rule=rule["id"]):
                classes = json.loads(json.dumps(h.CLASSES))
                classes["rules"].append(rule)
                h.write(self.w.root, ec.CLASSES_PATH, classes)
                self.assertIn("CONTRACT_INVALID", self.w.codes())

    def test_contract_invalid_taxonomy_accepting_hosted(self):
        tax = json.loads(json.dumps(self.w.taxonomy))
        tax["origins_accepted_in_m0"] = ["local", "hosted"]
        w = h.World(taxonomy=tax)
        self.addCleanup(w.close)
        w.patch(self)
        self.assertEqual(w.codes(), ["CONTRACT_INVALID"])

    def test_history_rewritten_fail_dropped_by_merge(self):
        # Review M1: a FAIL record added on a side branch and dropped by the merge (strategy ours / git rm in merge).
        for strategy in ("ours", "rm"):
            with self.subTest(strategy=strategy):
                w = h.World()
                self.addCleanup(w.close)
                w.patch(self)
                h.git(w.root, "checkout", "-q", "-b", "side")
                rec = w.record(result="FAIL", outcome="fail", commit_it=True)
                h.git(w.root, "checkout", "-q", "main")
                if strategy == "ours":
                    h.git(w.root, "merge", "-q", "-s", "ours", "--no-edit", "side")
                else:
                    h.git(w.root, "merge", "-q", "--no-ff", "--no-commit", "side")
                    h.git(w.root, "rm", "-q", "-f", "evidence/records/%s.json" % rec["id"], rec["log"]["path"])
                    h.git(w.root, "commit", "-q", "-m", "merge dropping evidence")
                self.assertEqual(w.codes(), ["EVIDENCE_HISTORY_REWRITTEN"])

    def test_invalid_id_types_never_crash(self):
        for bad in ([], {}, 5, None):
            with self.subTest(bad=bad):
                h.write(self.w.root, "evidence/records/EV-x.json", json.dumps({"id": bad}))
                self.assertEqual(self.w.codes(), ["EVIDENCE_INVALID"])

    def test_untraceable_cited_file_does_not_define_test(self):
        # Review N4: the cited file itself must define the cited test.
        ref = h.PY_UNIT + "::Demo.test_absent"
        self.w.record(mutate=lambda r: (r["subject"].update(tests=[ref]),
                                        r.update(command=ec.expected_command({"tests": [ref]}, "unit"))),
                      mutate_log=lambda t: t.replace("Demo.test_ok", "Demo.test_absent"))
        self.assertEqual(self.w.codes(), ["EVIDENCE_UNTRACEABLE"])

    def test_unclassified_test_hidden_under_fixtures(self):
        # Review cycle 2 N-c: unittest discovery would run tests/fixtures/unit_hidden.py if fixtures is a package.
        h.write(self.w.root, "tests/fixtures/__init__.py", "")
        h.write(self.w.root, "tests/fixtures/unit_hidden.py", "")
        self.assertEqual(self.w.codes(), ["TEST_UNCLASSIFIED"])

    def test_unclassified_nested_python_tests(self):
        # Review N3: tests/sub/unit_x.py is runnable by unittest discovery but not discovered here.
        h.write(self.w.root, "tests/sub/__init__.py", "")
        h.write(self.w.root, "tests/sub/unit_x.py", "")
        self.assertEqual(self.w.codes(), ["TEST_UNCLASSIFIED"])

    def test_contract_invalid_record_schema(self):
        h.write(self.w.root, "contracts/evidence/record.schema.json", "{}")
        self.assertEqual(self.w.codes(), ["CONTRACT_INVALID"])

    def test_every_finding_code_has_a_negative_test(self):
        names = " ".join(n for n in dir(self) if n.startswith("test_"))
        expected = {"EVIDENCE_INVALID": "invalid", "EVIDENCE_UNTRACEABLE": "untraceable", "EVIDENCE_UNBOUND": "unbound",
                    "EVIDENCE_OVERSTATED": "overstated", "EVIDENCE_HOSTED_CLAIM": "hosted", "EVIDENCE_MISMATCH": "mismatch",
                    "EVIDENCE_TAMPERED": "tampered", "EVIDENCE_STATUS_INVALID": "status_invalid",
                    "EVIDENCE_DUPLICATE": "duplicate", "EVIDENCE_HISTORY_REWRITTEN": "history_rewritten",
                    "TEST_UNCLASSIFIED": "unclassified", "TEST_AMBIGUOUS": "ambiguous", "CONTRACT_INVALID": "contract_invalid"}
        self.assertEqual(set(expected), set(ce.FINDING_CODES))
        for code, stem in expected.items():
            self.assertIn(stem, names, code)


class Units(unittest.TestCase):
    def test_record_id_excludes_id_and_log_path(self):
        rec = {"a": 1, "log": {"path": "evidence/logs/x.log", "sha256": "0" * 64}}
        rid = ec.record_id(rec)
        self.assertEqual(ec.record_id(dict(rec, id="EV-x", log={"path": "other", "sha256": "0" * 64})), rid)
        self.assertNotEqual(ec.record_id(dict(rec, a=2)), rid)

    def test_refs_and_expected_command(self):
        self.assertEqual(ec.test_ref(GO), ("go", h.GO_UNIT, "TestDemo"))
        self.assertEqual(ec.test_ref(PY), ("py", h.PY_UNIT, "Demo.test_ok"))
        for bad in ("backend/x.go::TestA", "backend/x_test.go::helper", "tests/x.py::test_a", "../x_test.go::TestA", 5):
            self.assertIsNone(ec.test_ref(bad), bad)
        self.assertEqual(ec.expected_command({"tests": [PY, PY]}, "unit"), ec.RUNNER + ["--tier", "unit", "--", PY])
        self.assertEqual(ec.expected_command({"gate": "go-test"}, "unit"), ec.RUNNER + ["--gate", "go-test"])

    def test_glob_and_classify(self):
        self.assertTrue(ec.glob_regex("backend/**/*_test.go").fullmatch("backend/a/b/c_test.go"))
        self.assertTrue(ec.glob_regex("backend/**/*_test.go").fullmatch("backend/c_test.go"))
        self.assertFalse(ec.glob_regex("tests/unit_*.py").fullmatch("tests/sub/unit_x.py"))
        rules = {"rules": [{"id": "a", "glob": "x/**", "exclude": ["x/y/*"], "tier": "unit", "kinds": ["functional"]}]}
        self.assertEqual(len(ec.classify(rules, "x/z")), 1)
        self.assertEqual(ec.classify(rules, "x/y/z"), [])

    def test_parse_runner_log_failure_wins(self):
        text = "\n".join(json.dumps(x) for x in ({"evidence_test": "a", "outcome": "fail"},
                                                 {"evidence_test": "a", "outcome": "pass"}, {"evidence_exit": 1}))
        self.assertEqual(ec.parse_runner_log(text)[1:], ({"a": "fail"}, 1))

    def test_committed_classification_covers_s03_files_as_specified(self):
        classes = json.loads((ROOT / ec.CLASSES_PATH).read_text())
        expect = {"backend/internal/hypervisor/fake/fake_test.go": "unit",
                  "backend/internal/hypervisor/contract_alignment_test.go": "unit",
                  "backend/internal/hypervisor/libvirttest/libvirttest_test.go": "simulated_libvirt",
                  "backend/cmd/api/main_test.go": "unit", "tests/unit_check_threats.py": "unit",
                  "tests/integration_gates.py": "container_integration"}
        for path, tier in expect.items():
            hits = ec.classify(classes, path)
            self.assertEqual([r["tier"] for r in hits], [tier], path)

    def test_fixture_taxonomy_matches_docs_repo(self):
        docs = os.environ.get("DOCS_REPO")
        if not docs:
            self.skipTest("needs DOCS_REPO (set by make check)")
        sha = json.loads((ROOT / "docs-lock.json").read_text())["commit"]
        linkage = ec.load_linkage()
        raw = linkage.git(docs, "cat-file", "blob", "%s:%s" % (sha, ec.TAXONOMY_PATH))
        self.assertEqual(json.loads(raw), json.loads((ROOT / "tests/fixtures/evidence/taxonomy.json").read_text()))


@unittest.skipUnless(__import__("shutil").which("go"), "needs the Go toolchain (present in make check)")
class RealGoDeps(unittest.TestCase):
    """Review cycle 2 F1: a cited package that no longer builds test files is STALE, never an environment error."""

    def test_package_without_go_files_or_excluded_by_tags(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            files = {"backend/go.mod": "module example.invalid/probe\n\ngo 1.25\n",
                     "backend/ok/ok.go": "package ok\n", "backend/ok/ok_test.go": "package ok\n\nimport \"testing\"\n\n"
                     "func TestX(t *testing.T) { t.Log(1) }\n",
                     "backend/gone/testdata/keep.txt": "x",
                     "backend/tagged/t_test.go": "//go:build never\n\npackage tagged\n"}
            for rel, text in files.items():
                (root / rel).parent.mkdir(parents=True, exist_ok=True)
                (root / rel).write_text(text)
            self.assertEqual(ce.go_dep_dirs(root, "unit", {"backend/ok"}), {"backend/ok"})
            self.assertIsNone(ce.go_dep_dirs(root, "unit", {"backend/gone"}))
            self.assertIsNone(ce.go_dep_dirs(root, "unit", {"backend/tagged"}))


class Main(Base):
    def test_cli_exit_codes(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            rc = ce.main(["--docs-repo", str(self.w.tmp / "missing")])
        self.assertEqual(rc, 2)
        self.assertIn("ERROR USAGE", out.getvalue())


if __name__ == "__main__":
    unittest.main()
