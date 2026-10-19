"""Tests for tools/check_interfaces.py (story M0-E01-S01 DRAFT, tier T0, simulated)."""
import copy
import importlib.util
import json
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CHECKER = ROOT / "tools" / "check_interfaces.py"
CONTRACTS = ROOT / "contracts" / "interfaces"

spec = importlib.util.spec_from_file_location("check_interfaces", CHECKER)
ci = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ci)


def load():
    data, findings = ci.load_contracts(CONTRACTS)
    assert not findings, findings
    return data


def codes(findings):
    return sorted({f[0] for f in findings})


def approved():
    data = copy.deepcopy(load())
    data["inventory"]["auth_design_approved"] = True
    return ci.Contracts(data)


class CommittedContracts(unittest.TestCase):
    def test_committed_contracts_and_fixtures_pass(self):
        proc = subprocess.run([sys.executable, str(CHECKER)], capture_output=True, text=True, timeout=60)
        self.assertEqual((proc.returncode, proc.stdout), (0, "OK interfaces: contracts and fixtures valid\n"))

    def test_every_boundary_resource_and_row_present(self):
        data = load()
        self.assertEqual(set(data["inventory"]["boundaries"]), set(ci.BOUNDARIES))
        self.assertEqual(set(data["resources"]["resources"]), set(ci.RESOURCES))
        self.assertEqual(set(data["failure-matrix"]["rows"]), ci.ROWS)

    def test_health_contract_unchanged(self):
        text = (ROOT / "contracts" / "openapi.yaml").read_text()
        paths = re.findall(r"^  (/\S*):", text, re.M)
        self.assertEqual(paths[0], "/healthz")
        self.assertTrue(all(p.startswith("/api/v1/") for p in paths[1:]))  # every other path is declared and not implemented
        self.assertIn("const: scaffold", text)
        self.assertEqual(text.count("x-implementation-status: implemented"), 21)  # health, 3 session routes, 2 host reads (DR-015), 2 VM reads, 2 image reads, submit + read operation (DR-016), 2 volume + 2 backup reads (DR-020), 2 network reads (DR-021), the operations list (DR-022), the events list and read (DR-024)
        api_go = (ROOT / "backend" / "internal" / "api" / "api.go").read_text()
        self.assertIn('`{"status":"scaffold"}`', api_go)
        main_go = (ROOT / "backend" / "cmd" / "api" / "main.go").read_text()
        self.assertIn('"127.0.0.1:8081"', main_go)
        self.assertEqual(load()["inventory"]["boundaries"]["browser-api"]["implemented_requests"],
                         ["GET /healthz", "GET /api/v1/auth/session", "POST /api/v1/auth/session", "DELETE /api/v1/auth/session",
                          "GET /api/v1/hosts", "GET /api/v1/hosts/{id}", "GET /api/v1/vms", "GET /api/v1/vms/{id}", "GET /api/v1/images", "GET /api/v1/images/{id}", "GET /api/v1/virtual-networks", "GET /api/v1/virtual-networks/{id}", "GET /api/v1/volumes", "GET /api/v1/volumes/{id}", "GET /api/v1/backups", "GET /api/v1/backups/{id}",
                          "GET /api/v1/operations", "POST /api/v1/operations", "GET /api/v1/operations/{id}", "GET /api/v1/events", "GET /api/v1/events/{id}"])

    def test_positive_fixtures_are_health_only(self):
        # Before the auth design is approved, only health may be accepted (review F9).
        for path in sorted((ROOT / "tests/fixtures/interfaces/positive").glob("*.json")):
            self.assertEqual(json.loads(path.read_text())["request"]["category"], "health", path.name)


class ContractMutations(unittest.TestCase):
    """AC01/AC03: removing required fields, unknown names or weakened security are typed findings."""

    def mutate(self, fn):
        data = copy.deepcopy(load())
        fn(data)
        return ci.check_contracts(data)

    def assertFinds(self, fn, code):
        self.assertIn(code, codes(self.mutate(fn)))

    def test_each_boundary_field_required(self):
        fields = ci.BOUNDARY_TEXT_FIELDS + ("security", "permitted_request_categories", "error_categories",
                                            "implementation_status", "implemented_requests")
        for boundary in sorted(ci.BOUNDARIES):
            for field in fields:
                with self.subTest(boundary=boundary, field=field):
                    found = self.mutate(lambda d: d["inventory"]["boundaries"][boundary].pop(field))
                    self.assertTrue(found, (boundary, field))

    def test_empty_text_field_rejected(self):
        found = self.mutate(lambda d: d["inventory"]["boundaries"]["browser-api"].update(authorization=" "))
        self.assertIn(("FIELD_MISSING", "browser-api.authorization", "required non-empty text"), found)

    def test_security_weakening_rejected(self):
        # Review F4: security properties are pinned by the checker, not by prose.
        cases = [
            ("operation-manager-host-agent", "transport_kind", "tcp"),
            ("operation-manager-host-agent", "listener", "tcp_0.0.0.0:9000"),
            ("operation-manager-host-agent", "peer_auth", "none"),
            ("host-agent-libvirt", "accepts_client_xml", True),
            ("browser-api", "authz_model", "allow_all"),
            ("browser-api", "ownership_check", False),
            ("operation-manager-host-agent", "executes_commands", True),
        ]
        for boundary, key, value in cases:
            with self.subTest(boundary=boundary, key=key):
                self.assertFinds(lambda d: d["inventory"]["boundaries"][boundary]["security"].update({key: value}),
                                 "SECURITY_WEAKENED")
        self.assertFinds(lambda d: d["inventory"]["boundaries"]["operation-manager-host-agent"]
                         ["permitted_request_categories"].append("arbitrary_shell"), "SECURITY_WEAKENED")
        self.assertFinds(lambda d: d["inventory"]["boundaries"]["browser-api"]
                         ["permitted_request_categories"].remove("health"), "SECURITY_WEAKENED")

    def test_unknown_and_missing_names(self):
        cases = [
            (lambda d: d["inventory"]["boundaries"].update({"browser-agent": {}}), "BOUNDARY_UNKNOWN"),
            (lambda d: d["inventory"]["boundaries"].pop("host-agent-libvirt"), "BOUNDARY_MISSING"),
            (lambda d: d["resources"]["resources"].update({"Cluster": {}}), "RESOURCE_UNKNOWN"),
            (lambda d: d["resources"]["resources"].pop("Volume"), "RESOURCE_MISSING"),
            (lambda d: d["failure-matrix"]["rows"].update({"disk-full": {}}), "ROW_UNKNOWN"),
            (lambda d: d["failure-matrix"]["rows"].pop("agent-timeout"), "ROW_MISSING"),
        ]
        for fn, code in cases:
            with self.subTest(code=code):
                self.assertFinds(fn, code)

    def test_implementation_claims_rejected(self):
        # Review F5: allowed statuses are hardcoded; scaffold only for browser-api.
        self.assertFinds(lambda d: d["inventory"]["boundaries"]["browser-api"]["implemented_requests"]
                         .append("POST /vms"), "IMPLEMENTATION_CLAIM")
        self.assertFinds(lambda d: d["inventory"]["boundaries"]["host-agent-libvirt"]
                         .update(implementation_status="implemented"), "IMPLEMENTATION_CLAIM")
        self.assertFinds(lambda d: d["inventory"]["boundaries"]["host-agent-libvirt"]
                         .update(implementation_status="scaffold"), "IMPLEMENTATION_CLAIM")
        self.assertFinds(lambda d: d["inventory"]["boundaries"]["operation-manager-host-agent"]
                         .update(implemented_requests=["start_vm"]), "IMPLEMENTATION_CLAIM")

    def test_single_store_writer(self):
        # Review F6 / ADR-003.
        self.assertFinds(lambda d: d["resources"].update(store_writer="host-agent"), "SECURITY_WEAKENED")
        self.assertFinds(lambda d: d["resources"].pop("store_writer"), "SECURITY_WEAKENED")
        self.assertFinds(lambda d: d["failure-matrix"]["rows"]["agent-timeout"]
                         .update(durable_state_owner="host-agent"), "SECURITY_WEAKENED")
        for field, value in (("desired_state_source", "browser"), ("desired_state_source", "host-agent"),
                             ("observed_state_reporter", "browser-js"), ("observed_state_writer", "host-agent")):
            with self.subTest(field=field, value=value):
                self.assertTrue(self.mutate(lambda d: d["resources"]["resources"]["VM"].update({field: value})))

    def test_resource_value_checks(self):
        self.assertFinds(lambda d: d["resources"]["resources"]["VM"].update(ownership_scope="system"), "FIELD_MISSING")
        self.assertFinds(lambda d: d["resources"]["resources"]["VM"].update(generation_tracking="yes"), "FIELD_MISSING")
        for field in ("ownership_scope", "desired_state_source", "observed_state_reporter", "generation_tracking"):
            with self.subTest(field=field):
                self.assertFinds(lambda d: d["resources"]["resources"]["Image"].pop(field), "FIELD_MISSING")

    def test_each_failure_row_field_required(self):
        for row in sorted(ci.ROWS):
            for field in ci.ROW_FIELDS:
                with self.subTest(row=row, field=field):
                    self.assertTrue(self.mutate(lambda d: d["failure-matrix"]["rows"][row].pop(field)))

    def test_recovery_claims_and_story_ids(self):
        for value in (True, "yes", None):
            with self.subTest(value=value):
                self.assertFinds(lambda d: d["failure-matrix"]["rows"]["agent-timeout"]
                                 .update(recovery_implemented=value), "RECOVERY_CLAIM")
        for story in ("M1-E02-S01", "S07", "M0-E02-S07x"):
            with self.subTest(story=story):
                self.assertFinds(lambda d: d["failure-matrix"]["rows"]["api-restart"].update(recovery_story=story),
                                 "FIELD_MISSING")

    def test_inventory_and_error_fields(self):
        # Review F10: fields previously untested.
        # Review R1: the auth gate is pinned closed by the checker.
        self.assertFinds(lambda d: d["inventory"].pop("auth_design_approved"), "SECURITY_WEAKENED")
        self.assertFinds(lambda d: d["inventory"].update(auth_design_approved="no"), "SECURITY_WEAKENED")
        self.assertFinds(lambda d: d["inventory"].update(auth_design_approved=True), "SECURITY_WEAKENED")
        self.assertFinds(lambda d: d["errors"]["categories"]["timeout"].pop("retryable"), "FIELD_MISSING")
        self.assertFinds(lambda d: d["errors"]["categories"]["timeout"].update(http_status="504"), "FIELD_MISSING")
        self.assertFinds(lambda d: d["inventory"]["boundaries"]["browser-api"]["error_categories"].append("teapot"),
                         "ERROR_UNDEFINED")
        self.assertFinds(lambda d: d["failure-matrix"]["rows"]["api-restart"].update(caller_visible_error="oops"),
                         "ERROR_UNDEFINED")

    def test_operation_status_contract(self):
        self.assertFinds(lambda d: d["resources"]["operation_status"].update(
            {k: {"terminal": False, "retryable": True} for k in d["resources"]["operation_status"]}), "FIELD_MISSING")
        self.assertFinds(lambda d: d["resources"]["operation_status"]["failed"].pop("retryable"), "FIELD_MISSING")
        found = self.mutate(lambda d: d["resources"]["operation_persisted_fields"].remove("idempotency_key"))
        self.assertIn(("FIELD_MISSING", "operation_persisted_fields", "missing idempotency_key"), found)

    def test_prohibited_and_redaction_contracts(self):
        self.assertFinds(lambda d: d["prohibited"]["categories"].pop("AGENT_TCP"), "CONTRACT_INVALID")
        self.assertFinds(lambda d: d["prohibited"]["categories"]["ARBITRARY_SHELL"].pop("tokens"), "CONTRACT_INVALID")
        self.assertFinds(lambda d: d["prohibited"]["categories"]["HYPERVISOR_XML"].update(pattern="("),
                         "CONTRACT_INVALID")
        self.assertFinds(lambda d: d["prohibited"]["redaction"].update(key_substrings=[]), "FIELD_MISSING")
        # Review F8: every credential token must be covered by redaction.
        self.assertFinds(lambda d: d["prohibited"]["redaction"].update(key_substrings=["password"]),
                         "SECURITY_WEAKENED")
        self.assertFinds(lambda d: d["request-schemas"]["categories"].pop("health"), "CONTRACT_INVALID")

    def test_malformed_structures_are_typed_findings(self):
        # Review F7: wrong types never crash.
        cases = [
            lambda d: d["inventory"]["boundaries"]["browser-api"].update(error_categories=5),
            lambda d: d["inventory"]["boundaries"]["browser-api"].update(permitted_request_categories=5),
            lambda d: d["resources"]["resources"]["VM"].update(observed_state_reporter=["a"]),
            lambda d: d["resources"].update(operation_persisted_fields=5),
            lambda d: d["prohibited"].update(redaction=[1]),
            lambda d: d["failure-matrix"]["rows"]["api-restart"].update(caller_visible_error=["x"]),
            lambda d: d["inventory"]["boundaries"].update({"browser-api": 7}),
            lambda d: d["resources"].update(operation_status=[1]),
            lambda d: d["request-schemas"]["value_types"].update(id="("),
            lambda d: d["request-schemas"]["categories"].update(get_app=5),
            lambda d: d["request-schemas"]["categories"].update(get_app=[["a"]]),
            lambda d: d["request-schemas"].pop("value_types"),
        ]
        for i, fn in enumerate(cases):
            with self.subTest(case=i):
                found = self.mutate(fn)
                self.assertTrue(found)
                self.assertTrue(all(len(f) == 3 and isinstance(f[0], str) for f in found))

    def test_contract_file_errors(self):
        with tempfile.TemporaryDirectory() as tmp:
            shutil.copytree(CONTRACTS, tmp, dirs_exist_ok=True)
            (Path(tmp) / "errors.json").write_text("{broken")
            (Path(tmp) / "inventory.json").write_text(json.dumps({"schema": 2}))
            (Path(tmp) / "resources.json").write_text("[" * 100000 + "]" * 100000)
            data, findings = ci.load_contracts(tmp)
            self.assertIsNone(data)
            self.assertEqual([f[:2] for f in findings], [("CONTRACT_INVALID", "errors"),
                                                          ("CONTRACT_INVALID", "inventory"),
                                                          ("CONTRACT_INVALID", "resources")])


class RequestClassification(unittest.TestCase):
    """AC02: allowlisted schemas plus normalised defence-in-depth categories; nothing executed."""

    @classmethod
    def setUpClass(cls):
        cls.c = ci.Contracts(load())
        cls.a = approved()

    def classify(self, request, contracts=None):
        return ci.classify_request(contracts or self.c, request)

    def test_valid_requests_accepted_once_auth_approved(self):
        valid = [
            {"boundary": "browser-api", "category": "read_resource", "payload": {"kind": "VM", "id": "vm-01"}},
            {"boundary": "api-operation-manager", "category": "get_operation", "payload": {"id": "op-01"}},
            {"boundary": "paas-controller-workload-vm", "category": "get_app", "payload": {"id": "app-01"}},
            {"boundary": "operation-manager-host-agent", "category": "typed_host_command", "transport": "unix",
             "payload": {"action": "start_vm", "operation_id": "op-1", "attempt": "1"}},
            {"boundary": "host-agent-libvirt", "category": "typed_libvirt_call", "transport": "qemu:///system",
             "payload": {"call": "domain_create", "resource_id": "vm-01"}},
        ]
        for request in valid:
            with self.subTest(category=request["category"]):
                self.assertEqual(self.classify(request, self.a), [])
                self.assertIn("PRIVILEGED_BEFORE_AUTH", self.classify(request))

    def test_agent_transport_allowlist(self):
        # Review F1.
        for transport in ("tcp", "TCP4", "tcp6", "tcp://127.0.0.1:9", "unix+tcp", "grpc", "ws", "vsock", "", None):
            with self.subTest(transport=transport):
                request = {"boundary": "operation-manager-host-agent", "category": "typed_host_command", "payload": {}}
                if transport is not None:
                    request["transport"] = transport
                self.assertIn("AGENT_TCP", self.classify(request, self.a))
        ok = {"boundary": "operation-manager-host-agent", "category": "typed_host_command", "transport": "unix",
              "payload": {"action": "start_vm", "operation_id": "op-1", "attempt": "1"}}
        self.assertEqual(self.classify(ok, self.a), [])
        # Review N3: exact comparison, no normalisation.
        for transport in (" UNIX ", "UNIX", "unix\n", "\uff55\uff4e\uff49\uff58", "u\u200bnix"):
            with self.subTest(transport=transport):
                self.assertIn("AGENT_TCP", self.classify(dict(ok, transport=transport), self.a))

    def test_libvirt_must_be_local(self):
        for transport in ("qemu+tcp://h/system", "qemu+ssh://h/system", "qemu:///session", "test:///default", ""):
            with self.subTest(transport=transport):
                request = {"boundary": "host-agent-libvirt", "category": "typed_libvirt_call", "transport": transport,
                           "payload": {}}
                self.assertIn("REMOTE_HYPERVISOR", self.classify(request, self.a))

    def test_unknown_keys_and_unsafe_values_rejected(self):
        # Review F2/F3: the schema allowlist is the primary control.
        base = {"boundary": "browser-api", "category": "read_resource"}
        for payload in ({"kind": "VM", "id": "vm-01", "extra": "x"}, {"kind": "VM", "id": "a b"},
                        {"kind": "VM", "id": "../etc"}, {"kind": "VM", "id": "$(id)"}, {"kind": "VM", "id": 5},
                        {"kind": "VM", "id": ["x"]}, "kind=VM", ["kind"], {"kind": "VM", "id": "x" * 70}):
            with self.subTest(payload=payload):
                self.assertIn("SCHEMA_VIOLATION", self.classify(dict(base, payload=payload), self.a))
        self.assertIn("SCHEMA_VIOLATION", self.classify(dict(base, payload={"kind": "VM", "id": "v"}, extra=1), self.a))
        self.assertIn("SCHEMA_VIOLATION", self.classify(["not", "a", "dict"]))

    def test_normalised_denylist_variants(self):
        base = {"boundary": "browser-api", "category": "health"}
        for key in ("Command ", "cmd_line", "shell_command", "commandLine", "entrypoint", "args",
                    "Ｃｏｍｍａｎｄ", "c​md", "EXEC"):
            with self.subTest(key=key):
                self.assertIn("ARBITRARY_SHELL", self.classify(dict(base, payload={key: "x"})))
        for key in ("hcloud_token", "aws-access-key-id", "API_KEY", "Bearer", "client_secret"):
            with self.subTest(key=key):
                self.assertIn("PROVIDER_CREDENTIALS", self.classify(dict(base, payload={key: "x"})))
        for value in ("<domain/>", "< domain>", "&lt;domain", "%3Cdisk%3E", "<!DOCTYPE x>", "<?xml?>",
                      "<interface type='network'/>"):
            with self.subTest(value=value):
                self.assertIn("HYPERVISOR_XML", self.classify(dict(base, payload={"n": value})))
        self.assertIn("HYPERVISOR_XML", self.classify(dict(base, payload={"<qemu:commandline>": "x"})))

    def test_deep_requests_fail_closed(self):
        deep = {}
        node = deep
        for _ in range(ci.MAX_DEPTH + 5):
            node["n"] = {}
            node = node["n"]
        self.assertIn("SCHEMA_VIOLATION", self.classify({"boundary": "browser-api", "category": "health",
                                                         "payload": deep}))

    def test_shell_payload_is_not_executed(self):
        with tempfile.TemporaryDirectory() as tmp:
            pwned = Path(tmp) / "pwned"
            fixtures = Path(tmp) / "fx"
            (fixtures / "negative").mkdir(parents=True)
            request = {"boundary": "browser-api", "category": "health",
                       "payload": {"command": "touch %s" % pwned, "name": "$(touch %s)" % pwned}}
            (fixtures / "negative" / "x.json").write_text(json.dumps(
                {"request": request, "expect": ["ARBITRARY_SHELL", "SCHEMA_VIOLATION"]}))
            proc = subprocess.run([sys.executable, str(CHECKER), "--fixtures", str(fixtures)],
                                  capture_output=True, text=True, timeout=60, cwd=tmp)
            self.assertNotIn("negative/x.json", proc.stdout)  # classified exactly as expected
            self.assertFalse(pwned.exists())
            self.assertEqual(sorted(p.name for p in Path(tmp).iterdir()), ["fx"])

    def test_redaction_superset(self):
        value = {"user": "alice", "Password": "p", "nested": [{"api_TOKEN": "t", "ok": 1}],
                 "aws_access_key_id": "a", "api-key": "k", "passwd": "x", "Bearer": "b", "session_cookie": "c"}
        self.assertEqual(ci.redact(self.c, value), {
            "user": "alice", "Password": "[REDACTED]", "nested": [{"api_TOKEN": "[REDACTED]", "ok": 1}],
            "aws_access_key_id": "[REDACTED]", "api-key": "[REDACTED]", "passwd": "[REDACTED]",
            "Bearer": "[REDACTED]", "session_cookie": "[REDACTED]"})


class ReviewCycle2(unittest.TestCase):
    """Second prep review: N1 pinned content, N2 crashes, N4 transport, N5 duplicates, N6/N7 typed values."""

    @classmethod
    def setUpClass(cls):
        cls.a = approved()

    def mutate(self, fn):
        data = copy.deepcopy(load())
        fn(data)
        return ci.check_contracts(data)

    def test_contract_weakening_fails_pins(self):
        cases = [
            lambda d: d["prohibited"]["categories"]["AGENT_TCP"]["allowed_transports"].append("tcp6"),
            lambda d: d["prohibited"]["categories"]["REMOTE_HYPERVISOR"]["allowed_transports"].append("qemu:///session"),
            lambda d: d["request-schemas"]["value_types"].update(id=".*"),
            lambda d: d["request-schemas"]["categories"]["typed_host_command"].update(cmd="id"),
            lambda d: d["request-schemas"]["categories"]["typed_libvirt_call"]["call"].append("virDomainDefineXML"),
            lambda d: d["prohibited"]["categories"]["ARBITRARY_SHELL"]["tokens"].remove("exec"),
            lambda d: d["prohibited"]["categories"]["HYPERVISOR_XML"].update(pattern="<\\s*[a-z]"),
            lambda d: d["prohibited"]["redaction"]["key_substrings"].remove("cookie"),
            lambda d: d["errors"]["categories"]["forbidden"].update(http_status=200),
            lambda d: d["resources"]["operation_status"]["succeeded"].update(retryable=True),
            lambda d: d["resources"]["resources"]["VM"].update(generation_tracking=False),
            lambda d: d["failure-matrix"]["rows"]["api-restart"].update(caller_visible_error="internal"),
        ]
        for i, fn in enumerate(cases):
            with self.subTest(case=i):
                self.assertIn("SECURITY_WEAKENED", codes(self.mutate(fn)))

    def test_recovery_story_pinned(self):
        for story in ("M0-E01-S01", "M0-E02-S09"):
            with self.subTest(story=story):
                self.assertIn("FIELD_MISSING", codes(self.mutate(
                    lambda d: d["failure-matrix"]["rows"]["api-restart"].update(recovery_story=story))))

    def test_unhashable_or_missing_category_is_typed(self):
        for request in ({"boundary": "browser-api", "category": ["health"]}, {"boundary": "browser-api"}, {}):
            with self.subTest(request=request):
                self.assertIn(ci.classify_request(self.a, request), (["SCHEMA_VIOLATION"], ["BOUNDARY_UNKNOWN"]))

    def test_transport_not_allowed_on_other_boundaries(self):
        for transport in ("<domain type='kvm'/>", "$(id)", "tcp://0.0.0.0:80", 123):
            with self.subTest(transport=transport):
                codes_ = ci.classify_request(self.a, {"boundary": "browser-api", "category": "health",
                                                      "transport": transport, "payload": {}})
                self.assertIn("SCHEMA_VIOLATION", codes_)

    def test_duplicate_json_keys_rejected(self):
        dup = '{"request": {"boundary": "browser-api", "category": "health", "category": "health", "payload": {}}, "expect": []}'
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "positive").mkdir()
            (Path(tmp) / "positive" / "a.json").write_text(dup)
            proc = subprocess.run([sys.executable, str(CHECKER), "--fixtures", tmp], capture_output=True, text=True,
                                  timeout=60)
            self.assertIn("FIXTURE_INVALID", proc.stdout)
        with self.assertRaises(ValueError):
            ci.loads('{"a": 1, "a": 2}')

    def test_typed_commands_are_enumerated(self):
        base = {"boundary": "operation-manager-host-agent", "category": "typed_host_command", "transport": "unix"}
        for action in ("exec", "shell", "run_script", "START_VM"):
            with self.subTest(action=action):
                payload = {"action": action, "operation_id": "op-1", "attempt": "1"}
                self.assertIn("SCHEMA_VIOLATION", ci.classify_request(self.a, dict(base, payload=payload)))
        lv = {"boundary": "host-agent-libvirt", "category": "typed_libvirt_call", "transport": "qemu:///system"}
        for call in ("virDomainDefineXML", "virDomainQemuMonitorCommand"):
            with self.subTest(call=call):
                self.assertIn("SCHEMA_VIOLATION", ci.classify_request(
                    self.a, dict(lv, payload={"call": call, "resource_id": "vm-01"})))

    def test_image_digest_type(self):
        base = {"boundary": "paas-controller-workload-vm", "category": "deploy_app"}
        good = dict(base, payload={"app_id": "app-1", "image_digest": "sha256:" + "a" * 64})
        self.assertEqual(ci.classify_request(self.a, good), [])
        for bad in ("sha256:" + "A" * 64, "sha256:abc", "latest", "sha256:" + "a" * 64 + "\n"):
            with self.subTest(bad=bad):
                self.assertIn("SCHEMA_VIOLATION", ci.classify_request(
                    self.a, dict(base, payload={"app_id": "app-1", "image_digest": bad})))

    def test_required_payload_keys(self):
        self.assertIn("SCHEMA_VIOLATION", ci.classify_request(
            self.a, {"boundary": "browser-api", "category": "read_resource", "payload": {"kind": "VM"}}))

    def test_list_resources_optional_keys(self):
        """DR-012 D6: limit and cursor are optional for list_resources only; required <= keys <= allowed."""
        base = {"boundary": "browser-api", "category": "list_resources"}
        only = []  # accepted shape (this class models an approved auth design; the fixture covers the unapproved case)
        for payload in ({"kind": "VM"}, {"kind": "VM", "limit": "200"}, {"kind": "VM", "cursor": "abc_-9"},
                        {"kind": "Event", "limit": "1", "cursor": "A" * 128}):
            with self.subTest(payload=payload):
                self.assertEqual(ci.classify_request(self.a, dict(base, payload=payload)), only)
        bad = ({}, {"limit": "5"}, {"kind": "VM", "limit": "0"}, {"kind": "VM", "limit": "201"}, {"kind": "VM", "limit": "05"},
               {"kind": "VM", "limit": 5}, {"kind": "VM", "cursor": ""}, {"kind": "VM", "cursor": "A" * 129},
               {"kind": "VM", "cursor": "a b"}, {"kind": "VM", "cursor": "a\n"}, {"kind": "Nope"},
               {"kind": "VM", "extra": "x"}, {"kind": "VM", "limit": "5\n"})
        for payload in bad:
            with self.subTest(payload=payload):
                self.assertIn("SCHEMA_VIOLATION", ci.classify_request(self.a, dict(base, payload=payload)))
        # Optionality does not leak to other categories.
        self.assertIn("SCHEMA_VIOLATION", ci.classify_request(
            self.a, {"boundary": "browser-api", "category": "read_resource", "payload": {"kind": "VM"}}))
        self.assertIn("SCHEMA_VIOLATION", ci.classify_request(
            self.a, {"boundary": "browser-api", "category": "submit_operation", "payload": {"type": "start", "kind": "VM", "id": "vm-1"}}))

    def test_wider_redaction(self):
        value = {k: "x" for k in ("pass", "pwd", "db_dsn", "connection_string", "jwt", "kubeconfig", "private_cert")}
        self.assertTrue(all(v == "[REDACTED]" for v in ci.redact(self.a, value).values()))


class StoryScopeCompletion(unittest.TestCase):
    """Approved AC02/AC03 items completed on story/M0-E01-S01."""

    def test_six_failure_rows(self):
        self.assertEqual(set(load()["failure-matrix"]["rows"]), {
            "api-restart", "operation-manager-restart", "agent-timeout", "agent-unavailable", "host-agent-crash",
            "libvirt-unavailable"})
        for row in ("operation-manager-restart", "host-agent-crash"):
            data = copy.deepcopy(load())
            data["failure-matrix"]["rows"].pop(row)
            self.assertIn("ROW_MISSING", codes(ci.check_contracts(data)))

    def test_every_prohibited_code_needs_a_negative_fixture(self):
        with tempfile.TemporaryDirectory() as tmp:
            shutil.copytree(ROOT / "tests/fixtures/interfaces", tmp, dirs_exist_ok=True)
            for path in Path(tmp, "negative").glob("*.json"):
                if "AGENT_TCP" in json.loads(path.read_text())["expect"]:
                    path.unlink()
            proc = subprocess.run([sys.executable, str(CHECKER), "--fixtures", tmp], capture_output=True, text=True,
                                  timeout=60)
            self.assertEqual(proc.returncode, 1)
            self.assertIn("ERROR FIXTURE_MISSING AGENT_TCP", proc.stdout)

    def test_expect_must_be_list_of_codes(self):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "negative").mkdir()
            req = {"boundary": "browser-api", "category": "health", "payload": {"cmd": "x"}}
            (Path(tmp) / "negative" / "a.json").write_text(json.dumps({"request": req, "expect": "AB"}))
            proc = subprocess.run([sys.executable, str(CHECKER), "--fixtures", tmp], capture_output=True, text=True,
                                  timeout=60)
            self.assertIn("FIXTURE_INVALID negative/a.json", proc.stdout)


class FixtureChecks(unittest.TestCase):
    def run_fixtures(self, files):
        with tempfile.TemporaryDirectory() as tmp:
            for rel, content in files.items():
                path = Path(tmp) / rel
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(content)
            proc = subprocess.run([sys.executable, str(CHECKER), "--fixtures", tmp],
                                  capture_output=True, text=True, timeout=60)
            return proc.returncode, proc.stdout

    def test_wrong_expectation_is_mismatch(self):
        req = {"boundary": "browser-api", "category": "health", "payload": {"cmd": "x"}}
        code, out = self.run_fixtures({"negative/a.json": json.dumps({"request": req, "expect": ["HYPERVISOR_XML"]})})
        self.assertEqual(code, 1)
        self.assertIn("ERROR FIXTURE_MISMATCH negative/a.json", out)

    def test_positive_fixture_must_expect_nothing(self):
        req = {"boundary": "browser-api", "category": "health", "payload": {"cmd": "x"}}
        code, out = self.run_fixtures({"positive/a.json": json.dumps({"request": req, "expect": ["ARBITRARY_SHELL"]})})
        self.assertIn("FIXTURE_INVALID", out)

    def test_invalid_oversized_deep_and_missing_fixtures(self):
        self.assertIn("FIXTURE_INVALID", self.run_fixtures({"negative/a.json": "{"})[1])
        big = json.dumps({"request": {"boundary": "browser-api", "category": "health", "payload": {"n": "x" * 70000}},
                          "expect": ["SCHEMA_VIOLATION"]})
        self.assertIn("FIXTURE_INVALID", self.run_fixtures({"negative/a.json": big})[1])
        self.assertIn("FIXTURE_INVALID", self.run_fixtures({"negative/a.json": "[" * 5000 + "]" * 5000})[1])
        self.assertIn("FIXTURE_MISSING", self.run_fixtures({})[1])

    def test_usage_error(self):
        proc = subprocess.run([sys.executable, str(CHECKER), "--contracts", "/nonexistent"],
                              capture_output=True, text=True, timeout=60)
        self.assertEqual(proc.returncode, 2)


if __name__ == "__main__":
    unittest.main()
