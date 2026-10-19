"""Unit tests for tools/check_openapi.py (M0-E01-S04 AC01 positive, AC02 negative mutations).

Every mutation of the schema or the contracts must fail with exactly its section-2 finding code. The checker itself
must write nothing.
"""
import copy
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location("check_openapi", ROOT / "tools" / "check_openapi.py")
co = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(co)

SPEC = co.load_yaml((ROOT / co.SPEC_FILE).read_bytes())
CONTRACTS = co.load_contracts(ROOT)
VM_LIST = "/api/v1/vms"


def codes(spec, contracts=None):
    return sorted({f[0] for f in co.check_spec(spec, contracts or CONTRACTS)})


def mutated(fn, target="spec"):
    spec, contracts = copy.deepcopy(SPEC), copy.deepcopy(CONTRACTS)
    fn(spec if target == "spec" else contracts)
    return codes(spec, contracts)


def schema(spec, name):
    return spec["components"]["schemas"][name]


class Positive(unittest.TestCase):
    def test_real_spec_has_no_findings(self):
        self.assertEqual(co.check_spec(SPEC, CONTRACTS), [])

    def test_every_path_maps_to_one_permitted_category(self):
        inv = CONTRACTS["inventory"]["boundaries"]["browser-api"]
        seen = set()
        for path, item in SPEC["paths"].items():
            for method, op in item.items():
                seen.add((method, path))
                self.assertIn(op["x-request-category"], inv["permitted_request_categories"])
        self.assertEqual(seen, set(co.PATHS))

    def test_only_health_is_implemented_and_error_responses_are_boundary_categories(self):
        inv = CONTRACTS["inventory"]["boundaries"]["browser-api"]
        for path, item in SPEC["paths"].items():
            for method, op in item.items():
                self.assertEqual(op["x-implementation-status"] == "implemented", "%s %s" % (method.upper(), path) in inv["implemented_requests"])
                for status, ref in op["responses"].items():
                    if status[0] != "2":
                        name = ref["$ref"].rsplit("/", 1)[1]
                        self.assertIn(SPEC["components"]["responses"][name]["x-error-category"], inv["error_categories"])

    def test_error_branches_match_errors_contract(self):
        branches = {b["properties"]["category"]["const"]: b for b in schema(SPEC, "Error")["oneOf"]}
        self.assertEqual(set(branches), set(CONTRACTS["errors"]["categories"]))
        for name, spec in CONTRACTS["errors"]["categories"].items():
            self.assertIs(branches[name]["properties"]["retryable"]["const"], spec["retryable"])
            self.assertEqual(branches[name]["x-http-status"], spec["http_status"])

    def test_no_free_text_message_and_no_secret_in_responses(self):
        self.assertNotIn("message", schema(SPEC, "Error")["properties"])
        self.assertNotIn("idempotency_key", schema(SPEC, "Operation")["properties"])
        for name in co.reachable_from_responses(SPEC):
            for where, node in co.walk_properties(schema(SPEC, name), name):
                self.assertNotIn(node["x-data-class"], co.SECRET_CLASSES, where)

    def test_digest_is_stable_and_covers_response_schemas_only(self):
        d = co.response_schema_digest(SPEC)
        spec = copy.deepcopy(SPEC)
        spec["paths"]["/healthz"]["get"]["operationId"] = "other"
        schema(spec, "SubmitOperationRequest")["properties"]["id"]["maxLength"] = 10  # request schema, not a response
        self.assertEqual(co.response_schema_digest(spec), d)
        schema(spec, "VM")["properties"]["name"]["maxLength"] = 10
        self.assertNotEqual(co.response_schema_digest(spec), d)


class Mutations(unittest.TestCase):
    """Each case: (name, mutation, expected exact code set)."""

    def check(self, cases, target="spec"):
        for name, fn, want in cases:
            with self.subTest(name):
                self.assertEqual(mutated(fn, target), sorted(want))

    def test_schema_structure(self):
        def unknown_keyword(s):
            schema(s, "Host")["properties"]["name"]["pattern2"] = "x"

        def add_message(s):
            schema(s, "Error")["properties"]["message"] = {"type": "string", "maxLength": 10, "x-data-class": "operational"}

        def bad_version(s):
            s["openapi"] = "3.0.3"

        def callbacks(s):
            s["paths"]["/healthz"]["get"]["callbacks"] = {}

        def external_ref(s):
            schema(s, "Host")["properties"]["name"] = {"$ref": "https://example.invalid/x.json"}

        def anyof(s):
            schema(s, "Host")["properties"]["name"]["anyOf"] = []

        def correlation_pattern(s):
            schema(s, "Error")["properties"]["correlation_id"]["pattern"] = "^.*$"

        def field_codes(s):
            schema(s, "Error")["properties"]["field_errors"]["items"]["properties"]["code"]["enum"].append("other")

        def additional_true_everywhere(s):
            schema(s, "Error")["properties"]["extra"] = {"type": "string", "maxLength": 1, "x-data-class": "operational"}

        self.check([("unknown keyword", unknown_keyword, ["SCHEMA_STRUCTURE"]), ("free-text message", add_message, ["SCHEMA_STRUCTURE"]),
                    ("openapi version", bad_version, ["SCHEMA_STRUCTURE"]), ("callbacks", callbacks, ["SCHEMA_STRUCTURE"]),
                    ("external ref", external_ref, ["SCHEMA_STRUCTURE"]), ("anyOf", anyof, ["SCHEMA_STRUCTURE"]),
                    ("correlation pattern", correlation_pattern, ["SCHEMA_STRUCTURE"]),
                    ("field error codes", field_codes, ["SCHEMA_STRUCTURE"]),
                    ("extra envelope property", additional_true_everywhere, ["SCHEMA_STRUCTURE"])])

    def test_error_enum_mismatch(self):
        def drop_category(s):
            schema(s, "Error")["properties"]["category"]["enum"].remove("timeout")

        def add_category(s):
            schema(s, "Error")["properties"]["category"]["enum"].append("teapot")

        def retryable_const(s):
            for b in schema(s, "Error")["oneOf"]:
                if b["properties"]["category"]["const"] == "rate_limited":
                    b["properties"]["retryable"]["const"] = False

        def drop_branch(s):
            schema(s, "Error")["oneOf"] = [b for b in schema(s, "Error")["oneOf"] if b["properties"]["category"]["const"] != "conflict"]

        def wrong_status(s):
            s["paths"][VM_LIST]["get"]["responses"]["401"] = {"$ref": "#/components/responses/Forbidden"}

        def unknown_status(s):
            s["paths"][VM_LIST]["get"]["responses"]["418"] = {"$ref": "#/components/responses/Forbidden"}

        def http_status(s):
            for b in schema(s, "Error")["oneOf"]:
                if b["properties"]["category"]["const"] == "validation":
                    b["x-http-status"] = 422

        def retryable_type(s):
            schema(s, "Error")["properties"]["retryable"]["type"] = "integer"

        self.check([("category removed", drop_category, ["ERROR_ENUM_MISMATCH"]), ("category added", add_category, ["ERROR_ENUM_MISMATCH"]),
                    ("retryable constant", retryable_const, ["ERROR_ENUM_MISMATCH"]), ("branch removed", drop_branch, ["ERROR_ENUM_MISMATCH"]),
                    ("status mapping", wrong_status, ["ERROR_ENUM_MISMATCH"]), ("unknown status", unknown_status, ["ERROR_ENUM_MISMATCH"]),
                    ("branch status", http_status, ["ERROR_ENUM_MISMATCH"]), ("retryable type", retryable_type, ["ERROR_ENUM_MISMATCH"])])

    def test_error_enum_mismatch_from_contract(self):
        def flip(c):
            c["errors"]["categories"]["unavailable"]["retryable"] = False

        self.check([("errors.json retryable", flip, ["ERROR_ENUM_MISMATCH"])], target="contracts")

    def test_error_response_untyped(self):
        def untyped_component(s):
            s["components"]["responses"]["NotFound"]["content"]["application/json"]["schema"] = {"$ref": "#/components/schemas/Health"}

        def inline_error(s):
            s["paths"][VM_LIST]["get"]["responses"]["401"] = {"description": "x", "content": {
                "application/json": {"schema": {"type": "object", "additionalProperties": False, "properties": {}}}}}

        def default_response(s):
            s["paths"][VM_LIST]["get"]["responses"]["default"] = {"$ref": "#/components/responses/InternalError"}

        self.check([("component uses Health", untyped_component, ["ERROR_RESPONSE_UNTYPED"]),
                    ("inline body", inline_error, ["ERROR_RESPONSE_UNTYPED"]),
                    ("default key", default_response, ["ERROR_RESPONSE_UNTYPED"])])

    def test_boundary_category(self):
        def timeout(s):
            s["components"]["responses"]["Timeout"] = {"description": "t", "x-error-category": "timeout", "content": {
                "application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}}
            s["paths"][VM_LIST]["get"]["responses"]["504"] = {"$ref": "#/components/responses/Timeout"}

        def host_error(s):
            s["components"]["responses"]["HostError"] = {"description": "h", "x-error-category": "host_error", "content": {
                "application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}}
            s["paths"]["/api/v1/operations"]["post"]["responses"]["502"] = {"$ref": "#/components/responses/HostError"}

        def narrower_boundary(c):
            c["inventory"]["boundaries"]["browser-api"]["error_categories"].remove("rate_limited")

        self.check([("504 timeout", timeout, ["BOUNDARY_CATEGORY"]), ("502 host_error", host_error, ["BOUNDARY_CATEGORY"])])
        self.check([("boundary shrinks", narrower_boundary, ["BOUNDARY_CATEGORY"])], target="contracts")

    def test_resource_set(self):
        def extra(s):
            s["components"]["schemas"]["Extra"] = copy.deepcopy(schema(s, "Health"))

        def missing(s):
            del s["components"]["schemas"]["Backup"]

        def missing_list(s):
            del s["components"]["schemas"]["ImageList"]

        def no_submit_request(s):
            del s["components"]["schemas"]["SubmitOperationRequest"]

        def contract_kind(c):
            c["resources"]["resources"]["Widget"] = copy.deepcopy(c["resources"]["resources"]["Backup"])

        self.check([("extra schema", extra, ["RESOURCE_SET"]), ("missing kind", missing, ["RESOURCE_SET"]),
                    ("missing list", missing_list, ["RESOURCE_SET"]), ("missing request", no_submit_request, ["RESOURCE_SET", "PATH_CATEGORY"])])
        self.check([("contract gains a kind", contract_kind, ["RESOURCE_SET"])], target="contracts")

    def test_resource_shape(self):
        def drop_project_id(s):
            vm = schema(s, "VM")
            del vm["properties"]["project_id"]
            vm["required"].remove("project_id")

        def host_gets_project_id(s):
            host = schema(s, "Host")
            host["properties"]["project_id"] = copy.deepcopy(schema(s, "VM")["properties"]["project_id"])
            host["required"].append("project_id")

        def drop_generation(s):
            vol = schema(s, "Volume")
            del vol["properties"]["generation"]
            vol["required"].remove("generation")

        def event_generation(s):
            ev = schema(s, "Event")
            ev["properties"]["generation"] = copy.deepcopy(schema(s, "VM")["properties"]["generation"])
            ev["required"].append("generation")

        def power_enum(s):
            schema(s, "VM")["properties"]["observed"]["properties"]["power"]["enum"].remove("crashed")

        def desired_type(s):
            schema(s, "VM")["properties"]["desired"]["properties"]["power"]["type"] = "boolean"

        def new_leaf(s):
            schema(s, "App")["properties"]["observed"]["properties"]["pid"] = {"type": "integer", "minimum": 0, "maximum": 5, "x-data-class": "operational"}
            schema(s, "App")["properties"]["observed"]["required"].append("pid")

        def not_required(s):
            schema(s, "VM")["required"].remove("name")

        def unbounded_string(s):
            del schema(s, "VM")["properties"]["name"]["maxLength"]

        def unbounded_array(s):
            del schema(s, "VMList")["properties"]["items"]["maxItems"]

        def list_item_ref(s):
            schema(s, "VMList")["properties"]["items"]["items"] = {"$ref": "#/components/schemas/Host"}

        def drop_next_cursor(s):
            lst = schema(s, "VMList")
            del lst["properties"]["next_cursor"]
            lst["required"].remove("next_cursor")

        def event_extra(s):
            ev = schema(s, "Event")
            ev["properties"]["name"] = copy.deepcopy(schema(s, "VM")["properties"]["name"])
            ev["required"].append("name")

        self.check([("VM loses project_id", drop_project_id, ["RESOURCE_SHAPE"]),
                    ("Host gains project_id", host_gets_project_id, ["RESOURCE_SHAPE"]),
                    ("Volume loses generation", drop_generation, ["RESOURCE_SHAPE"]),
                    ("Event gains generation", event_generation, ["RESOURCE_SHAPE"]),
                    ("observed enum", power_enum, ["RESOURCE_SHAPE"]), ("desired type", desired_type, ["RESOURCE_SHAPE"]),
                    ("extra observed leaf", new_leaf, ["RESOURCE_SHAPE"]), ("not required", not_required, ["RESOURCE_SHAPE"]),
                    ("unbounded string", unbounded_string, ["RESOURCE_SHAPE"]), ("unbounded array", unbounded_array, ["RESOURCE_SHAPE"]),
                    ("list item kind", list_item_ref, ["RESOURCE_SHAPE"]), ("collection loses cursor", drop_next_cursor, ["RESOURCE_SHAPE"]),
                    ("Event gains name", event_extra, ["RESOURCE_SHAPE"])])

    def test_operation_fields(self):
        def drop_attempts(s):
            op = schema(s, "Operation")
            del op["properties"]["attempts"]
            op["required"].remove("attempts")

        def add_key(s):
            op = schema(s, "Operation")
            op["properties"]["idempotency_key"] = {"type": "string", "maxLength": 63, "x-data-class": "operational"}
            op["required"].append("idempotency_key")

        def statuses(s):
            schema(s, "Operation")["properties"]["status"]["enum"].append("paused")

        def status_removed(s):
            schema(s, "Operation")["properties"]["status"]["enum"].remove("cancelled")

        def error_category(s):
            schema(s, "Operation")["properties"]["error_category"]["enum"].remove("host_error")

        def contract_field(c):
            c["resources"]["operation_persisted_fields"].append("lease")

        def contract_secret(c):
            c["data-classes"]["fields"]["operation.attempts"] = "secret"

        self.check([("attempts removed", drop_attempts, ["OPERATION_FIELDS"]), ("status added", statuses, ["OPERATION_FIELDS"]),
                    ("status removed", status_removed, ["OPERATION_FIELDS"]), ("error_category enum", error_category, ["OPERATION_FIELDS"])])
        self.assertEqual(mutated(add_key), ["CLASS_MISMATCH", "OPERATION_FIELDS"])  # also mislabelled: credential in the contract
        self.check([("persisted field added", contract_field, ["OPERATION_FIELDS"])], target="contracts")
        # A contract that newly classifies a persisted field as secret removes it from the response shape and
        # contradicts the schema's annotation.
        self.assertEqual(mutated(contract_secret, "contracts"), ["CLASS_MISMATCH", "OPERATION_FIELDS"])

    def test_open_object(self):
        def nested(s):
            schema(s, "VM")["properties"]["observed"]["additionalProperties"] = True

        def top(s):
            del schema(s, "HostList")["additionalProperties"]

        def error(s):
            del schema(s, "Error")["additionalProperties"]

        def field_error_item(s):
            schema(s, "Error")["properties"]["field_errors"]["items"]["additionalProperties"] = {"type": "string"}

        def request(s):
            del schema(s, "SubmitOperationRequest")["additionalProperties"]

        self.check([("nested object", nested, ["OPEN_OBJECT"]), ("collection", top, ["OPEN_OBJECT"]), ("Error", error, ["OPEN_OBJECT"]),
                    ("field error item", field_error_item, ["OPEN_OBJECT"]), ("request body", request, ["OPEN_OBJECT"])])

    def test_classification(self):
        def unclassified(s):
            del schema(s, "VM")["properties"]["name"]["x-data-class"]

        def unknown_class(s):
            schema(s, "VM")["properties"]["name"]["x-data-class"] = "private"

        def nested_unclassified(s):
            del schema(s, "VM")["properties"]["observed"]["properties"]["power"]["x-data-class"]

        def items_unclassified(s):
            del schema(s, "Error")["properties"]["field_errors"]["items"]["properties"]["field"]["x-data-class"]

        def secret(s):
            schema(s, "VM")["properties"]["name"]["x-data-class"] = "secret"

        def credential_nested(s):
            schema(s, "VM")["properties"]["observed"]["properties"]["power"]["x-data-class"] = "credential"

        def personal_elsewhere(s):
            schema(s, "VM")["properties"]["name"]["x-data-class"] = "personal"

        def operation_class(s):
            schema(s, "Operation")["properties"]["status"]["x-data-class"] = "public"

        def requested_by(s):
            schema(s, "Operation")["properties"]["requested_by"]["x-data-class"] = "operational"

        def request_class(s):
            schema(s, "SubmitOperationRequest")["properties"]["idempotency_key"]["x-data-class"] = "operational"

        def request_unclassified(s):
            del schema(s, "SubmitOperationRequest")["properties"]["kind"]["x-data-class"]

        self.check([("missing class", unclassified, ["UNCLASSIFIED_FIELD"]), ("unknown class", unknown_class, ["UNCLASSIFIED_FIELD"]),
                    ("nested missing", nested_unclassified, ["UNCLASSIFIED_FIELD"]), ("array item property", items_unclassified, ["UNCLASSIFIED_FIELD"]),
                    ("secret", secret, ["SECRET_IN_RESPONSE"]), ("nested credential", credential_nested, ["SECRET_IN_RESPONSE"]),
                    ("personal elsewhere", personal_elsewhere, ["CLASS_MISMATCH"]), ("operation class", operation_class, ["CLASS_MISMATCH"]),
                    ("requested_by class", requested_by, ["CLASS_MISMATCH"]), ("request body class", request_class, ["CLASS_MISMATCH"]),
                    ("request body missing", request_unclassified, ["UNCLASSIFIED_FIELD"])])

    def test_action_invalid(self):
        def vm_extra(s):
            enum = schema(s, "VM")["properties"]["allowed_actions"]["items"]["enum"]
            enum.append("migrate")
            schema(s, "VM")["properties"]["allowed_actions"]["maxItems"] = len(enum)

        def vm_missing(s):
            schema(s, "VM")["properties"]["allowed_actions"]["items"]["enum"].remove("start")

        def host_actions(s):
            schema(s, "Host")["properties"]["allowed_actions"] = {"type": "array", "maxItems": 1, "items": {"type": "string", "enum": ["start"]},
                                                                   "x-data-class": "operational"}

        def volume_start(s):
            schema(s, "Volume")["properties"]["allowed_actions"]["items"]["enum"].append("start")

        def list_delete(s):
            schema(s, "VMList")["properties"]["allowed_actions"]["items"]["enum"].append("delete")

        def event_create(s):
            schema(s, "EventList")["properties"]["allowed_actions"] = {"type": "array", "maxItems": 1, "items": {"type": "string", "enum": ["create"]},
                                                                      "x-data-class": "operational"}

        def operation_delete(s):
            schema(s, "Operation")["properties"]["allowed_actions"]["items"]["enum"] = ["delete"]

        def no_create(s):
            schema(s, "VMList")["properties"]["allowed_actions"]["items"]["enum"] = []

        self.check([("VM extra id", vm_extra, ["ACTION_INVALID"]), ("VM missing id", vm_missing, ["ACTION_INVALID"]),
                    ("Host actions", host_actions, ["ACTION_INVALID"]), ("Volume start", volume_start, ["ACTION_INVALID"]),
                    ("collection delete", list_delete, ["ACTION_INVALID"]), ("Event collection create", event_create, ["ACTION_INVALID"]),
                    ("Operation delete", operation_delete, ["ACTION_INVALID"]), ("empty enum is outside the subset", no_create, ["SCHEMA_STRUCTURE"])])

    def test_path_category(self):
        def wrong_category(s):
            s["paths"][VM_LIST]["get"]["x-request-category"] = "read_resource"

        def unknown_category(s):
            s["paths"][VM_LIST]["get"]["x-request-category"] = "typed_host_command"

        def extra_method(s):
            op = copy.deepcopy(s["paths"][VM_LIST]["get"])
            op["operationId"] = "deleteVMs"
            s["paths"][VM_LIST]["delete"] = op

        def extra_path(s):
            s["paths"]["/api/v1/secrets"] = copy.deepcopy(s["paths"][VM_LIST])

        def missing_path(s):
            del s["paths"]["/api/v1/vms/{id}"]

        def limit_bound(s):
            s["components"]["parameters"]["Limit"]["schema"]["maximum"] = 500

        def id_pattern(s):
            s["components"]["parameters"]["Id"]["schema"]["pattern"] = "^.*$"

        def cursor_pattern(s):
            s["components"]["parameters"]["Cursor"]["schema"]["pattern"] = "^.*$"

        def submit_enum(s):
            schema(s, "SubmitOperationRequest")["properties"]["type"]["enum"].append("restart")

        def submit_key(s):
            body = schema(s, "SubmitOperationRequest")
            body["properties"]["force"] = {"type": "boolean", "x-data-class": "operational"}
            body["required"].append("force")

        def success_schema(s):
            s["paths"][VM_LIST]["get"]["responses"]["200"]["content"]["application/json"]["schema"] = {"$ref": "#/components/schemas/HostList"}

        def success_status(s):
            r = s["paths"]["/api/v1/operations"]["post"]["responses"]
            r["200"] = r.pop("202")

        def no_401(s):
            del s["paths"][VM_LIST]["get"]["responses"]["401"]

        def body_on_get(s):
            s["paths"][VM_LIST]["get"]["requestBody"] = {"required": True, "content": {"application/json": {"schema": {"$ref": "#/components/schemas/SubmitOperationRequest"}}}}

        def params_changed(s):
            s["paths"][VM_LIST]["get"]["parameters"] = [{"$ref": "#/components/parameters/Limit"}]

        def contract_category(c):
            c["inventory"]["boundaries"]["browser-api"]["permitted_request_categories"].remove("list_resources")

        def contract_limit(c):
            c["request-schemas"]["value_types"]["limit"] = "^[1-9][0-9]?$"

        self.check([("category swapped", wrong_category, ["PATH_CATEGORY"]), ("category not permitted", unknown_category, ["PATH_CATEGORY"]),
                    ("extra method", extra_method, ["PATH_CATEGORY"]), ("extra path", extra_path, ["PATH_CATEGORY"]),
                    ("missing path", missing_path, ["PATH_CATEGORY"]), ("limit bound", limit_bound, ["PATH_CATEGORY"]),
                    ("id pattern", id_pattern, ["PATH_CATEGORY"]), ("cursor pattern", cursor_pattern, ["PATH_CATEGORY"]),
                    ("submit enum", submit_enum, ["PATH_CATEGORY"]), ("submit key", submit_key, ["PATH_CATEGORY"]),
                    ("success schema", success_schema, ["PATH_CATEGORY"]), ("success status", success_status, ["PATH_CATEGORY"]),
                    ("no 401", no_401, ["PATH_CATEGORY"]), ("body on GET", body_on_get, ["PATH_CATEGORY"]),
                    ("parameters", params_changed, ["PATH_CATEGORY"])])
        self.check([("category removed from contract", contract_category, ["PATH_CATEGORY"]),
                    ("limit contract changed", contract_limit, ["PATH_CATEGORY"])], target="contracts")

    def test_security_missing(self):
        def none(s):
            s["paths"][VM_LIST]["get"]["security"] = []

        def other_scheme(s):
            s["paths"][VM_LIST]["get"]["security"] = [{"anonymous": []}]

        def drop_scheme(s):
            s["components"]["securitySchemes"] = {}

        def health_secured(s):
            s["paths"]["/healthz"]["get"]["security"] = [{"ownerSession": []}]

        def second_scheme(s):
            s["components"]["securitySchemes"]["anonymous"] = {"type": "http", "scheme": "basic"}

        self.check([("empty security", none, ["SECURITY_MISSING"]), ("other scheme", other_scheme, ["SECURITY_MISSING"]),
                    ("no scheme defined", drop_scheme, ["SECURITY_MISSING"]), ("health secured", health_secured, ["SECURITY_MISSING"]),
                    ("second scheme", second_scheme, ["SECURITY_MISSING"])])

    def test_implemented_claim(self):
        def claim(s):
            s["paths"]["/api/v1/apps"]["get"]["x-implementation-status"] = "implemented"

        def health_not(s):
            s["paths"]["/healthz"]["get"]["x-implementation-status"] = "not_implemented"

        def free_text(s):
            s["paths"]["/api/v1/apps"]["get"]["x-implementation-status"] = "partial"

        def contract(c):
            c["inventory"]["boundaries"]["browser-api"]["implemented_requests"].append("GET /api/v1/apps")

        self.check([("claim", claim, ["IMPLEMENTED_CLAIM"]), ("health not implemented", health_not, ["IMPLEMENTED_CLAIM"]),
                    ("free text", free_text, ["IMPLEMENTED_CLAIM"])])
        self.check([("contract claims an implementation the spec denies", contract, ["IMPLEMENTED_CLAIM"])], target="contracts")


    def test_m2_storage_additions_are_pinned(self):
        """DR-020: the closed `params` object, the VM and Host observations, the Image evidence and the action sets."""
        def params_prop(s):
            schema(s, "SubmitOperationRequest")["properties"]["params"]["properties"]["path"] = {"type": "string", "maxLength": 10}

        def params_removed(s):
            del schema(s, "SubmitOperationRequest")["properties"]["params"]

        def params_open(s):
            schema(s, "SubmitOperationRequest")["properties"]["params"]["additionalProperties"] = True

        def params_disk_unbounded(s):
            schema(s, "SubmitOperationRequest")["properties"]["params"]["properties"]["disk_gib"]["maximum"] = 99999

        def params_key_pattern(s):
            schema(s, "SubmitOperationRequest")["properties"]["params"]["properties"]["ssh_public_key"]["pattern"] = "^.*$"

        def params_snapshot_loose(s):
            schema(s, "SubmitOperationRequest")["properties"]["params"]["properties"]["snapshot_id"]["pattern"] = "^.*$"

        def params_required(s):
            schema(s, "SubmitOperationRequest")["properties"]["params"]["required"] = ["disk_gib"]

        def vm_snapshots_unbounded(s):
            schema(s, "VM")["properties"]["observed"]["properties"]["snapshots"]["maxItems"] = 9

        def vm_snapshot_extra(s):
            schema(s, "VM")["properties"]["observed"]["properties"]["snapshots"]["items"]["properties"]["path"] = {"type": "string", "maxLength": 9}

        def vm_disk_unbounded(s):
            schema(s, "VM")["properties"]["observed"]["properties"]["disk_gib"]["maximum"] = 10 ** 9

        def vm_action(s):
            schema(s, "VM")["properties"]["allowed_actions"]["items"]["enum"].append("console")

        def backup_action(s):
            schema(s, "Backup")["properties"]["allowed_actions"]["items"]["enum"].remove("restore")

        def host_storage_removed(s):
            del schema(s, "Host")["properties"]["observed"]["properties"]["storage"]

        def host_storage_state(s):
            schema(s, "Host")["properties"]["observed"]["properties"]["storage"]["properties"]["state"]["enum"].append("degraded")

        def host_storage_free(s):
            schema(s, "Host")["properties"]["observed"]["properties"]["storage"]["properties"]["pool_free_gib"]["type"] = "string"

        def image_evidence(s):
            del schema(s, "Image")["properties"]["observed"]["properties"]["qualification_evidence"]

        def type_enum(s):
            schema(s, "SubmitOperationRequest")["properties"]["type"]["enum"].append("format_disk")

        self.check([
            ("params gains a property", params_prop, ["PATH_CATEGORY"]), ("params removed", params_removed, ["PATH_CATEGORY"]),
            ("params open", params_open, ["OPEN_OBJECT", "PATH_CATEGORY"]), ("params disk unbounded", params_disk_unbounded, ["PATH_CATEGORY"]),
            ("params key gets a pattern", params_key_pattern, ["PATH_CATEGORY"]), ("params snapshot id loose", params_snapshot_loose, ["PATH_CATEGORY"]),
            ("params has required fields", params_required, ["PATH_CATEGORY"]), ("type enum grows", type_enum, ["PATH_CATEGORY"]),
            ("snapshots unbounded", vm_snapshots_unbounded, ["RESOURCE_SHAPE"]), ("snapshot item gains a path", vm_snapshot_extra, ["RESOURCE_SHAPE", "UNCLASSIFIED_FIELD"]),
            ("disk unbounded", vm_disk_unbounded, ["RESOURCE_SHAPE"]), ("VM action added", vm_action, ["ACTION_INVALID"]),
            ("backup restore removed", backup_action, ["ACTION_INVALID"]), ("host storage removed", host_storage_removed, ["RESOURCE_SHAPE"]),
            ("host storage state grows", host_storage_state, ["RESOURCE_SHAPE"]), ("host storage figure retyped", host_storage_free, ["RESOURCE_SHAPE"]),
            ("image evidence removed", image_evidence, ["RESOURCE_SHAPE"]),
        ])


    def test_m3_network_additions_are_pinned(self):
        """DR-021: VirtualNetwork observations, the VM network object, the new params and the create network."""
        def vn(s):
            return schema(s, "VirtualNetwork")["properties"]["observed"]["properties"]

        def res_unbounded(s):
            vn(s)["reservations"]["maxItems"] = 257

        def res_extra(s):
            vn(s)["reservations"]["items"]["properties"]["path"] = {"type": "string", "maxLength": 9}

        def gw_pattern(s):
            vn(s)["gateway"]["pattern"] = "^.*$"

        def subnet_free(s):
            vn(s)["subnet"]["maxLength"] = 1000

        def attached_unbounded(s):
            vn(s)["attached_vms"]["maximum"] = 10 ** 12

        def managed_gone(s):
            del vn(s)["managed"]

        def mode_enum(s):
            schema(s, "VirtualNetwork")["properties"]["desired"]["properties"]["mode"]["enum"].append("tap")

        def net_action(s):
            schema(s, "VirtualNetwork")["properties"]["allowed_actions"]["items"]["enum"].append("format")

        def vm_network_removed(s):
            del schema(s, "VM")["properties"]["observed"]["properties"]["network"]

        def vm_network_extra(s):
            schema(s, "VM")["properties"]["observed"]["properties"]["network"]["properties"]["bridge_path"] = {"type": "string", "maxLength": 9}

        def vm_network_state(s):
            schema(s, "VM")["properties"]["observed"]["properties"]["network"]["properties"]["state"]["enum"].append("broken")

        def create_net_required(s):
            schema(s, "SubmitOperationRequest")["properties"]["create"]["required"].append("network")

        def create_net_loose(s):
            del schema(s, "SubmitOperationRequest")["properties"]["create"]["properties"]["network"]["pattern"]

        def params_vcpus(s):
            schema(s, "SubmitOperationRequest")["properties"]["params"]["properties"]["vcpus"]["maximum"] = 65

        def params_autostart(s):
            schema(s, "SubmitOperationRequest")["properties"]["params"]["properties"]["autostart"]["enum"].append("maybe")

        def params_ip_loose(s):
            schema(s, "SubmitOperationRequest")["properties"]["params"]["properties"]["ip_address"]["pattern"] = "^.*$"

        def params_bridge(s):
            schema(s, "SubmitOperationRequest")["properties"]["params"]["properties"]["bridge"] = {"type": "string", "maxLength": 15}

        def vm_action(s):
            schema(s, "VM")["properties"]["allowed_actions"]["items"]["enum"].append("snapshot_live")

        self.check([
            ("reservations unbounded", res_unbounded, ["RESOURCE_SHAPE"]), ("reservation item gains a path", res_extra, ["RESOURCE_SHAPE", "UNCLASSIFIED_FIELD"]),
            ("gateway pattern loosened", gw_pattern, ["RESOURCE_SHAPE"]), ("subnet unbounded", subnet_free, ["RESOURCE_SHAPE"]),
            ("attached unbounded", attached_unbounded, ["RESOURCE_SHAPE"]), ("managed removed", managed_gone, ["RESOURCE_SHAPE"]),
            ("mode enum grows", mode_enum, ["RESOURCE_SHAPE"]), ("network action added", net_action, ["ACTION_INVALID"]),
            ("VM network removed", vm_network_removed, ["RESOURCE_SHAPE"]), ("VM network gains a field", vm_network_extra, ["RESOURCE_SHAPE", "UNCLASSIFIED_FIELD"]),
            ("VM network state grows", vm_network_state, ["RESOURCE_SHAPE"]), ("create network required", create_net_required, ["PATH_CATEGORY"]),
            ("create network loosened", create_net_loose, ["PATH_CATEGORY"]), ("vcpus unbounded", params_vcpus, ["PATH_CATEGORY"]),
            ("autostart enum grows", params_autostart, ["PATH_CATEGORY"]), ("ip pattern loosened", params_ip_loose, ["PATH_CATEGORY"]),
            ("params gains a bridge", params_bridge, ["PATH_CATEGORY"]), ("VM action added", vm_action, ["ACTION_INVALID"]),
        ])


class Loader(unittest.TestCase):
    def test_rejects_duplicate_keys_anchors_and_oversize(self):
        for raw in (b"a: 1\na: 2\n", b"a: &x 1\nb: *x\n", b"a: &x {b: 1}\n", b"x: " + b"y" * (co.MAX_SPEC_BYTES + 1)):
            with self.subTest(raw[:12]), self.assertRaises(co.Structure):
                co.load_yaml(raw)

    def test_rejects_python_tags(self):
        with self.assertRaises(Exception):
            co.load_yaml(b"a: !!python/object/apply:os.system ['true']\n")

    def test_non_mapping_or_garbage_are_findings_not_crashes(self):
        for value in (None, [], "x", 3, {"openapi": "3.1.0"}):
            with self.subTest(value=value):
                self.assertTrue(co.check_spec(value, CONTRACTS))

    def test_malformed_paths_do_not_crash(self):
        spec = copy.deepcopy(SPEC)
        spec["paths"]["/healthz"]["get"]["responses"] = None
        spec["paths"][VM_LIST] = []
        self.assertIn("SCHEMA_STRUCTURE", codes(spec))


def reg(**decisions):
    return {k: {"status": v[0], "stories": v[1]} for k, v in decisions.items()}


def raw(decision, digest):
    return json.dumps({"schema": 1, "decision": decision, "schema_digest": digest}).encode()


A, B = "a" * 64, "b" * 64
P1, P2, P3 = "1" * 40, "2" * 40, "3" * 40


class Baseline(unittest.TestCase):
    """Section 5 (review M10, R2-M3)."""

    deps = {"DR-012", "DR-020", "DR-021"}

    def run_check(self, digest, chain, registers):
        return [f[2] for f in co.check_baseline(digest, chain, lambda sha: registers[sha], self.deps)]

    def first(self):
        return [{"raw": raw("DR-012", A), "pin": P1}]

    def test_first_baseline_passes(self):
        self.assertEqual(self.run_check(A, self.first(), {P1: reg(**{"DR-012": ("approved", [co.STORY_ID])})}), [])

    def test_schema_change_without_baseline_update(self):
        out = self.run_check(B, self.first(), {P1: reg(**{"DR-012": ("approved", [co.STORY_ID])})})
        self.assertEqual(len(out), 1)
        self.assertIn("without updating the baseline", out[0])

    def test_missing_or_malformed_baseline(self):
        self.assertTrue(co.check_baseline(A, [], lambda s: {}, self.deps))
        self.assertTrue(co.check_baseline(A, [{"raw": b"{}", "pin": P1}], lambda s: {}, self.deps))
        self.assertTrue(co.check_baseline(A, [{"raw": raw("DR-012", A), "pin": None}], lambda s: {}, self.deps))
        extra = json.dumps({"schema": 1, "decision": "DR-012", "schema_digest": A, "note": "x"}).encode()
        self.assertTrue(co.check_baseline(A, [{"raw": extra, "pin": P1}], lambda s: {}, self.deps))

    def test_decision_must_be_approved_list_the_story_and_be_declared(self):
        for label, registers, deps in (
                ("not approved", {P1: reg(**{"DR-012": ("proposed", [co.STORY_ID])})}, self.deps),
                ("wrong story", {P1: reg(**{"DR-012": ("approved", ["M0-E01-S01"])})}, self.deps),
                ("absent", {P1: {}}, self.deps),
                ("undeclared", {P1: reg(**{"DR-012": ("approved", [co.STORY_ID])})}, {"DR-020"})):
            with self.subTest(label):
                out = [f[2] for f in co.check_baseline(A, self.first(), lambda sha: registers[sha], deps)]
                self.assertEqual(len(out), 1, out)

    def test_register_problem_is_reported(self):
        out = co.check_baseline(A, self.first(), lambda sha: "decision register malformed", self.deps)
        self.assertEqual([f[0] for f in out], ["BREAKING_CHANGE"])

    def chain2(self, second_decision="DR-020", digest2=B):
        return [{"raw": raw("DR-012", A), "pin": P1}, {"raw": raw(second_decision, digest2), "pin": P2}]

    def test_schema_change_with_a_new_approved_decision_passes(self):
        registers = {P1: reg(**{"DR-012": ("approved", [co.STORY_ID]), "DR-020": ("proposed", [co.STORY_ID])}),
                     P2: reg(**{"DR-012": ("approved", [co.STORY_ID]), "DR-020": ("approved", [co.STORY_ID])})}
        self.assertEqual(self.run_check(B, self.chain2(), registers), [])

    def test_schema_change_reusing_a_decision_fails(self):
        registers = {P1: reg(**{"DR-012": ("approved", [co.STORY_ID])}), P2: reg(**{"DR-012": ("approved", [co.STORY_ID])})}
        out = self.run_check(B, self.chain2("DR-012"), registers)
        self.assertTrue(any("different from every earlier baseline" in m for m in out), out)

    def test_decision_already_approved_at_previous_pin_fails(self):
        registers = {P1: reg(**{"DR-012": ("approved", [co.STORY_ID]), "DR-020": ("approved", [co.STORY_ID])}),
                     P2: reg(**{"DR-012": ("approved", [co.STORY_ID]), "DR-020": ("approved", [co.STORY_ID])})}
        out = self.run_check(B, self.chain2(), registers)
        self.assertTrue(any("already approved" in m for m in out), out)

    def test_new_decision_must_be_approved_at_its_own_pin(self):
        registers = {P1: reg(**{"DR-012": ("approved", [co.STORY_ID])}),
                     P2: reg(**{"DR-012": ("approved", [co.STORY_ID]), "DR-020": ("proposed", [co.STORY_ID])})}
        self.assertTrue(self.run_check(B, self.chain2(), registers))

    def test_decision_edit_without_schema_change_fails(self):
        registers = {P1: reg(**{"DR-012": ("approved", [co.STORY_ID])}),
                     P2: reg(**{"DR-012": ("approved", [co.STORY_ID]), "DR-020": ("approved", [co.STORY_ID])})}
        out = self.run_check(A, self.chain2(digest2=A), registers)
        self.assertTrue(any("without a schema change" in m for m in out), out)

    def test_third_change_may_not_return_to_an_earlier_decision(self):
        registers = {p: reg(**{"DR-012": ("approved", [co.STORY_ID]), "DR-020": ("approved", [co.STORY_ID]),
                               "DR-021": ("approved", [co.STORY_ID])}) for p in (P1, P2, P3)}
        registers[P1] = reg(**{"DR-012": ("approved", [co.STORY_ID])})
        registers[P2] = reg(**{"DR-012": ("approved", [co.STORY_ID]), "DR-020": ("approved", [co.STORY_ID])})
        chain = self.chain2() + [{"raw": raw("DR-012", "c" * 64), "pin": P3}]
        out = self.run_check("c" * 64, chain, registers)
        self.assertTrue(any("different from every earlier baseline" in m for m in out), out)


class History(unittest.TestCase):
    """baseline_chain reads first-parent history and appends a differing working-tree baseline."""

    def git(self, repo, *args):
        env = dict(os.environ, GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM="1")
        subprocess.run(["git", "-C", str(repo), "-c", "user.name=t", "-c", "user.email=t@example.invalid", "-c", "commit.gpgsign=false", *args],
                       check=True, capture_output=True, env=env)

    def test_chain(self):
        linkage = co.load_linkage(ROOT)
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            self.git(repo, "init", "-q", "-b", "main")
            (repo / "contracts").mkdir()
            lock = lambda sha: json.dumps({"schema": 1, "docs_repo": "cloud-product-docs", "commit": sha}).encode()  # noqa: E731
            (repo / "docs-lock.json").write_bytes(lock(P1))
            (repo / co.BASELINE_FILE).write_bytes(raw("DR-012", A))
            self.git(repo, "add", "-A")
            self.git(repo, "commit", "-q", "-m", "one")
            (repo / "other.txt").write_text("x")
            self.git(repo, "add", "-A")
            self.git(repo, "commit", "-q", "-m", "unrelated")
            same = co.baseline_chain(linkage, str(repo), raw("DR-012", A), lock(P1))
            self.assertEqual([c["pin"] for c in same], [P1])
            (repo / "docs-lock.json").write_bytes(lock(P2))
            (repo / co.BASELINE_FILE).write_bytes(raw("DR-020", B))
            self.git(repo, "add", "-A")
            self.git(repo, "commit", "-q", "-m", "two")
            both = co.baseline_chain(linkage, str(repo), raw("DR-020", B), lock(P2))
            self.assertEqual([c["pin"] for c in both], [P1, P2])
            pending = co.baseline_chain(linkage, str(repo), raw("DR-021", "c" * 64), lock(P3))
            self.assertEqual([c["pin"] for c in pending], [P1, P2, P3])
            # A side branch merged with --no-ff does not add its own baseline commits to the first-parent chain.
            self.git(repo, "checkout", "-q", "-b", "side")
            (repo / co.BASELINE_FILE).write_bytes(raw("DR-021", "c" * 64))
            self.git(repo, "commit", "-q", "-am", "side")
            self.git(repo, "checkout", "-q", "main")
            self.git(repo, "merge", "-q", "--no-ff", "-m", "merge", "side")
            merged = co.baseline_chain(linkage, str(repo), raw("DR-021", "c" * 64), lock(P2))
            self.assertEqual(len(merged), 3)

    def test_repo_without_history_is_an_environment_error(self):
        linkage = co.load_linkage(ROOT)
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(co.EnvError):
                co.baseline_chain(linkage, tmp, raw("DR-012", A), b"{}")


class ReadOnly(unittest.TestCase):
    def test_checker_writes_nothing(self):
        def snapshot():
            return sorted((str(p), p.stat().st_mtime_ns, p.stat().st_size) for p in ROOT.rglob("*")
                          if p.is_file() and ".git" not in p.parts and "node_modules" not in p.parts)

        before = snapshot()
        docs = os.environ.get("DOCS_REPO") or str(ROOT.parent / "cloud-product-docs")
        proc = subprocess.run([sys.executable, "-B", str(ROOT / "tools" / "check_openapi.py"), "--docs-repo", docs],
                              capture_output=True, text=True)
        self.assertIn(proc.returncode, (0, 1), proc.stdout + proc.stderr)
        self.assertEqual(snapshot(), before)


if __name__ == "__main__":
    unittest.main()
