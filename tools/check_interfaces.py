#!/usr/bin/env python3
"""Interface contract and request-fixture checker (story M0-E01-S01, DRAFT).

Validates contracts/interfaces/*.json and classifies request fixtures.
Security-relevant properties are pinned here (not taken from the contracts),
so weakening a contract fails the check. Requests are validated against an
allowlisted schema per category; denylist categories are defence in depth.
Standard library only; requests are data, never executed.

Exit codes: 0 no findings, 1 findings, 2 usage error.
"""
import argparse
import hashlib
import json
import re
import sys
import unicodedata
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CONTRACT_FILES = ("errors", "inventory", "resources", "prohibited", "failure-matrix", "request-schemas")

# Architecture pinned by the checker (ADR-001, ADR-003, ADR-004, ADR-011).
BOUNDARIES = {
    "browser-api": {
        "security": {"transport_kind": "https", "listener": "loopback_scaffold", "peer_auth": "session_cookie_csrf",
                     "authz_model": "deny_by_default", "ownership_check": True, "accepts_client_xml": False,
                     "executes_commands": False},
        "categories": {"health", "list_resources", "read_resource", "submit_operation", "cancel_operation", "auth_status",
                       "sign_in", "sign_out"},
        "status": "scaffold",
        "implemented": ["GET /healthz", "GET /api/v1/auth/session", "POST /api/v1/auth/session",
                        "DELETE /api/v1/auth/session", "GET /api/v1/hosts", "GET /api/v1/hosts/{id}",
                        "GET /api/v1/vms", "GET /api/v1/vms/{id}", "GET /api/v1/images", "GET /api/v1/images/{id}",
                        "GET /api/v1/virtual-networks", "GET /api/v1/virtual-networks/{id}", "GET /api/v1/volumes", "GET /api/v1/volumes/{id}", "GET /api/v1/backups", "GET /api/v1/backups/{id}",
                        "GET /api/v1/operations", "POST /api/v1/operations", "GET /api/v1/operations/{id}",
                        "GET /api/v1/events", "GET /api/v1/events/{id}"]},
    "api-operation-manager": {
        "security": {"transport_kind": "in_process", "listener": "none", "peer_auth": "in_process_actor_propagation",
                     "authz_model": "deny_by_default", "ownership_check": True, "accepts_client_xml": False,
                     "executes_commands": False},
        "categories": {"submit_operation", "get_operation", "cancel_operation"},
        "status": "not_implemented", "implemented": []},
    "operation-manager-host-agent": {
        "security": {"transport_kind": "unix", "listener": "unix_socket", "peer_auth": "so_peercred_allowlist",
                     "authz_model": "enumerated_typed_commands", "ownership_check": True,
                     "accepts_client_xml": False, "executes_commands": False},
        "categories": {"typed_host_command"},
        "status": "not_implemented", "implemented": []},
    "host-agent-libvirt": {
        "security": {"transport_kind": "libvirt_local", "listener": "none", "peer_auth": "libvirt_socket_permissions",
                     "authz_model": "enumerated_typed_calls", "ownership_check": True, "accepts_client_xml": False,
                     "executes_commands": False},
        "categories": {"typed_libvirt_call"},
        "status": "not_implemented", "implemented": []},
    "paas-controller-workload-vm": {
        "security": {"transport_kind": "managed_vm_network", "listener": "none", "peer_auth": "per_vm_credential",
                     "authz_model": "deny_by_default", "ownership_check": True, "accepts_client_xml": False,
                     "executes_commands": False},
        "categories": {"deploy_app", "get_app"},
        "status": "not_implemented", "implemented": []},
}
BOUNDARY_TEXT_FIELDS = ("caller", "callee", "transport", "authentication", "authorization", "audit", "data_owner")
RESOURCES = {"Host": "system", "Project": "system", "VM": "project", "Volume": "project",
             "VirtualNetwork": "project", "Image": "project", "Backup": "project", "App": "project",
             "Operation": "project", "Event": "project"}
STORE_WRITER = "operation-manager"
OBSERVED_REPORTERS = {"api", "host-agent", "operation-manager", "paas-controller"}
DESIRED_SOURCES = {"api", "operation-manager"}
ROWS = {"api-restart", "operation-manager-restart", "agent-timeout", "agent-unavailable", "host-agent-crash",
        "libvirt-unavailable"}
# DR-015 D2 is ratified (sponsor, 2026-10-09) and M1-E04-S05 is verified locally, but this flag stays False on purpose: it
# drives the contract-fixture model "every category except health is rejected" (PRIVILEGED_BEFORE_AUTH), which has no way to
# express an authenticated browser-api request. Flipping it is a fixture-model change (positive fixtures for session-authenticated
# requests, the prohibited-code coverage rule, docs/INTERFACES.md), tracked in docs/NEXT-SLICE.md; it does not gate the running
# API, whose sessions and CSRF are enforced and tested in package api. Pinned so a contract edit cannot change it (review R1).
AUTH_DESIGN_APPROVED = False
ROW_FIELDS = ("durable_state_owner", "caller_visible_error", "retry_responsibility", "idempotency", "recovery_story",
              "recovery_implemented")
PROHIBITED_CODES = {"ARBITRARY_SHELL", "HYPERVISOR_XML", "AGENT_TCP", "REMOTE_HYPERVISOR", "PROVIDER_CREDENTIALS",
                    "PRIVILEGED_BEFORE_AUTH", "CATEGORY_NOT_PERMITTED", "SCHEMA_VIOLATION"}
REQUIRED_OPERATION_FIELDS = {"id", "project_id", "status", "idempotency_key", "generation", "requested_by"}
REQUEST_KEYS = {"boundary", "category", "payload", "transport"}
UNAUTHENTICATED_CATEGORIES = {"health", "auth_status", "sign_in", "sign_out"}
# Optional payload keys (DR-012 D6): required <= keys <= allowed for these categories only. Pinned here, not in the
# contract, so a contract edit cannot make other keys optional.
OPTIONAL_KEYS = {"list_resources": {"limit", "cursor"}}
# Exact transport allowlists, compared without normalisation (review N3).
TRANSPORTS = {"operation-manager-host-agent": ("AGENT_TCP", "unix"),
              "host-agent-libvirt": ("REMOTE_HYPERVISOR", "qemu:///system")}
# Security-relevant contract sections are pinned by SHA-256 of canonical JSON
# (sorted keys, no whitespace). Any edit, weakening or not, fails until the
# checker is updated in a reviewed change (review N1). Regenerate with
# `python3 tools/check_interfaces.py --print-pins`.
PINNED_SECTIONS = {
    "errors.categories":
        "a4898076a81d23defebaecde7d9f0f73057b2b019a8e9c5f35f222e23c67d785",
    "prohibited.categories":
        "fde7db0ad78372837fc84bcbd398e153314e7faeec8a04dc8bf9549b31a19570",
    "prohibited.redaction.key_substrings":
        "e345ee00860d558c374286b0f269929a5df6f4bec8efd163e29113efbb1ac721",
    "request-schemas.categories":
        "2983c495b00b766482702ac73170826f35c94036ea4fedaeb6ecff4911f02679",
    "request-schemas.value_types":
        "978c4121daba96af9dde165f9267833011a77d0b051a3ea068cad83a76a8ce2e",
    "resources.resources":
        "b704d4f139d9626dd2ef23d58e9090c6d05dec78b367844a5b90cb1c67ead010",
    "resources.operation_status":
        "07438e921bfc0f2fe39de94dc2023547c589ba994504e1b71ad563e625df06b1",
    "resources.operation_persisted_fields":
        "0427ad0b1e53001c00319836b690da4e3c9a96c524b66e4eb7513d82f8c32a14",
    "failure-matrix.rows.structured":
        "d38a7b49baf737d700b3ac065d4720134bb74d3d8a009a9f926031ac9207a2d7",
}
MAX_FIXTURE_BYTES = 65536
MAX_DEPTH = 32


def normalize(text):
    """NFKC, case-fold, drop format/zero-width characters, '-' and spaces to '_'."""
    text = unicodedata.normalize("NFKC", str(text))
    text = "".join(ch for ch in text if unicodedata.category(ch) != "Cf")
    return re.sub(r"[\s\-]+", "_", text.strip().casefold())


class Contracts:
    def __init__(self, data):
        self.errors = data["errors"]
        self.inventory = data["inventory"]
        self.resources = data["resources"]
        self.prohibited = data["prohibited"]
        self.failures = data["failure-matrix"]
        self.schemas = data["request-schemas"]


def reject_duplicates(pairs):
    """object_pairs_hook rejecting duplicate keys (review N5)."""
    keys = [k for k, _ in pairs]
    if len(keys) != len(set(keys)):
        raise ValueError("duplicate JSON key")
    return dict(pairs)


def loads(text):
    return json.loads(text, object_pairs_hook=reject_duplicates)


def section(data, name):
    file, _, path = name.partition(".")
    value = data[file]
    if path == "rows.structured":
        return {row: {k: v for k, v in as_dict(spec).items()
                      if k in ("durable_state_owner", "caller_visible_error", "recovery_story", "recovery_implemented")}
                for row, spec in as_dict(value.get("rows")).items()}
    for part in path.split("."):
        value = as_dict(value).get(part)
    return value


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
                                     ensure_ascii=False).encode()).hexdigest()


def load_contracts(directory):
    data, findings = {}, []
    for name in CONTRACT_FILES:
        path = Path(directory) / ("%s.json" % name)
        try:
            value = loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError, RecursionError) as exc:
            findings.append(("CONTRACT_INVALID", name, "cannot load: %s" % exc.__class__.__name__))
            continue
        if not isinstance(value, dict) or type(value.get("schema")) is not int or value.get("schema") != 1:
            findings.append(("CONTRACT_INVALID", name, "must be an object with schema 1"))
            continue
        data[name] = value
    return (data if not findings else None), findings


def is_text(value):
    return isinstance(value, str) and value.strip() != ""


def as_dict(value):
    return value if isinstance(value, dict) else {}


def check_contracts(data):
    """Return typed findings; malformed structures become CONTRACT_INVALID, never a crash."""
    try:
        return _check_contracts(data)
    except (TypeError, AttributeError, KeyError, ValueError, RecursionError) as exc:
        return [("CONTRACT_INVALID", "structure", "malformed contract structure: %s" % exc.__class__.__name__)]


def _check_contracts(data):
    findings = []
    errors = data["errors"].get("categories")
    if not isinstance(errors, dict) or not errors:
        return [("CONTRACT_INVALID", "errors", "categories must be a non-empty object")]
    for name, spec in errors.items():
        spec = as_dict(spec)
        if not (type(spec.get("http_status")) is int and type(spec.get("retryable")) is bool
                and is_text(spec.get("description"))):
            findings.append(("FIELD_MISSING", "errors." + name, "needs http_status, retryable, description"))

    inv = data["inventory"]
    if inv.get("auth_design_approved") is not AUTH_DESIGN_APPROVED:
        findings.append(("SECURITY_WEAKENED", "inventory.auth_design_approved",
                         "must be %s until an approved auth-design story changes the checker" % AUTH_DESIGN_APPROVED))
    boundaries = inv.get("boundaries")
    if not isinstance(boundaries, dict):
        return findings + [("CONTRACT_INVALID", "inventory", "boundaries must be an object")]
    for name in sorted(set(boundaries) - set(BOUNDARIES)):
        findings.append(("BOUNDARY_UNKNOWN", name, "boundary not in the approved architecture"))
    for name in sorted(set(BOUNDARIES) - set(boundaries)):
        findings.append(("BOUNDARY_MISSING", name, "required boundary not declared"))
    for name in sorted(set(boundaries) & set(BOUNDARIES)):
        spec, pinned = as_dict(boundaries[name]), BOUNDARIES[name]
        for field in BOUNDARY_TEXT_FIELDS:
            if not is_text(spec.get(field)):
                findings.append(("FIELD_MISSING", "%s.%s" % (name, field), "required non-empty text"))
        if spec.get("security") != pinned["security"]:
            findings.append(("SECURITY_WEAKENED", name, "security properties must equal %s" % pinned["security"]))
        cats = spec.get("permitted_request_categories")
        if not isinstance(cats, list) or set(cats) != pinned["categories"] or len(cats) != len(set(cats)):
            findings.append(("SECURITY_WEAKENED", name, "permitted categories must be exactly %s"
                             % sorted(pinned["categories"])))
        ecats = spec.get("error_categories")
        if not isinstance(ecats, list) or not ecats:
            findings.append(("FIELD_MISSING", name + ".error_categories", "required list"))
        else:
            for category in ecats:
                if not isinstance(category, str) or category not in errors:
                    findings.append(("ERROR_UNDEFINED", name, "error category %r not in errors.json" % (category,)))
        if spec.get("implementation_status") != pinned["status"]:
            findings.append(("IMPLEMENTATION_CLAIM", name, "implementation_status must be %s" % pinned["status"]))
        if spec.get("implemented_requests") != pinned["implemented"]:
            findings.append(("IMPLEMENTATION_CLAIM", name, "implemented requests must be %s" % pinned["implemented"]))

    res_doc = data["resources"]
    if res_doc.get("store_writer") != STORE_WRITER:
        findings.append(("SECURITY_WEAKENED", "resources.store_writer", "ADR-003: single store writer must be %s"
                         % STORE_WRITER))
    res = res_doc.get("resources")
    if not isinstance(res, dict):
        return findings + [("CONTRACT_INVALID", "resources", "resources must be an object")]
    for name in sorted(set(res) - set(RESOURCES)):
        findings.append(("RESOURCE_UNKNOWN", name, "resource not in the architecture"))
    for name in sorted(set(RESOURCES) - set(res)):
        findings.append(("RESOURCE_MISSING", name, "required resource not declared"))
    for name in sorted(set(res) & set(RESOURCES)):
        spec = as_dict(res[name])
        if spec.get("ownership_scope") != RESOURCES[name]:
            findings.append(("FIELD_MISSING", name + ".ownership_scope", "must be %s" % RESOURCES[name]))
        if spec.get("desired_state_source") not in DESIRED_SOURCES:
            findings.append(("FIELD_MISSING", name + ".desired_state_source", "must be one of %s" % sorted(DESIRED_SOURCES)))
        if spec.get("observed_state_reporter") not in OBSERVED_REPORTERS:
            findings.append(("FIELD_MISSING", name + ".observed_state_reporter", "must be one of %s"
                             % sorted(OBSERVED_REPORTERS)))
        if type(spec.get("generation_tracking")) is not bool:
            findings.append(("FIELD_MISSING", name + ".generation_tracking", "must be boolean"))
        extra = set(spec) - {"ownership_scope", "desired_state_source", "observed_state_reporter", "generation_tracking"}
        if extra:
            findings.append(("CONTRACT_INVALID", name, "unknown resource fields %s" % sorted(extra)))
    op_status = res_doc.get("operation_status")
    if not isinstance(op_status, dict) or not op_status:
        findings.append(("FIELD_MISSING", "operation_status", "required"))
    else:
        for name, spec in op_status.items():
            spec = as_dict(spec)
            if type(spec.get("terminal")) is not bool or type(spec.get("retryable")) is not bool:
                findings.append(("FIELD_MISSING", "operation_status." + name, "needs terminal and retryable booleans"))
        if not any(as_dict(s).get("terminal") is True for s in op_status.values()):
            findings.append(("FIELD_MISSING", "operation_status", "needs at least one terminal status"))
    persisted = res_doc.get("operation_persisted_fields")
    persisted = set(persisted) if isinstance(persisted, list) and all(isinstance(x, str) for x in persisted) else set()
    for field in sorted(REQUIRED_OPERATION_FIELDS - persisted):
        findings.append(("FIELD_MISSING", "operation_persisted_fields", "missing %s" % field))

    pro = data["prohibited"]
    cats = pro.get("categories")
    if not isinstance(cats, dict) or set(cats) != PROHIBITED_CODES:
        findings.append(("CONTRACT_INVALID", "prohibited", "categories must be exactly %s" % sorted(PROHIBITED_CODES)))
    else:
        for code in ("ARBITRARY_SHELL", "PROVIDER_CREDENTIALS"):
            tokens = as_dict(cats[code]).get("tokens")
            if not isinstance(tokens, list) or not tokens or not all(is_text(t) for t in tokens):
                findings.append(("CONTRACT_INVALID", "prohibited." + code, "tokens must be a non-empty list"))
        for code in ("AGENT_TCP", "REMOTE_HYPERVISOR"):
            allowed = as_dict(cats[code]).get("allowed_transports")
            if not isinstance(allowed, list) or not allowed:
                findings.append(("CONTRACT_INVALID", "prohibited." + code, "allowed_transports required"))
        try:
            re.compile(str(as_dict(cats["HYPERVISOR_XML"]).get("pattern", "")))
        except re.error:
            findings.append(("CONTRACT_INVALID", "prohibited.HYPERVISOR_XML", "invalid pattern"))
        if not as_dict(cats["HYPERVISOR_XML"]).get("pattern"):
            findings.append(("CONTRACT_INVALID", "prohibited.HYPERVISOR_XML", "pattern required"))
    subs = as_dict(pro.get("redaction")).get("key_substrings")
    if not isinstance(subs, list) or not subs or not all(is_text(s) for s in subs):
        findings.append(("FIELD_MISSING", "prohibited.redaction.key_substrings", "required list"))
    elif isinstance(cats, dict) and "PROVIDER_CREDENTIALS" in cats:
        missing = [t for t in as_dict(cats["PROVIDER_CREDENTIALS"]).get("tokens") or []
                   if not any(normalize(s) in normalize(t) for s in subs)]
        if missing:
            findings.append(("SECURITY_WEAKENED", "prohibited.redaction", "credential tokens not redacted: %s" % missing))

    schemas = data["request-schemas"]
    types = schemas.get("value_types")
    if not isinstance(types, dict) or set(types) != {"id", "digest", "limit", "cursor", "username", "password"}:
        findings.append(("CONTRACT_INVALID", "request-schemas", "value_types must be exactly id, digest, limit, cursor, username and password"))
    else:
        for name, pattern in types.items():
            try:
                re.compile(pattern)
            except (re.error, TypeError):
                findings.append(("CONTRACT_INVALID", "request-schemas", "invalid value_types.%s" % name))
    sc = schemas.get("categories")
    all_categories = set().union(*(b["categories"] for b in BOUNDARIES.values()))
    if not isinstance(sc, dict) or set(sc) != all_categories:
        findings.append(("CONTRACT_INVALID", "request-schemas", "categories must be exactly %s" % sorted(all_categories)))

    rows = data["failure-matrix"].get("rows")
    if not isinstance(rows, dict):
        return findings + [("CONTRACT_INVALID", "failure-matrix", "rows must be an object")]
    for name in sorted(set(rows) - ROWS):
        findings.append(("ROW_UNKNOWN", name, "unexpected failure row"))
    for name in sorted(ROWS - set(rows)):
        findings.append(("ROW_MISSING", name, "required failure row"))
    for name in sorted(set(rows) & ROWS):
        spec = as_dict(rows[name])
        for field in ROW_FIELDS:
            if field not in spec or (field != "recovery_implemented" and not is_text(spec[field])):
                findings.append(("FIELD_MISSING", "%s.%s" % (name, field), "required"))
        if spec.get("durable_state_owner") != STORE_WRITER:
            findings.append(("SECURITY_WEAKENED", name, "durable state owner must be the single writer %s" % STORE_WRITER))
        if not isinstance(spec.get("caller_visible_error"), str) or spec.get("caller_visible_error") not in errors:
            findings.append(("ERROR_UNDEFINED", name, "caller_visible_error not in errors.json"))
        if spec.get("recovery_story") != "M0-E02-S07":
            findings.append(("FIELD_MISSING", name + ".recovery_story", "must be M0-E02-S07 (DR-002)"))
        if spec.get("recovery_implemented") is not False:
            findings.append(("RECOVERY_CLAIM", name, "this story implements no recovery; recovery_implemented must be false"))
    for name, expected in PINNED_SECTIONS.items():
        if digest(section(data, name)) != expected:
            findings.append(("SECURITY_WEAKENED", name, "differs from the content pinned in the checker"))
    return findings


def walk(value, depth=0):
    """Yield ("key", text) and ("value", text) pairs recursively; ValueError when too deep."""
    if depth > MAX_DEPTH:
        raise ValueError("too deep")
    if isinstance(value, dict):
        for key, item in value.items():
            yield "key", str(key)
            yield from walk(item, depth + 1)
    elif isinstance(value, list):
        for item in value:
            yield from walk(item, depth + 1)
    elif isinstance(value, str):
        yield "value", value


def classify_request(contracts, request):
    """Return the sorted list of codes a request triggers (empty means accepted).

    Uses only contract sections whose content is pinned by the checker.
    """
    if not isinstance(request, dict):
        return ["SCHEMA_VIOLATION"]
    cats, inv = contracts.prohibited["categories"], contracts.inventory
    codes = set()
    boundary = request.get("boundary")
    if not isinstance(boundary, str) or boundary not in BOUNDARIES:
        return ["BOUNDARY_UNKNOWN"]
    category = request.get("category")
    if not isinstance(category, str):
        return ["SCHEMA_VIOLATION"]
    if set(request) - REQUEST_KEYS:
        codes.add("SCHEMA_VIOLATION")
    if category not in BOUNDARIES[boundary]["categories"]:
        codes.add("CATEGORY_NOT_PERMITTED")
    if category not in UNAUTHENTICATED_CATEGORIES and inv.get("auth_design_approved") is not True:
        codes.add("PRIVILEGED_BEFORE_AUTH")
    if boundary in TRANSPORTS:
        code, allowed = TRANSPORTS[boundary]
        if request.get("transport") != allowed:
            codes.add(code)
    elif "transport" in request:
        codes.add("SCHEMA_VIOLATION")
    # Allowlisted schema: exact keys; each value matches its type or enumeration.
    payload = request.get("payload", {})
    schema = contracts.schemas["categories"].get(category)
    types = contracts.schemas["value_types"]
    optional = OPTIONAL_KEYS.get(category, set())
    if not isinstance(payload, dict) or not isinstance(schema, dict) \
            or not (set(schema) - optional) <= set(payload) <= set(schema):
        codes.add("SCHEMA_VIOLATION")
    else:
        for key, rule in schema.items():
            if key not in payload:
                continue
            value = payload[key]
            ok = isinstance(value, str) and (value in rule if isinstance(rule, list)
                                             else re.fullmatch(types[rule], value) is not None)
            if not ok:
                codes.add("SCHEMA_VIOLATION")
    # Defence in depth over the whole request except routing fields.
    shell = [normalize(t) for t in cats["ARBITRARY_SHELL"]["tokens"]]
    creds = [normalize(t) for t in cats["PROVIDER_CREDENTIALS"]["tokens"]]
    xml = re.compile(cats["HYPERVISOR_XML"]["pattern"], re.I)
    try:
        for kind, text in walk({k: v for k, v in request.items() if k not in ("boundary", "category")}):
            norm = normalize(text)
            if kind == "key":
                if any(t in norm for t in shell):
                    codes.add("ARBITRARY_SHELL")
                if any(t in norm for t in creds):
                    codes.add("PROVIDER_CREDENTIALS")
            if xml.search(norm) or xml.search(text):
                codes.add("HYPERVISOR_XML")
    except ValueError:
        codes.add("SCHEMA_VIOLATION")
    return sorted(codes)


def redact(contracts, value, depth=0):
    """Return a copy of value with secret-bearing keys replaced by [REDACTED]."""
    subs = [normalize(s) for s in contracts.prohibited["redaction"]["key_substrings"]]
    if depth > MAX_DEPTH:
        return "[REDACTED]"
    if isinstance(value, dict):
        return {k: "[REDACTED]" if any(s in normalize(k) for s in subs) else redact(contracts, v, depth + 1)
                for k, v in value.items()}
    if isinstance(value, list):
        return [redact(contracts, v, depth + 1) for v in value]
    return value


def check_fixtures(contracts, directory):
    findings, covered = [], set()
    paths = sorted(Path(directory).glob("*/*.json"))
    if not paths:
        return [("FIXTURE_MISSING", str(directory), "no fixtures found")]
    for path in paths:
        label = "%s/%s" % (path.parent.name, path.name)
        try:
            if path.stat().st_size > MAX_FIXTURE_BYTES:
                findings.append(("FIXTURE_INVALID", label, "exceeds %d bytes" % MAX_FIXTURE_BYTES))
                continue
            fixture = loads(path.read_text(encoding="utf-8"))
            expect = fixture["expect"]
            request = fixture["request"]
            if not isinstance(expect, list) or not all(isinstance(e, str) for e in expect):
                raise TypeError("expect must be a list of codes")
            expect = sorted(expect)
        except (OSError, ValueError, KeyError, TypeError, RecursionError):
            findings.append(("FIXTURE_INVALID", label, "needs request and expect; no duplicate keys"))
            continue
        if (path.parent.name == "positive") != (expect == []):
            findings.append(("FIXTURE_INVALID", label, "positive fixtures expect [], negative fixtures expect codes"))
        try:
            actual = classify_request(contracts, request)
        except (TypeError, ValueError, KeyError, AttributeError, RecursionError) as exc:
            findings.append(("FIXTURE_INVALID", label, "unclassifiable request: %s" % exc.__class__.__name__))
            continue
        if actual != expect:
            findings.append(("FIXTURE_MISMATCH", label, "expected %s, got %s" % (expect, actual)))
        if path.parent.name == "negative":
            covered.update(expect)
    # Draft/approved AC02: at least one negative fixture per prohibited code (review R2).
    for code in sorted(PROHIBITED_CODES - covered):
        findings.append(("FIXTURE_MISSING", code, "no negative fixture expects this prohibited code"))
    return findings


def main(argv=None):
    parser = argparse.ArgumentParser(description="Check interface contracts (M0-E01-S01 draft).")
    parser.add_argument("--contracts", default=str(ROOT / "contracts" / "interfaces"))
    parser.add_argument("--fixtures", default=str(ROOT / "tests" / "fixtures" / "interfaces"))
    parser.add_argument("--print-pins", action="store_true", help="print digests of pinned sections")
    args = parser.parse_args(argv)
    if args.print_pins:
        data, findings = load_contracts(args.contracts)
        if data is None:
            print("ERROR cannot load contracts")
            return 2
        for name in PINNED_SECTIONS:
            try:
                value = digest(section(data, name))
            except (UnicodeError, TypeError, ValueError) as exc:
                print("ERROR cannot digest %s: %s" % (name, exc.__class__.__name__))
                return 2
            print('    "%s":\n        "%s",' % (name, value))
        return 0
    if not Path(args.contracts).is_dir():
        print("ERROR USAGE: contracts directory not found")
        return 2
    data, findings = load_contracts(args.contracts)
    if data is not None:
        findings = check_contracts(data)
        if not findings:
            findings = check_fixtures(Contracts(data), args.fixtures)
    for code, subject, message in findings:
        print("ERROR %s %s: %s" % (code, subject, message))
    if findings:
        return 1
    print("OK interfaces: contracts and fixtures valid")
    return 0


if __name__ == "__main__":
    sys.exit(main())
