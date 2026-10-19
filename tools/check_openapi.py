#!/usr/bin/env python3
"""OpenAPI schema-first checker (story M0-E01-S04; DR-012; refinement M0-E01-S04 sections 1, 2 and 5).

contracts/openapi.yaml is the single machine-checked source of the browser-api shapes: the typed error envelope,
every resource shape, the Operation shape, `allowed_actions` and the path/versioning convention. This tool pins it
against the existing contracts (errors, inventory, resources, request-schemas: M0-E01-S01; data-classes: M0-E01-S02)
and against a compatibility baseline (contracts/openapi-baseline.json).

Expectations that must not be weakened by editing a contract file are pinned in this module (the S01 pattern).

Read-only: writes nothing (no bytecode, no files). Standard library plus the PyYAML already pinned in the image.
Exit codes: 0 no findings, 1 findings, 2 usage or environment error.
"""
import argparse
import hashlib
import importlib.util
import json
import re
import sys
from pathlib import Path

sys.dont_write_bytecode = True

ROOT = Path(__file__).resolve().parents[1]
SPEC_FILE = "contracts/openapi.yaml"
BASELINE_FILE = "contracts/openapi-baseline.json"
DEPS_FILE = "contracts/decision-deps.json"
LOCK_FILE = "docs-lock.json"
CONTRACT_DIR = "contracts/interfaces"
DATA_CLASSES_FILE = "contracts/threats/data-classes.json"
STORY_ID = "M0-E01-S04"
MAX_SPEC_BYTES = 2 << 20
MAX_JSON_BYTES = 1 << 20
MAX_DEPTH = 24

KINDS = ["Host", "Project", "VM", "Volume", "VirtualNetwork", "Image", "Backup", "App", "Operation", "Event"]
COLLECTION = {"Host": "hosts", "Project": "projects", "VM": "vms", "Volume": "volumes",
              "VirtualNetwork": "virtual-networks", "Image": "images", "Backup": "backups", "App": "apps",
              "Operation": "operations", "Event": "events"}
SUBMIT_KINDS = ["VM", "Volume", "VirtualNetwork", "Image", "Backup", "App"]
# Section 1.5: action ids valid per item kind; `create` only on collections of a submit_operation kind.
# DR-020 (M2): resize, reinstall, snapshot and backup join the VM actions; a Backup can also be restored.
ITEM_ACTIONS = {"VM": {"start", "stop", "reboot", "force_off", "delete", "resize", "reinstall", "snapshot", "backup", "compute", "reserve_ip", "release_ip", "eject_iso", "set_schedule", "clear_schedule", "graphics_enable", "iso_attach", "rescue", "unrescue"}, "App": {"start", "stop", "delete"}, "Volume": {"attach", "detach", "delete"},
                "VirtualNetwork": {"start", "stop", "delete", "enable_autostart", "disable_autostart"}, "Image": {"delete"}, "Backup": {"restore", "delete", "export"}, "Operation": {"cancel"},
                "Host": set(), "Project": set(), "Event": {"acknowledge"}}
# Section 1.3 table: the extra properties and the desired/observed leaves of every kind except Operation and Event.
# leaf: (set of JSON types, closed enum or None)
_B, _S, _I = {"boolean"}, {"string"}, {"integer"}


def _e(*values):
    return (_S, set(values))


DESIRED_OBSERVED = {
    "Host": ({"maintenance": (_B, None)},
             {"reachable": (_B, None), "agent_version": (_S, None), "cpu_count": (_I, None), "memory_mib": (_I, None),
              "capability_verdict": _e("supported", "unsupported", "unknown"),
              # DR-015 D3: the only approved additions to Host.observed (nested shapes pinned in check_host_extension).
              "virtualization": ({"object"}, None), "distribution": ({"object"}, None),
              "capability_findings": ({"array"}, None),
              "creation": ({"object"}, None),  # DR-016: pinned in check_host_extension
              "storage": ({"object"}, None),  # DR-020: pinned in check_host_extension
              "usage": ({"object"}, None),  # DR-022: sampled CPU and memory with a bounded history, pinned in check_host_extension
              "alerts": ({"object"}, None), "nightly_boot": ({"object", "null"}, None), "bridge": ({"object", "null"}, None)}),  # DR-024 D2, D4, D5
    "Project": ({}, {}),
    "VM": ({"power": _e("running", "stopped"), "backup_schedule": ({"object", "null"}, None)},  # DR-024 D3
           
           {"power": _e("running", "stopped", "paused", "crashed", "unknown"), "last_seen_at": (_S, None),
            # DR-016: ownership, an observed DHCP lease and the image's login user
            "managed": (_B, None), "ip_address": ({"string", "null"}, None), "login_user": ({"string", "null"}, None),
            # DR-023 D3: the installation media attached now
            "iso": ({"string", "null"}, None),
            # DR-020: the root disk's virtual size and the VM's own snapshots (pinned in check_vm_extension)
            "disk_gib": ({"integer", "null"}, None), "snapshots": ({"array"}, None),
            # DR-021 (M3): the VM's network (pinned in check_vm_extension)
            "network": ({"object", "null"}, None),
            # DR-022: the configured size and sampled CPU use (pinned in check_vm_extension)
            "vcpus": ({"integer", "null"}, None), "memory_mib": ({"integer", "null"}, None), "usage": ({"object"}, None),
            "backup": ({"object"}, None),  # DR-024 D3
            "graphical_console": (_S, {"absent", "present"}), "rescue": (_B, None)}),  # DR-026 D1, D2
    "Volume": ({"size_gib": (_I, None), "attached_to": ({"string", "null"}, None)},
               {"state": _e("available", "attached", "error", "unknown")}),
    # DR-021 (M3): managed vs foreign networks with their addressing (nested shapes pinned in check_network_extension)
    "VirtualNetwork": ({"mode": _e("nat", "route", "bridge", "open", "isolated", "other"), "autostart": (_B, None)},
                       {"state": _e("active", "inactive", "unknown"), "managed": (_B, None), "bridge": ({"string", "null"}, None),
                        "subnet": ({"string", "null"}, None), "gateway": ({"string", "null"}, None), "dhcp_start": ({"string", "null"}, None),
                        "dhcp_end": ({"string", "null"}, None), "attached_vms": (_I, None), "reservations": ({"array"}, None)}),
    "Image": ({"source_digest": (_S, None)},
              {"state": _e("available", "verifying", "failed"), "distribution": (_S, None), "version": (_S, None),
               "architecture": _e("x86_64"), "login_user": ({"string", "null"}, None), "min_disk_gib": (_I, None),
               # DR-023 D3: cloud image or installation media
               "media": _e("disk", "iso"),
               # DR-017: separate registered / verified / qualified claims (disabled images are never shown)
               "qualification": _e("registered", "verified", "qualified"),
               # DR-020: the operator-recorded qualification evidence reference (null unless qualified)
               "qualification_evidence": ({"string", "null"}, None)}),
    "Backup": ({"source_volume_id": (_S, None)}, {"state": _e("pending", "complete", "failed"), "copies": ({"array"}, None)}),  # DR-023 D4: off-host copies
    "App": ({"image_digest": (_S, None)}, {"state": _e("running", "stopped", "failed")}),
}
EVENT_PROPS = {"id", "project_id", "type", "resource_kind", "resource_id", "severity", "state", "value", "created_at", "updated_at", "allowed_actions"}  # DR-024 D2: an alert
FIELD_ERROR_CODES = {"required", "unknown_field", "type", "pattern", "enum", "too_long"}
CORRELATION_PATTERN = "^[A-Za-z0-9-]{8,64}$"
SECURITY_SCHEME = "ownerSession"
SECRET_CLASSES = {"secret", "credential"}
BASELINE_KEYS = {"schema", "decision", "schema_digest"}

# (method, path) -> (category, success status, success schema, parameter names, has body)
PATHS = {("get", "/healthz"): ("health", "200", "Health", (), False)}
# DR-015 D3: the authentication session. Reachable without a session by design (status, sign-in) or idempotent
# (sign-out); the session itself is the credential, enforced by the handler, so these declare `security: []`.
PATHS[("get", "/api/v1/auth/session")] = ("auth_status", "200", "AuthSession", (), False)
PATHS[("post", "/api/v1/auth/session")] = ("sign_in", "200", "AuthSession", (), "SignInRequest")
PATHS[("delete", "/api/v1/auth/session")] = ("sign_out", "200", "AuthSession", (), False)
ANONYMOUS_CATEGORIES = {"health", "auth_status", "sign_in", "sign_out"}
NO_401_CATEGORIES = {"health", "auth_status", "sign_out"}
for _k in KINDS:
    PATHS[("get", "/api/v1/%s" % COLLECTION[_k])] = ("list_resources", "200", _k + "List", ("Limit", "Cursor"), False)
    PATHS[("get", "/api/v1/%s/{id}" % COLLECTION[_k])] = ("read_resource", "200", _k, ("Id",), False)
PATHS[("post", "/api/v1/operations")] = ("submit_operation", "202", "Operation", (), "SubmitOperationRequest")
PATHS[("post", "/api/v1/operations/{id}/cancel")] = ("cancel_operation", "200", "Operation", ("Id",), False)
METHODS = {"get", "put", "post", "delete", "options", "head", "patch", "trace"}

SCHEMA_KEYWORDS = {"type", "enum", "const", "pattern", "format", "minLength", "maxLength", "minimum", "maximum",
                   "required", "properties", "additionalProperties", "items", "minItems", "maxItems", "uniqueItems",
                   "oneOf", "$ref", "description", "x-data-class", "x-http-status"}
JSON_TYPES = {"object", "array", "string", "integer", "boolean", "null"}
OPERATION_KEYS = {"operationId", "x-request-category", "x-implementation-status", "security", "parameters", "requestBody",
                  "responses"}
RESPONSE_KEYS = {"description", "content", "x-error-category", "$ref"}
TOP_KEYS = {"openapi", "info", "x-versioning", "paths", "components"}
COMPONENT_KEYS = {"securitySchemes", "parameters", "responses", "schemas"}
REF_RE = re.compile(r"#/components/(schemas|responses|parameters)/([A-Za-z0-9]+)")


class EnvError(Exception):
    """Usage or environment failure; exit code 2."""


class Structure(Exception):
    """The document leaves the allowed OpenAPI subset (SCHEMA_STRUCTURE)."""


# ---- loading ---------------------------------------------------------------------------------------------------------
def load_yaml(raw):
    """Parse YAML safely: bounded size, no anchors or aliases, no duplicate keys, plain data only."""
    import yaml  # PyYAML is pinned in the dev image (toolchain/requirements-ci-policy.txt)

    if len(raw) > MAX_SPEC_BYTES:
        raise Structure("document larger than %d bytes" % MAX_SPEC_BYTES)
    text = raw.decode("utf-8")
    for event in yaml.parse(text, Loader=yaml.SafeLoader):
        if isinstance(event, yaml.AliasEvent) or getattr(event, "anchor", None) is not None:
            raise Structure("YAML anchors and aliases are not allowed")

    class Loader(yaml.SafeLoader):
        pass

    def mapping(loader, node, deep=False):
        keys = [loader.construct_object(k, deep=True) for k, _ in node.value]
        if len(keys) != len(set(map(repr, keys))):
            raise Structure("duplicate key")
        return yaml.SafeLoader.construct_mapping(loader, node, deep)

    Loader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, mapping)
    try:
        return yaml.load(text, Loader=Loader)  # nosec B506: restricted SafeLoader subclass
    except yaml.YAMLError as exc:
        raise Structure("invalid YAML: %s" % exc.__class__.__name__) from None


def load_json_bytes(raw, label):
    if len(raw) > MAX_JSON_BYTES:
        raise EnvError("%s larger than %d bytes" % (label, MAX_JSON_BYTES))

    def pairs(items):
        keys = [k for k, _ in items]
        if len(keys) != len(set(keys)):
            raise ValueError("duplicate JSON key")
        return dict(items)

    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=pairs)
    except (UnicodeDecodeError, ValueError, RecursionError):
        raise EnvError("%s is not valid JSON" % label) from None


def load_contracts(root):
    root = Path(root)
    data = {}
    for name in ("errors", "inventory", "resources", "request-schemas"):
        data[name] = load_json_bytes(_read(root / CONTRACT_DIR / (name + ".json")), name)
    data["data-classes"] = load_json_bytes(_read(root / DATA_CLASSES_FILE), "data-classes")
    return data


def _read(path):
    try:
        return Path(path).read_bytes()
    except OSError as exc:
        raise EnvError("cannot read %s: %s" % (path, exc.strerror)) from None


# ---- helpers ---------------------------------------------------------------------------------------------------------
def as_dict(v):
    return v if isinstance(v, dict) else {}


def types_of(node):
    t = as_dict(node).get("type")
    return set(t) if isinstance(t, list) else ({t} if isinstance(t, str) else set())


def resolve(spec, node, kinds=("schemas", "responses", "parameters")):
    """Follow a single $ref (only #/components/{schemas,responses,parameters}/Name); return (name, target)."""
    if not isinstance(node, dict) or "$ref" not in node:
        return None, node
    ref = node["$ref"]
    m = REF_RE.fullmatch(ref) if isinstance(ref, str) else None
    if not m or m.group(1) not in kinds:
        raise Structure("unsupported $ref %r" % (ref if isinstance(ref, str) else "?"))
    target = as_dict(as_dict(spec.get("components")).get(m.group(1))).get(m.group(2))
    if target is None:
        raise Structure("unresolved $ref %s" % ref)
    return m.group(2), target


def ref_name(node):
    ref = as_dict(node).get("$ref")
    m = REF_RE.fullmatch(ref) if isinstance(ref, str) else None
    return m.group(2) if m else None


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()


# ---- structure: the allowed OpenAPI subset ---------------------------------------------------------------------------
def check_subset(spec):
    out = []

    def bad(where, msg):
        out.append(("SCHEMA_STRUCTURE", where, msg))

    if not isinstance(spec, dict):
        return [("SCHEMA_STRUCTURE", "document", "must be a mapping")]
    if set(spec) - TOP_KEYS or TOP_KEYS - set(spec):
        bad("document", "top-level keys must be exactly %s" % sorted(TOP_KEYS))
    if spec.get("openapi") != "3.1.0":
        bad("openapi", "must be 3.1.0")
    info = as_dict(spec.get("info"))
    if set(info) - {"title", "version", "description"} or not {"title", "version"} <= set(info):
        bad("info", "title and version are required; only title, version, description are allowed")
    comps = as_dict(spec.get("components"))
    if set(comps) - COMPONENT_KEYS or COMPONENT_KEYS - set(comps):
        bad("components", "must be exactly %s" % sorted(COMPONENT_KEYS))
    paths = spec.get("paths")
    if not isinstance(paths, dict):
        return out + [("SCHEMA_STRUCTURE", "paths", "must be a mapping")]
    for path, item in paths.items():
        if not isinstance(path, str) or not isinstance(item, dict):
            bad("paths", "path item must be a mapping")
            continue
        for method, op in item.items():
            where = "%s %s" % (str(method).upper(), path)
            if method not in METHODS:
                bad(where, "unsupported path-item key")
                continue
            if not isinstance(op, dict) or set(op) - OPERATION_KEYS:
                bad(where, "operation keys must be within %s" % sorted(OPERATION_KEYS))
                continue
            for key in ("operationId", "x-request-category", "x-implementation-status", "security", "responses"):
                if key not in op:
                    bad(where, "missing %s" % key)
            if not isinstance(op.get("responses"), dict):
                bad(where, "responses must be a mapping")
                continue
            for status, resp in op["responses"].items():
                if not isinstance(status, str):
                    bad(where, "response keys must be quoted strings")
                elif not isinstance(resp, dict) or set(resp) - {"$ref", "description", "content"}:
                    bad(where + " " + str(status), "response keys must be within $ref, description, content")
    for name, resp in as_dict(comps.get("responses")).items():
        if not isinstance(resp, dict) or set(resp) - RESPONSE_KEYS:
            bad("components.responses." + str(name), "unsupported keys")
    for name, schema in as_dict(comps.get("schemas")).items():
        _schema_subset(schema, "components.schemas." + str(name), out, 0)
    for name, param in as_dict(comps.get("parameters")).items():
        if not isinstance(param, dict) or set(param) - {"name", "in", "required", "schema"}:
            bad("components.parameters." + str(name), "unsupported keys")
        else:
            _schema_subset(param.get("schema"), "components.parameters.%s.schema" % name, out, 0)
    return out


def _schema_subset(node, where, out, depth):
    if depth > MAX_DEPTH:
        out.append(("SCHEMA_STRUCTURE", where, "nesting too deep"))
        return
    if not isinstance(node, dict):
        out.append(("SCHEMA_STRUCTURE", where, "schema must be a mapping"))
        return
    extra = set(node) - SCHEMA_KEYWORDS
    if extra:
        out.append(("SCHEMA_STRUCTURE", where, "keyword(s) outside the allowed subset: %s" % sorted(map(str, extra))))
    t = node.get("type")
    if t is not None and not (isinstance(t, str) and t in JSON_TYPES
                              or isinstance(t, list) and t and all(isinstance(x, str) and x in JSON_TYPES for x in t)):
        out.append(("SCHEMA_STRUCTURE", where, "invalid type"))
    if "enum" in node and not (isinstance(node["enum"], list) and node["enum"]):
        out.append(("SCHEMA_STRUCTURE", where, "enum must be a non-empty list"))
    if "$ref" in node and not (isinstance(node["$ref"], str) and REF_RE.fullmatch(node["$ref"])):
        out.append(("SCHEMA_STRUCTURE", where, "unsupported $ref"))
    if "properties" in node:
        if not isinstance(node["properties"], dict):
            out.append(("SCHEMA_STRUCTURE", where, "properties must be a mapping"))
        else:
            for pn, pv in node["properties"].items():
                _schema_subset(pv, "%s.%s" % (where, pn), out, depth + 1)
    if "items" in node:
        _schema_subset(node["items"], where + "[]", out, depth + 1)
    if "oneOf" in node:
        if not isinstance(node["oneOf"], list):
            out.append(("SCHEMA_STRUCTURE", where, "oneOf must be a list"))
        else:
            for i, branch in enumerate(node["oneOf"]):
                _schema_subset(branch, "%s.oneOf[%d]" % (where, i), out, depth + 1)
    if "required" in node and not (isinstance(node["required"], list) and all(isinstance(x, str) for x in node["required"])):
        out.append(("SCHEMA_STRUCTURE", where, "required must be a list of names"))


# ---- semantic checks -------------------------------------------------------------------------------------------------
def schemas_of(spec):
    return as_dict(as_dict(spec.get("components")).get("schemas"))


def walk_objects(node, where, depth=0):
    """Yield (where, schema) for every nested schema except oneOf constraint branches."""
    if depth > MAX_DEPTH or not isinstance(node, dict):
        return
    yield where, node
    for pn, pv in as_dict(node.get("properties")).items():
        yield from walk_objects(pv, "%s.%s" % (where, pn), depth + 1)
    if "items" in node:
        yield from walk_objects(node["items"], where + "[]", depth + 1)


def walk_properties(node, where, depth=0):
    """Yield (where, property schema) for every property at any depth (through array items); never array elements."""
    if depth > MAX_DEPTH or not isinstance(node, dict):
        return
    for pn, pv in as_dict(node.get("properties")).items():
        yield "%s.%s" % (where, pn), pv
        yield from walk_properties(pv, "%s.%s" % (where, pn), depth + 1)
    if "items" in node:
        yield from walk_properties(node["items"], where + "[]", depth + 1)


def check_open_objects(spec):
    out = []
    for name, schema in schemas_of(spec).items():
        for where, node in walk_objects(schema, name):
            if ("object" in types_of(node) or "properties" in node) and node.get("additionalProperties") is not False:
                out.append(("OPEN_OBJECT", where, "additionalProperties must be false"))
        for i, branch in enumerate(as_dict(schema).get("oneOf") or []):
            if as_dict(branch).get("properties") is not None and "additionalProperties" in as_dict(branch):
                out.append(("OPEN_OBJECT", "%s.oneOf[%d]" % (name, i), "constraint branches must not set additionalProperties"))
    return out


def check_error_envelope(spec, c):
    out = []
    err = schemas_of(spec).get("Error")
    cats = c["errors"]["categories"]
    if not isinstance(err, dict):
        return [("SCHEMA_STRUCTURE", "Error", "components.schemas.Error is required")]
    props = as_dict(err.get("properties"))
    if set(props) != {"category", "retryable", "correlation_id", "field_errors"} \
            or set(err.get("required") or []) != {"category", "retryable", "correlation_id"}:
        out.append(("SCHEMA_STRUCTURE", "Error", "properties must be category, retryable, correlation_id, field_errors "
                    "(the last optional) and there is no free-text message"))
    cat = as_dict(props.get("category"))
    if types_of(cat) != {"string"} or not isinstance(cat.get("enum"), list) or sorted(map(str, cat["enum"])) != sorted(cats) \
            or len(cat["enum"]) != len(set(map(str, cat["enum"]))):
        out.append(("ERROR_ENUM_MISMATCH", "Error.category", "enum must equal the errors.json categories"))
    if types_of(props.get("retryable")) != {"boolean"}:
        out.append(("ERROR_ENUM_MISMATCH", "Error.retryable", "must be a boolean"))
    corr = as_dict(props.get("correlation_id"))
    if types_of(corr) != {"string"} or corr.get("pattern") != CORRELATION_PATTERN:
        out.append(("SCHEMA_STRUCTURE", "Error.correlation_id", "string with pattern %s" % CORRELATION_PATTERN))
    fe = as_dict(props.get("field_errors"))
    fe_item = as_dict(fe.get("items"))
    codes = as_dict(as_dict(fe_item.get("properties")).get("code")).get("enum")
    if types_of(fe) != {"array"} or set(as_dict(fe_item.get("properties"))) != {"field", "code"} \
            or set(fe_item.get("required") or []) != {"field", "code"} \
            or not isinstance(codes, list) or set(codes) != FIELD_ERROR_CODES or len(codes) != len(FIELD_ERROR_CODES):
        out.append(("SCHEMA_STRUCTURE", "Error.field_errors", "array of {field, code}; code in %s" % sorted(FIELD_ERROR_CODES)))
    branches = err.get("oneOf")
    seen = {}
    if not isinstance(branches, list):
        out.append(("ERROR_ENUM_MISMATCH", "Error.oneOf", "one branch per category is required"))
    else:
        for i, b in enumerate(branches):
            bp = as_dict(as_dict(b).get("properties"))
            name = as_dict(bp.get("category")).get("const")
            spec_c = cats.get(name) if isinstance(name, str) else None
            where = "Error.oneOf[%d]" % i
            if spec_c is None or name in seen:
                out.append(("ERROR_ENUM_MISMATCH", where, "branch category must be a distinct errors.json category"))
                continue
            seen[name] = True
            if as_dict(bp.get("retryable")).get("const") is not spec_c["retryable"]:
                out.append(("ERROR_ENUM_MISMATCH", where, "retryable constant for %s must be %s" % (name, spec_c["retryable"])))
            if as_dict(b).get("x-http-status") != spec_c["http_status"] or type(as_dict(b).get("x-http-status")) is not int:
                out.append(("ERROR_ENUM_MISMATCH", where, "x-http-status for %s must be %s" % (name, spec_c["http_status"])))
            if set(as_dict(b).get("required") or []) != {"category", "retryable"} or set(bp) != {"category", "retryable"}:
                out.append(("ERROR_ENUM_MISMATCH", where, "branch must constrain exactly category and retryable"))
        for missing in sorted(set(cats) - set(seen)):
            out.append(("ERROR_ENUM_MISMATCH", "Error.oneOf", "no branch for category %s" % missing))
    return out


def status_category(c, status):
    for name, v in c["errors"]["categories"].items():
        if str(v["http_status"]) == status:
            return name
    return None


def check_paths(spec, c):
    out = []
    inv = as_dict(as_dict(c["inventory"].get("boundaries")).get("browser-api"))
    permitted = set(inv.get("permitted_request_categories") or [])
    boundary_cats = set(inv.get("error_categories") or [])
    implemented = set(inv.get("implemented_requests") or [])
    paths = as_dict(spec.get("paths"))
    declared = {(m, p) for p, item in paths.items() if isinstance(item, dict) for m in item if m in METHODS}
    for extra in sorted(declared - set(PATHS)):
        out.append(("PATH_CATEGORY", "%s %s" % (extra[0].upper(), extra[1]), "path and method are not in the approved convention"))
    for missing in sorted(set(PATHS) - declared):
        out.append(("PATH_CATEGORY", "%s %s" % (missing[0].upper(), missing[1]), "approved path is not declared"))
    schemas = schemas_of(spec)
    for (method, path), (category, ok_status, ok_schema, params, has_body) in PATHS.items():
        op = as_dict(as_dict(paths.get(path)).get(method))
        if not op:
            continue
        where = "%s %s" % (method.upper(), path)
        # Exactly one permitted category.
        if op.get("x-request-category") != category or category not in permitted:
            out.append(("PATH_CATEGORY", where, "must map to the permitted category %s" % category))
        # Security.
        sec = op.get("security")
        if category in ANONYMOUS_CATEGORIES:
            if sec != []:
                out.append(("SECURITY_MISSING", where, "%s declares security: []" % category))
        elif sec != [{SECURITY_SCHEME: []}]:
            out.append(("SECURITY_MISSING", where, "must require %s" % SECURITY_SCHEME))
        # Implementation claim.
        status = op.get("x-implementation-status")
        key = "%s %s" % (method.upper(), path)
        if status not in ("implemented", "not_implemented") or (status == "implemented") != (key in implemented):
            out.append(("IMPLEMENTED_CLAIM", where, "implemented only for %s" % sorted(implemented)))
        # Parameters.
        refs = [ref_name(p) for p in op.get("parameters") or []]
        if refs != list(params):
            out.append(("PATH_CATEGORY", where, "parameters must be %s" % list(params)))
        # Request body.
        body = op.get("requestBody")
        if has_body:
            sch = as_dict(as_dict(as_dict(as_dict(body).get("content")).get("application/json")).get("schema"))
            if ref_name(sch) != has_body or as_dict(body).get("required") is not True:
                out.append(("PATH_CATEGORY", where, "body must be the required %s" % has_body))
        elif body is not None:
            out.append(("PATH_CATEGORY", where, "no request body is declared for this path"))
        # Responses.
        resp = as_dict(op.get("responses"))
        got_ok = False
        for st, r in resp.items():
            try:
                _, target = resolve(spec, r, ("responses",))
            except Structure as exc:
                out.append(("SCHEMA_STRUCTURE", "%s %s" % (where, st), str(exc)))
                continue
            sch = as_dict(as_dict(as_dict(as_dict(target).get("content")).get("application/json")).get("schema"))
            if not isinstance(st, str) or not st.isdigit():
                out.append(("ERROR_RESPONSE_UNTYPED", "%s %s" % (where, st), "only numeric status keys are allowed"))
                continue
            if st[0] == "2":
                if st != ok_status or ref_name(sch) != ok_schema or got_ok:
                    out.append(("PATH_CATEGORY", "%s %s" % (where, st), "success response must be %s -> %s" % (ok_status, ok_schema)))
                got_ok = got_ok or st == ok_status
                continue
            cat = status_category(c, st)
            declared_cat = as_dict(target).get("x-error-category")
            if cat is None or (declared_cat is not None and declared_cat != cat):
                out.append(("ERROR_ENUM_MISMATCH", "%s %s" % (where, st), "status must map to its errors.json category"))
            if cat is not None and cat not in boundary_cats:
                out.append(("BOUNDARY_CATEGORY", "%s %s" % (where, st), "category %s is not a browser-api error category" % cat))
            if ref_name(sch) != "Error":
                out.append(("ERROR_RESPONSE_UNTYPED", "%s %s" % (where, st), "error responses must use the Error schema"))
        if not got_ok:
            out.append(("PATH_CATEGORY", where, "missing success response %s" % ok_status))
        if category not in NO_401_CATEGORIES and "401" not in resp:
            out.append(("PATH_CATEGORY", where, "must declare the unauthenticated (401) response"))
        # Success schema must exist.
        if ok_schema not in schemas:
            out.append(("RESOURCE_SET", ok_schema, "schema referenced by %s is missing" % where))
    for name, r in as_dict(as_dict(spec.get("components")).get("responses")).items():
        sch = as_dict(as_dict(as_dict(as_dict(r).get("content")).get("application/json")).get("schema"))
        if ref_name(sch) != "Error":
            out.append(("ERROR_RESPONSE_UNTYPED", "components.responses." + str(name), "must use the Error schema"))
        if as_dict(r).get("x-error-category") not in c["errors"]["categories"]:
            out.append(("ERROR_ENUM_MISMATCH", "components.responses." + str(name), "x-error-category must be an errors.json category"))
    # Security scheme must exist and be the only one.
    schemes = as_dict(as_dict(spec.get("components")).get("securitySchemes"))
    if set(schemes) != {SECURITY_SCHEME}:
        out.append(("SECURITY_MISSING", "components.securitySchemes", "must define exactly %s" % SECURITY_SCHEME))
    return out + check_request_shapes(spec, c)


def check_request_shapes(spec, c):
    """Parameters and the submit body equal the request-schemas.json value types and enums (path -> category)."""
    out = []
    vt = c["request-schemas"]["value_types"]
    cats = c["request-schemas"]["categories"]
    params = as_dict(as_dict(spec.get("components")).get("parameters"))

    def p(name):
        return as_dict(params.get(name))

    if as_dict(p("Id").get("schema")).get("pattern") != vt["id"] or p("Id").get("in") != "path" or p("Id").get("required") is not True \
            or p("Id").get("name") != "id":
        out.append(("PATH_CATEGORY", "components.parameters.Id", "must be the required path parameter `id` with the id pattern"))
    cur = p("Cursor")
    if as_dict(cur.get("schema")).get("pattern") != vt["cursor"] or cur.get("in") != "query" or cur.get("name") != "cursor" \
            or types_of(cur.get("schema")) != {"string"} or cur.get("required") is not False:
        out.append(("PATH_CATEGORY", "components.parameters.Cursor", "must be the optional query parameter with the cursor pattern"))
    lim = p("Limit")
    ls = as_dict(lim.get("schema"))
    pattern = re.compile(vt["limit"])
    if lim.get("in") != "query" or lim.get("name") != "limit" or lim.get("required") is not False \
            or types_of(ls) != {"integer"} or type(ls.get("minimum")) is not int or type(ls.get("maximum")) is not int \
            or not all(bool(pattern.fullmatch(str(n))) == (ls["minimum"] <= n <= ls["maximum"]) for n in range(-5, 1000)):
        out.append(("PATH_CATEGORY", "components.parameters.Limit", "bounds must equal the request-schemas limit pattern"))
    body = as_dict(schemas_of(spec).get("SubmitOperationRequest"))
    bp = as_dict(body.get("properties"))
    sub = cats["submit_operation"]
    # DR-016/DR-020: exactly two optional properties beyond the request-schemas.json keys: `create` and `params`, each with a pinned shape.
    ok = set(bp) == set(sub) | {"create", "params"} and set(body.get("required") or []) == set(sub) and create_shape_ok(bp.get("create")) \
        and params_shape_ok(bp.get("params"))
    for key, rule in sub.items():
        node = as_dict(bp.get(key))
        if isinstance(rule, list):
            ok = ok and isinstance(node.get("enum"), list) and sorted(node["enum"]) == sorted(rule)
        else:
            ok = ok and node.get("pattern") == vt[rule]
    if not ok:
        out.append(("PATH_CATEGORY", "SubmitOperationRequest", "must equal request-schemas.json submit_operation"))
    return out


CREATE_FIELDS = {"vcpus": ("integer", 1, 64), "memory_mib": ("integer", 64, 1048576), "disk_gib": ("integer", 1, 4096)}


def create_shape_ok(node):
    """The `create` object of SubmitOperationRequest (DR-016): five typed inputs, closed, bounded; nothing path-, URL- or XML-like."""
    node = as_dict(node)
    props = as_dict(node.get("properties"))
    if node.get("type") != "object" or node.get("additionalProperties") is not False \
            or set(props) != set(CREATE_FIELDS) | {"image_id", "ssh_public_key", "network"} or set(node.get("required") or []) != set(props) - {"network", "ssh_public_key"}:
        return False
    for name, (typ, lo, hi) in CREATE_FIELDS.items():
        p = as_dict(props[name])
        if p.get("type") != typ or p.get("minimum") != lo or p.get("maximum") != hi:
            return False
    image = as_dict(props["image_id"])
    key = as_dict(props["ssh_public_key"])
    net = as_dict(props["network"])
    if net.get("type") != "string" or net.get("pattern") != "^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$" or net.get("maxLength") != 63:
        return False
    return image.get("type") == "string" and image.get("pattern") == "^[a-z0-9][a-z0-9._-]{0,62}$" and image.get("maxLength") == 63 \
        and key.get("type") == "string" and key.get("maxLength") == 2048 and "pattern" not in key and "format" not in key


IPV4_PATTERN = "^(?:[0-9]{1,3}\\.){3}[0-9]{1,3}$"
PARAM_PATTERNS = {"image_id": "^[a-z0-9][a-z0-9._-]{0,62}$", "snapshot_id": "^snap-[0-9a-f]{12}$", "new_name": "^[a-z]([a-z0-9-]{0,61}[a-z0-9])?$",
                  "subnet": "^(?:[0-9]{1,3}\\.){3}[0-9]{1,3}/[0-9]{1,2}$", "dhcp_start": IPV4_PATTERN, "dhcp_end": IPV4_PATTERN, "ip_address": IPV4_PATTERN,
                  "vm_id": "^[a-z]([a-z0-9-]{0,61}[a-z0-9])?$", "target_id": "^[a-z][a-z0-9-]{1,30}[a-z0-9]$",
                  "at": "^([01][0-9]|2[0-3]):[0-5][0-9]$", "bridge": "^[a-zA-Z][a-zA-Z0-9_.:-]{0,14}$"}


def params_shape_ok(node):
    """The `params` object of SubmitOperationRequest (DR-020): five optional typed inputs, closed, bounded; no path, URL, volume name or XML."""
    node = as_dict(node)
    props = as_dict(node.get("properties"))
    if node.get("type") != "object" or node.get("additionalProperties") is not False \
            or set(props) != {"disk_gib", "ssh_public_key", "autostart", "vcpus", "memory_mib", "every_hours", "keep_local", "keep_offsite", "downtime_acknowledged", "boot"} | set(PARAM_PATTERNS) or node.get("required"):
        return False
    au, vc, mem = as_dict(props["autostart"]), as_dict(props["vcpus"]), as_dict(props["memory_mib"])
    if au.get("type") != "string" or au.get("enum") != ["on", "off"] or vc.get("type") != "integer" or (vc.get("minimum"), vc.get("maximum")) != (1, 64) \
            or mem.get("type") != "integer" or (mem.get("minimum"), mem.get("maximum")) != (64, 1048576):
        return False
    disk = as_dict(props["disk_gib"])
    key = as_dict(props["ssh_public_key"])
    if disk.get("type") != "integer" or disk.get("minimum") != 1 or disk.get("maximum") != 4096 \
            or key.get("type") != "string" or key.get("maxLength") != 2048 or "pattern" in key or "format" in key:
        return False
    return all(as_dict(props[n]).get("type") == "string" and as_dict(props[n]).get("pattern") == pat and isinstance(as_dict(props[n]).get("maxLength"), int)
               for n, pat in PARAM_PATTERNS.items())


def schema_bounds(spec):
    """Strings and arrays must be bounded; enums closed (section 1.3)."""
    out = []
    for name, schema in schemas_of(spec).items():
        for where, node in walk_objects(schema, name):
            if where == name:
                continue
            t = types_of(node)
            if "string" in t and not ({"enum", "const"} & set(node)) and not isinstance(node.get("maxLength"), int):
                out.append(("RESOURCE_SHAPE", where, "string must set maxLength"))
            if "array" in t and not isinstance(node.get("maxItems"), int):
                out.append(("RESOURCE_SHAPE", where, "array must set maxItems"))
    return out


def check_resources(spec, c):
    out = []
    schemas = schemas_of(spec)
    res = c["resources"]["resources"]
    expected = {"Health", "Error", "SubmitOperationRequest", "AuthSession", "SignInRequest"} | set(res) | {k + "List" for k in res}
    if set(res) != set(KINDS):
        out.append(("RESOURCE_SET", "resources.json", "resource kinds differ from the pinned set"))
    for extra in sorted(set(schemas) - expected):
        out.append(("RESOURCE_SET", extra, "schema is not defined by resources.json"))
    for missing in sorted(expected - set(schemas)):
        out.append(("RESOURCE_SET", missing, "schema is required"))
    classes = c["data-classes"]["fields"]
    classes_def = c["data-classes"]["classes"]
    persisted = c["resources"]["operation_persisted_fields"]
    for kind in KINDS:
        schema = as_dict(schemas.get(kind))
        props = as_dict(schema.get("properties"))
        if not schema:
            continue
        spec_k = res[kind]
        if set(schema.get("required") or []) != set(props) or len(schema.get("required") or []) != len(props):
            out.append(("RESOURCE_SHAPE", kind, "every property must be required (strict decoding)"))
        # allowed_actions (section 1.5)
        aa = as_dict(props.get("allowed_actions"))
        want = ITEM_ACTIONS[kind]
        if not aa or types_of(aa) != {"array"}:
            out.append(("RESOURCE_SHAPE", kind + ".allowed_actions", "required array"))
        elif want:
            enum = as_dict(aa.get("items")).get("enum")
            if not isinstance(enum, list) or set(enum) != want or len(enum) != len(want):
                out.append(("ACTION_INVALID", kind + ".allowed_actions", "ids must be exactly %s" % sorted(want)))
        elif aa.get("maxItems") != 0 or "enum" in as_dict(aa.get("items")):
            out.append(("ACTION_INVALID", kind + ".allowed_actions", "this kind has no actions (maxItems 0)"))
        if kind == "Operation":
            secret = {f for f in persisted if classes.get("operation." + f) in SECRET_CLASSES}
            want_props = (set(persisted) - secret) | {"allowed_actions"}
            if set(props) != want_props:
                out.append(("OPERATION_FIELDS", "Operation", "properties must be the persisted fields minus secret and "
                            "credential fields (%s), plus allowed_actions" % sorted(secret)))
            statuses = as_dict(props.get("status")).get("enum")
            if not isinstance(statuses, list) or sorted(statuses) != sorted(c["resources"]["operation_status"]):
                out.append(("OPERATION_FIELDS", "Operation.status", "enum must equal operation_status"))
            ec = as_dict(props.get("error_category")).get("enum")
            if not isinstance(ec, list) or sorted(map(str, ec)) != sorted(list(c["errors"]["categories"]) + ["None"]):
                out.append(("OPERATION_FIELDS", "Operation.error_category", "enum must be the errors.json categories or null"))
            continue
        # common properties (section 1.3)
        common = {"id", "allowed_actions"}
        if spec_k["ownership_scope"] == "project":
            common.add("project_id")
        if spec_k["generation_tracking"]:
            common.add("generation")
        if kind == "Event":
            want_props = EVENT_PROPS
            if "generation" in props:
                out.append(("RESOURCE_SHAPE", kind + ".generation", "Event has no generation"))
        else:
            want_props = common | {"name", "desired", "observed"}
        if set(props) != want_props:
            out.append(("RESOURCE_SHAPE", kind, "properties must be %s" % sorted(want_props)))
            continue
        if kind == "Event":
            continue
        want_d, want_o = DESIRED_OBSERVED[kind]
        for label, want_leaves in (("desired", want_d), ("observed", want_o)):
            node = as_dict(props.get(label))
            leaves = as_dict(node.get("properties"))
            if "object" not in types_of(node) or set(leaves) != set(want_leaves):
                out.append(("RESOURCE_SHAPE", "%s.%s" % (kind, label), "properties must be %s" % sorted(want_leaves)))
                continue
            for leaf, (want_t, want_enum) in want_leaves.items():
                ln = as_dict(leaves[leaf])
                if types_of(ln) != want_t or (want_enum is not None and (
                        not isinstance(ln.get("enum"), list) or set(ln["enum"]) != want_enum or len(ln["enum"]) != len(want_enum))):
                    out.append(("RESOURCE_SHAPE", "%s.%s.%s" % (kind, label, leaf), "type/enum differs from section 1.3"))
            if set(node.get("required") or []) != set(want_leaves):
                out.append(("RESOURCE_SHAPE", "%s.%s" % (kind, label), "every property must be required"))
    for kind in KINDS:
        coll = as_dict(schemas.get(kind + "List"))
        if not coll:
            continue
        props = as_dict(coll.get("properties"))
        items = as_dict(props.get("items"))
        nxt = as_dict(props.get("next_cursor"))
        if set(props) != {"items", "allowed_actions", "next_cursor"} or set(coll.get("required") or []) != set(props) \
                or ref_name(items.get("items")) != kind or types_of(items) != {"array"} \
                or items.get("maxItems") != 200 or types_of(nxt) != {"string", "null"} \
                or nxt.get("pattern") != c["request-schemas"]["value_types"]["cursor"]:
            out.append(("RESOURCE_SHAPE", kind + "List", "must be {items: [%s] (max 200), allowed_actions, next_cursor}" % kind))
        aa = as_dict(props.get("allowed_actions"))
        if kind in SUBMIT_KINDS:
            enum = as_dict(aa.get("items")).get("enum")
            if enum != ["create"]:
                out.append(("ACTION_INVALID", kind + "List.allowed_actions", "ids must be exactly ['create']"))
        elif aa.get("maxItems") != 0 or "enum" in as_dict(aa.get("items")):
            out.append(("ACTION_INVALID", kind + "List.allowed_actions", "this collection has no create action (maxItems 0)"))
    return out + check_host_extension(schemas) + check_vm_extension(schemas) + check_network_extension(schemas) + check_auth_shapes(schemas) + schema_bounds(spec)


def check_host_extension(schemas):
    """DR-015 D3: Host.observed carries exactly these extra, closed, bounded fields and nothing free-form."""
    out = []
    obs = as_dict(as_dict(as_dict(as_dict(schemas.get("Host")).get("properties")).get("observed")).get("properties"))
    v = as_dict(obs.get("virtualization"))
    vp = as_dict(v.get("properties"))
    states = ["available", "unavailable", "unknown"]
    if set(vp) != {"hardware", "kvm_device", "libvirt_packages", "qemu_packages"} or set(v.get("required") or []) != set(vp) \
            or v.get("additionalProperties") is not False \
            or any(sorted(as_dict(n).get("enum") or []) != sorted(states) for n in vp.values()):
        out.append(("RESOURCE_SHAPE", "Host.observed.virtualization", "must be four required available/unavailable/unknown states"))
    d = as_dict(obs.get("distribution"))
    if set(as_dict(d.get("properties"))) != {"id", "version_id"} or set(d.get("required") or []) != {"id", "version_id"} \
            or d.get("additionalProperties") is not False:
        out.append(("RESOURCE_SHAPE", "Host.observed.distribution", "must be {id, version_id}"))
    cr = as_dict(obs.get("creation"))
    crp = as_dict(cr.get("properties"))
    reasons = ["mutation_disabled", "no_usable_image", "storage_unavailable", "network_unavailable", "virtualization_unavailable", "host_not_qualified", "image_unqualified"]
    if set(crp) != {"enabled", "network", "storage", "vcpu_options", "memory_mib_options", "disk_gib_options", "ready", "reasons"} \
            or as_dict(crp.get("ready")).get("type") != "boolean" or as_dict(crp.get("reasons")).get("maxItems") != 8 \
            or sorted(as_dict(as_dict(crp.get("reasons")).get("items")).get("enum") or []) != sorted(reasons) \
            or set(cr.get("required") or []) != set(crp) or cr.get("additionalProperties") is not False \
            or any(sorted(as_dict(crp.get(k)).get("enum") or []) != sorted(states) for k in ("network", "storage")) \
            or any(as_dict(crp.get(k)).get("maxItems") != 16 or as_dict(as_dict(crp.get(k)).get("items")).get("type") != "integer"
                   for k in ("vcpu_options", "memory_mib_options", "disk_gib_options")):
        out.append(("RESOURCE_SHAPE", "Host.observed.creation", "must be {enabled, network, storage, three bounded integer option lists, ready, closed reasons}"))
    st = as_dict(obs.get("storage"))
    stp = as_dict(st.get("properties"))
    gib_leaves = ("pool_total_gib", "pool_free_gib", "images_gib", "backups_gib", "backups_free_gib")
    if set(stp) != {"state", "backups_configured", "allocation_note", "snapshots", "backup_targets"} | set(gib_leaves) or set(st.get("required") or []) != set(stp) \
            or st.get("additionalProperties") is not False or sorted(as_dict(stp.get("state")).get("enum") or []) != sorted(states) \
            or as_dict(stp.get("backups_configured")).get("type") != "boolean" \
            or sorted(as_dict(stp.get("snapshots")).get("enum") or []) != ["available", "unavailable", "unknown"] \
            or as_dict(stp.get("backup_targets")).get("type") != "array" or as_dict(stp.get("backup_targets")).get("maxItems") != 8 \
            or set(as_dict(as_dict(as_dict(stp.get("backup_targets")).get("items")).get("properties"))) != {"id", "kind", "state"} \
            or as_dict(stp.get("allocation_note")).get("type") != "string" or not isinstance(as_dict(stp.get("allocation_note")).get("maxLength"), int) \
            or any(types_of(as_dict(stp.get(k))) != {"integer", "null"} or not isinstance(as_dict(stp.get(k)).get("maximum"), int) for k in gib_leaves):
        out.append(("RESOURCE_SHAPE", "Host.observed.storage", "must be {state, five bounded nullable GiB figures, backups_configured, snapshots, allocation_note}"))
    out.extend(_usage_shape(as_dict(obs.get("usage")), "Host.observed.usage", ("state", "interval_seconds", "cpu_percent", "memory_used_mib", "disk_kib_s", "net_kib_s", "history"),
                            ("at", "cpu_percent", "memory_used_mib", "disk_kib_s", "net_kib_s")))
    f = as_dict(obs.get("capability_findings"))
    item = as_dict(f.get("items"))
    if f.get("maxItems") != 16 or set(as_dict(item.get("properties"))) != {"code", "remediation"} \
            or item.get("additionalProperties") is not False or as_dict(as_dict(item.get("properties")).get("code")).get("pattern") is None:
        out.append(("RESOURCE_SHAPE", "Host.observed.capability_findings", "must be at most 16 {code, remediation} items"))
    return out


def _usage_shape(u, where, keys, sample_keys):
    """DR-022: a closed usage object: a state, bounded nullable figures and a bounded history of closed samples (no free-form field)."""
    props = as_dict(u.get("properties"))
    hist = as_dict(props.get("history"))
    item = as_dict(hist.get("items"))
    ip = as_dict(item.get("properties"))
    percent = lambda n: types_of(n) <= {"integer", "null"} and n.get("minimum") == 0 and n.get("maximum") == 100
    bad = (set(props) != set(keys) or set(u.get("required") or []) != set(keys) or u.get("additionalProperties") is not False
           or sorted(as_dict(props.get("state")).get("enum") or []) != ["available", "unavailable"]
           or types_of(as_dict(props.get("cpu_percent"))) != {"integer", "null"} or not percent(as_dict(props.get("cpu_percent")))
           or hist.get("maxItems") != 240 or item.get("additionalProperties") is not False or set(ip) != set(sample_keys)
           or set(item.get("required") or []) != set(sample_keys) or as_dict(ip.get("at")).get("format") != "date-time"
           or types_of(as_dict(ip.get("cpu_percent"))) != {"integer"} or not percent(as_dict(ip.get("cpu_percent"))))
    if "interval_seconds" in keys:
        iv = as_dict(props.get("interval_seconds"))
        bad = bad or types_of(iv) != {"integer"} or iv.get("minimum") != 1 or iv.get("maximum") != 3600
    for k in ("memory_used_mib", "disk_kib_s", "net_kib_s"):  # DR-022 / DR-023 D5: bounded nullable figures and bounded sample integers
        n, sn = as_dict(props.get(k)), as_dict(ip.get(k))
        bad = bad or types_of(n) != {"integer", "null"} or not isinstance(n.get("maximum"), int) \
            or types_of(sn) != {"integer"} or not isinstance(sn.get("maximum"), int)
    return [("RESOURCE_SHAPE", where, "must be a closed usage object with a state, bounded nullable figures and at most 240 closed samples")] if bad else []


def check_vm_extension(schemas):
    """DR-020: VM.observed.disk_gib is bounded and nullable; snapshots are at most eight closed {id, created_at} items."""
    out = []
    obs = as_dict(as_dict(as_dict(as_dict(schemas.get("VM")).get("properties")).get("observed")).get("properties"))
    nw = as_dict(obs.get("network"))
    nwp = as_dict(nw.get("properties"))
    if types_of(nw) != {"object", "null"} or nw.get("additionalProperties") is not False or set(nwp) != {"name", "mac", "reserved_ip", "state"} \
            or set(nw.get("required") or []) != set(nwp) or sorted(as_dict(nwp.get("state")).get("enum") or []) != ["active", "inactive", "unknown"] \
            or types_of(as_dict(nwp.get("reserved_ip"))) != {"string", "null"} or as_dict(nwp.get("mac")).get("pattern") != "^(?:[0-9a-f]{2}:){5}[0-9a-f]{2}$":
        out.append(("RESOURCE_SHAPE", "VM.observed.network", "must be {name, mac, reserved_ip (nullable), state} or null"))
    out.extend(_usage_shape(as_dict(obs.get("usage")), "VM.observed.usage", ("state", "cpu_percent", "memory_used_mib", "disk_kib_s", "net_kib_s", "history"),
                            ("at", "cpu_percent", "memory_used_mib", "disk_kib_s", "net_kib_s")))
    for k, hi in (("vcpus", 1048576), ("memory_mib", 1073741824)):
        n = as_dict(obs.get(k))
        if types_of(n) != {"integer", "null"} or n.get("minimum") != 1 or n.get("maximum") != hi:
            out.append(("RESOURCE_SHAPE", "VM.observed." + k, "must be a bounded nullable integer"))
    disk = as_dict(obs.get("disk_gib"))
    snaps = as_dict(obs.get("snapshots"))
    item = as_dict(snaps.get("items"))
    ip = as_dict(item.get("properties"))
    if types_of(disk) != {"integer", "null"} or disk.get("minimum") != 1 or disk.get("maximum") != 4096 \
            or snaps.get("maxItems") != 8 or item.get("additionalProperties") is not False or set(ip) != {"id", "created_at"} \
            or set(item.get("required") or []) != {"id", "created_at"} or as_dict(ip.get("id")).get("pattern") != "^snap-[0-9a-f]{12}$":
        out.append(("RESOURCE_SHAPE", "VM.observed.snapshots", "must be disk_gib (1..4096 or null) and at most 8 closed {id, created_at} snapshots"))
    return out


def check_network_extension(schemas):
    """DR-021: VirtualNetwork.observed.reservations is a bounded list of closed {mac, ip} items; the addressing fields are bounded strings or null."""
    out = []
    obs = as_dict(as_dict(as_dict(as_dict(schemas.get("VirtualNetwork")).get("properties")).get("observed")).get("properties"))
    res = as_dict(obs.get("reservations"))
    item = as_dict(res.get("items"))
    ip = as_dict(item.get("properties"))
    if res.get("maxItems") != 256 or item.get("additionalProperties") is not False or set(ip) != {"mac", "ip"} or set(item.get("required") or []) != {"mac", "ip"} \
            or as_dict(ip.get("mac")).get("pattern") != "^(?:[0-9a-f]{2}:){5}[0-9a-f]{2}$" or as_dict(ip.get("ip")).get("pattern") != IPV4_PATTERN:
        out.append(("RESOURCE_SHAPE", "VirtualNetwork.observed.reservations", "must be at most 256 closed {mac, ip} items"))
    for k in ("gateway", "dhcp_start", "dhcp_end"):
        if types_of(as_dict(obs.get(k))) != {"string", "null"} or as_dict(obs.get(k)).get("pattern") != IPV4_PATTERN:
            out.append(("RESOURCE_SHAPE", "VirtualNetwork.observed." + k, "must be an IPv4 string or null"))
    sub = as_dict(obs.get("subnet"))
    if types_of(sub) != {"string", "null"} or sub.get("maxLength") != 18 or "/" not in str(sub.get("pattern")):
        out.append(("RESOURCE_SHAPE", "VirtualNetwork.observed.subnet", "must be a bounded CIDR string or null"))
    if as_dict(obs.get("attached_vms")).get("maximum") != 100000:
        out.append(("RESOURCE_SHAPE", "VirtualNetwork.observed.attached_vms", "must be bounded"))
    return out


def check_auth_shapes(schemas):
    """DR-015 D3: the authentication shapes are exactly these (no secret in a response, closed request)."""
    out = []
    a = as_dict(schemas.get("AuthSession"))
    keys = {"authenticated", "username", "expires_at", "role"}
    role = as_dict(as_dict(a.get("properties")).get("role"))
    if set(as_dict(a.get("properties"))) != keys or set(a.get("required") or []) != keys or a.get("additionalProperties") is not False \
            or types_of(role) != {"string", "null"} or sorted(map(str, role.get("enum") or [])) != sorted(["admin", "operator", "viewer", "None"]):
        out.append(("RESOURCE_SHAPE", "AuthSession", "must be exactly {authenticated, username, expires_at, role (admin|operator|viewer|null)}"))
    r = as_dict(schemas.get("SignInRequest"))
    rp = as_dict(r.get("properties"))
    if set(rp) != {"username", "password"} or set(r.get("required") or []) != {"username", "password"} \
            or r.get("additionalProperties") is not False or as_dict(rp.get("password")).get("x-data-class") != "credential":
        out.append(("RESOURCE_SHAPE", "SignInRequest", "must be exactly {username, password(credential)}"))
    return out


def reachable_from_responses(spec):
    """Names of component schemas reachable from path responses (the response schemas)."""
    names = set()
    schemas = schemas_of(spec)

    def visit_schema(node, depth=0):
        if depth > MAX_DEPTH or not isinstance(node, dict):
            return
        name = ref_name(node)
        if name and name not in names:
            names.add(name)
            visit_schema(schemas.get(name), depth + 1)
        for pv in as_dict(node.get("properties")).values():
            visit_schema(pv, depth + 1)
        if "items" in node:
            visit_schema(node["items"], depth + 1)

    for item in as_dict(spec.get("paths")).values():
        for op in as_dict(item).values():
            for r in as_dict(as_dict(op).get("responses")).values():
                try:
                    _, target = resolve(spec, r, ("responses",))
                except Structure:
                    continue
                sch = as_dict(as_dict(as_dict(as_dict(target).get("content")).get("application/json")).get("schema"))
                visit_schema(sch)
    return names


def check_classification(spec, c):
    out = []
    classes = set(c["data-classes"]["classes"])
    fields = c["data-classes"]["fields"]
    schemas = schemas_of(spec)
    names = reachable_from_responses(spec)
    for name in sorted(names):
        schema = as_dict(schemas.get(name))
        prefix = name.lower() if name in KINDS else None
        for where, node in walk_properties(schema, name):
            cls = node.get("x-data-class")
            if not isinstance(cls, str) or cls not in classes:
                out.append(("UNCLASSIFIED_FIELD", where, "needs x-data-class in %s" % sorted(classes)))
                continue
            if cls in SECRET_CLASSES:
                out.append(("SECRET_IN_RESPONSE", where, "%s-class data must never appear in a response" % cls))
            if cls == "personal" and where != "Operation.requested_by":
                out.append(("CLASS_MISMATCH", where, "personal is allowed only on Operation.requested_by"))
            top = where.split(".")
            if prefix and len(top) == 2 and prefix + "." + top[1] in fields and fields[prefix + "." + top[1]] != cls:
                out.append(("CLASS_MISMATCH", where, "data-classes.json says %s" % fields[prefix + "." + top[1]]))
    body = as_dict(schemas.get("SubmitOperationRequest"))
    for pn, pv in as_dict(body.get("properties")).items():
        want = fields.get("request.submit_operation." + pn)
        got = as_dict(pv).get("x-data-class")
        if got not in classes:
            out.append(("UNCLASSIFIED_FIELD", "SubmitOperationRequest." + pn, "needs x-data-class"))
        elif want is not None and want != got:
            out.append(("CLASS_MISMATCH", "SubmitOperationRequest." + pn, "data-classes.json says %s" % want))
    return out


def response_schema_digest(spec):
    schemas = schemas_of(spec)
    return digest({n: schemas[n] for n in sorted(reachable_from_responses(spec)) if n in schemas})


def check_spec(spec, c):
    """All findings for a parsed spec (everything except the baseline)."""
    findings = check_subset(spec)
    if findings:
        return findings  # semantic checks assume the allowed subset
    try:
        findings += check_open_objects(spec)
        findings += check_error_envelope(spec, c)
        findings += check_paths(spec, c)
        findings += check_resources(spec, c)
        findings += check_classification(spec, c)
    except Structure as exc:
        findings.append(("SCHEMA_STRUCTURE", "document", str(exc)))
    except (TypeError, AttributeError, KeyError, ValueError, RecursionError) as exc:
        findings.append(("SCHEMA_STRUCTURE", "document", "malformed structure: %s" % exc.__class__.__name__))
    return findings


# ---- compatibility baseline (section 5) -----------------------------------------------------------------------------
def parse_baseline(raw):
    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError):
        return None
    if not isinstance(data, dict) or set(data) != BASELINE_KEYS or data.get("schema") != 1 or type(data["schema"]) is not int \
            or not isinstance(data.get("decision"), str) or not re.fullmatch(r"(?:ADR|DR)-[0-9]{3}", data["decision"]) \
            or not isinstance(data.get("schema_digest"), str) or not re.fullmatch(r"[0-9a-f]{64}", data["schema_digest"]):
        return None
    return data


def pin_of(lock_raw):
    try:
        commit = json.loads(lock_raw.decode("utf-8")).get("commit")
    except (UnicodeDecodeError, ValueError, AttributeError, RecursionError):
        return None
    return commit if isinstance(commit, str) and re.fullmatch(r"[0-9a-f]{40}", commit) else None


def check_baseline(current_digest, chain, register_at, declared):
    """Findings (BREAKING_CHANGE) for a baseline chain, oldest first.

    chain: [{"raw": baseline bytes, "pin": docs commit pinned by docs-lock.json with that baseline}]. The last entry is
    the working-tree baseline. register_at(sha) returns {decision id: register record} or a problem string.
    declared: decision ids listed in contracts/decision-deps.json.
    """
    out = []

    def bad(msg):
        out.append(("BREAKING_CHANGE", BASELINE_FILE, msg))

    if not chain:
        return [("BREAKING_CHANGE", BASELINE_FILE, "no compatibility baseline")]
    parsed = []
    for i, entry in enumerate(chain):
        b = parse_baseline(entry["raw"])
        if b is None or entry["pin"] is None:
            return out + [("BREAKING_CHANGE", BASELINE_FILE, "baseline %d is malformed or has no valid docs pin" % i)]
        parsed.append((b, entry["pin"]))
    final = parsed[-1][0]
    if final["schema_digest"] != current_digest:
        bad("a response schema changed without updating the baseline in the same commit")
    earlier = []
    for i, (b, pin) in enumerate(parsed):
        label = "baseline %d (%s)" % (i, b["decision"])
        reg = register_at(pin)
        if isinstance(reg, str):
            bad("%s: %s" % (label, reg))
            continue
        rec = reg.get(b["decision"])
        if not rec or rec.get("status") != "approved" or STORY_ID not in (rec.get("stories") or []):
            bad("%s: decision must be approved at the pinned docs commit and list %s" % (label, STORY_ID))
        if b["decision"] not in declared:
            bad("%s: decision is not declared in %s" % (label, DEPS_FILE))
        if i > 0:
            prev_b, prev_pin = parsed[i - 1]
            if b["schema_digest"] == prev_b["schema_digest"]:
                if b["decision"] != prev_b["decision"]:
                    bad("%s: the decision record changed without a schema change" % label)
            else:
                if b["decision"] in earlier:
                    bad("%s: a schema change needs a decision record different from every earlier baseline" % label)
                prev_reg = register_at(prev_pin)
                prev_rec = prev_reg.get(b["decision"]) if isinstance(prev_reg, dict) else None
                if isinstance(prev_reg, dict) and prev_rec and prev_rec.get("status") == "approved":
                    bad("%s: the decision was already approved at the docs commit pinned by the previous baseline" % label)
        earlier.append(b["decision"])
    return out


# ---- repository access -----------------------------------------------------------------------------------------------
def load_linkage(root):
    spec = importlib.util.spec_from_file_location("check_linkage", Path(root) / "tools" / "check_linkage.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_decisions(root):
    spec = importlib.util.spec_from_file_location("check_decisions", Path(root) / "tools" / "check_decisions.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def baseline_chain(linkage, repo, working_raw, lock_raw):
    """Committed baselines from first-parent history (oldest first), then the working-tree baseline if it differs."""
    log = linkage.git(repo, "log", "--first-parent", "--reverse", "--format=%H", "--", BASELINE_FILE)
    if log is None:
        raise EnvError("cannot read first-parent history for %s" % BASELINE_FILE)
    chain = []
    for sha in log.decode("ascii", "replace").split():
        if not re.fullmatch(r"[0-9a-f]{40}", sha):
            raise EnvError("unexpected history entry")
        raw = linkage.git(repo, "cat-file", "blob", "%s:%s" % (sha, BASELINE_FILE))
        lock = linkage.git(repo, "cat-file", "blob", "%s:%s" % (sha, LOCK_FILE))
        if raw is None:  # the file was deleted in this commit: not a baseline version
            continue
        chain.append({"raw": raw, "pin": pin_of(lock or b"")})
    if not chain or chain[-1]["raw"] != working_raw or chain[-1]["pin"] != pin_of(lock_raw):
        chain.append({"raw": working_raw, "pin": pin_of(lock_raw)})
    return chain


def run(root, docs_repo, trusted_ref="refs/heads/main"):
    root = Path(root)
    c = load_contracts(root)
    try:
        spec = load_yaml(_read(root / SPEC_FILE))
    except Structure as exc:
        return [("SCHEMA_STRUCTURE", SPEC_FILE, str(exc))], None
    except UnicodeDecodeError:
        return [("SCHEMA_STRUCTURE", SPEC_FILE, "not valid UTF-8")], None
    findings = check_spec(spec, c)
    if any(f[0] == "SCHEMA_STRUCTURE" for f in findings):
        return findings, None
    working = _read(root / BASELINE_FILE)
    lock_raw = _read(root / LOCK_FILE)
    deps_raw = _read(root / DEPS_FILE)
    linkage, decisions = load_linkage(root), load_decisions(root)
    try:
        linkage.require_git_version()
        linkage.require_repo(str(docs_repo), "DOCS_REPO_UNAVAILABLE", "docs-repo")
        linkage.require_repo(str(root), "REPO_UNAVAILABLE", "repo")
        declared = set(decisions.load_deps(deps_raw))
        chain = baseline_chain(linkage, str(root), working, lock_raw)
        docs = linkage.Docs(str(docs_repo), trusted_ref)
        for entry in chain:
            if entry["pin"] is None or not docs.commit_exists(entry["pin"]) or not docs.is_trusted(entry["pin"]):
                raise EnvError("a baseline's docs pin is not a commit on the trusted docs ref")
        cache = {}

        def register_at(sha):
            if sha not in cache:
                cache[sha] = decisions.register_at(linkage, str(docs_repo), sha)
            return cache[sha]

        findings += check_baseline(response_schema_digest(spec), chain, register_at, declared)
    except (linkage.EnvError, decisions.EnvError) as exc:
        raise EnvError(str(exc)) from None
    return findings, len(spec["paths"])


def main(argv=None):
    parser = argparse.ArgumentParser(description="Check contracts/openapi.yaml (M0-E01-S04).")
    parser.add_argument("--docs-repo", required=True)
    parser.add_argument("--docs-ref", default="refs/heads/main")
    parser.add_argument("--repo", default=str(ROOT))
    parser.add_argument("--print-digest", action="store_true", help="print the response-schema digest (for the baseline)")
    args = parser.parse_args(argv)
    try:
        if args.print_digest:
            spec = load_yaml(_read(Path(args.repo) / SPEC_FILE))
            print(response_schema_digest(spec))
            return 0
        findings, paths = run(args.repo, args.docs_repo, args.docs_ref)
    except (EnvError, Structure) as exc:
        print("ERROR USAGE openapi: %s" % exc)
        return 2
    for code, where, msg in findings:
        print("ERROR %s %s: %s" % (code, where, msg))
    if findings:
        return 1
    print("OK openapi: %d paths, response schemas match the baseline" % paths)
    return 0


if __name__ == "__main__":
    sys.exit(main())
