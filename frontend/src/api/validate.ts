// Strict runtime validation against the generated schemas (M0-E01-S04, DR-012 D4).
// Implements exactly the OpenAPI subset tools/check_openapi.py allows; anything else in a schema fails closed.
// The failure reason is the JSON-Schema keyword that failed, so negative fixtures can name it.
import { SCHEMAS, type SchemaName } from "./schema";

export type Reason =
  | "type" | "enum" | "const" | "pattern" | "format" | "minLength" | "maxLength" | "minimum" | "maximum"
  | "required" | "additionalProperties" | "maxItems" | "minItems" | "uniqueItems" | "oneOf" | "schema";
export type Verdict = { ok: true } | { ok: false; reason: Reason; path: string };

type Node = Record<string, unknown>;
const MAX_DEPTH = 24;
const DATE_TIME = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(\.\d{1,9})?(Z|[+-]\d{2}:\d{2})$/;

const isObject = (v: unknown): v is Node => typeof v === "object" && v !== null && !Array.isArray(v);

function typeOf(v: unknown): string {
  if (v === null) return "null";
  if (Array.isArray(v)) return "array";
  if (typeof v === "number") return Number.isInteger(v) ? "integer" : "number";
  return typeof v;
}

function validDateTime(s: string): boolean {
  const m = DATE_TIME.exec(s);
  if (!m) return false;
  const [y, mo, d, h, mi, se] = [1, 2, 3, 4, 5, 6].map((i) => Number(m[i]));
  if (mo < 1 || mo > 12 || d < 1 || h > 23 || mi > 59 || se > 60) return false;
  const days = [31, y % 4 === 0 && (y % 100 !== 0 || y % 400 === 0) ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
  return d <= days[mo - 1];
}

const same = (a: unknown, b: unknown) => a === b;

function check(schema: Node, value: unknown, path: string, depth: number): Verdict {
  const fail = (reason: Reason): Verdict => ({ ok: false, reason, path });
  if (depth > MAX_DEPTH) return fail("schema");
  if (typeof schema.$ref === "string") {
    const name = schema.$ref.replace("#/components/schemas/", "");
    const target = name === "Error" ? "ApiError" : name;
    const next = (SCHEMAS as unknown as Record<string, Node>)[target];
    return next ? check(next, value, path, depth + 1) : fail("schema");
  }
  if ("const" in schema && !same(schema.const, value)) return fail("const");
  if (Array.isArray(schema.enum) && !schema.enum.some((e) => same(e, value))) return fail("enum");
  const types = schema.type === undefined ? null : ([] as unknown[]).concat(schema.type);
  const actual = typeOf(value);
  if (types && !types.includes(actual) && !(actual === "integer" && types.includes("number"))) return fail("type");
  if (typeof value === "string") {
    if (typeof schema.minLength === "number" && [...value].length < schema.minLength) return fail("minLength");
    if (typeof schema.maxLength === "number" && [...value].length > schema.maxLength) return fail("maxLength");
    if (typeof schema.pattern === "string" && !new RegExp(schema.pattern, "u").test(value)) return fail("pattern");
    if (schema.format === "date-time" && !validDateTime(value)) return fail("format");
  }
  if (typeof value === "number") {
    if (typeof schema.minimum === "number" && value < schema.minimum) return fail("minimum");
    if (typeof schema.maximum === "number" && value > schema.maximum) return fail("maximum");
  }
  if (Array.isArray(value)) {
    if (typeof schema.maxItems === "number" && value.length > schema.maxItems) return fail("maxItems");
    if (typeof schema.minItems === "number" && value.length < schema.minItems) return fail("minItems");
    if (schema.uniqueItems === true && new Set(value.map((v) => JSON.stringify(v))).size !== value.length) return fail("uniqueItems");
    if (isObject(schema.items)) {
      for (let i = 0; i < value.length; i++) {
        const r = check(schema.items, value[i], `${path}[${i}]`, depth + 1);
        if (!r.ok) return r;
      }
    }
  }
  if (isObject(value) && (types === null || types.includes("object"))) {
    const props = isObject(schema.properties) ? (schema.properties as Record<string, Node>) : {};
    const own = Object.keys(value);
    if (schema.additionalProperties === false) {
      const extra = own.find((k) => !Object.prototype.hasOwnProperty.call(props, k));
      if (extra !== undefined) return { ok: false, reason: "additionalProperties", path: `${path}.${extra}` };
    }
    if (Array.isArray(schema.required)) {
      const missing = (schema.required as string[]).find((k) => !Object.prototype.hasOwnProperty.call(value, k));
      if (missing !== undefined) return { ok: false, reason: "required", path: `${path}.${missing}` };
    }
    for (const k of own) {
      if (Object.prototype.hasOwnProperty.call(props, k)) {
        const r = check(props[k], value[k], `${path}.${k}`, depth + 1);
        if (!r.ok) return r;
      }
    }
  }
  if (Array.isArray(schema.oneOf)) {
    const passing = (schema.oneOf as Node[]).filter((b) => check(b, value, path, depth + 1).ok).length;
    if (passing !== 1) return fail("oneOf");
  }
  return { ok: true };
}

/** Validate a decoded JSON value against a generated schema. Never throws for hostile input. */
export function validate(name: SchemaName, value: unknown): Verdict {
  const schema = (SCHEMAS as unknown as Record<string, Node>)[name];
  if (!schema) return { ok: false, reason: "schema", path: "$" };
  try {
    return check(schema, value, "$", 0);
  } catch {
    return { ok: false, reason: "schema", path: "$" };
  }
}
