// The only module that talks to the API (M0-E02-S06 r5 section 9; DR-010 D5).
// - Same-origin relative paths only; there is no configurable base URL.
// - One deadline (REQUEST_DEADLINE_MS). Reads that miss it, or fail at the network level, are `unreachable`
//   (J8); mutations are `outcome_unknown` and are NEVER re-sent automatically.
// - Responses are decoded strictly; anything unexpected is the `internal` state, never rendered raw.
// - Nothing is logged and nothing is stored in Web Storage, IndexedDB or cookies.
// Error envelope, resource shapes and allowed_actions come from contracts/openapi.yaml (M0-E01-S04, DR-012): the
// generated types in ./schema.ts and the strict decoding in ./validate.ts.
import { normaliseCategory, type ErrorCategory } from "./errors";
import type { Health } from "./schema";
import { validate } from "./validate";

export const REQUEST_DEADLINE_MS = 10000;
export const MAX_BODY_BYTES = 1 << 20;

export type ReadResult<T> =
  | { kind: "ok"; data: T }
  | { kind: "error"; category: ErrorCategory; correlationId: string | null }
  | { kind: "unreachable" };

export type MutationResult<T> =
  | { kind: "ok"; data: T }
  | { kind: "error"; category: ErrorCategory; correlationId: string | null }
  | { kind: "outcome_unknown" };

export type Decoder<T> = (value: unknown) => T | null;

const PATH_RE = /^\/(?!\/)[A-Za-z0-9._~\-/]*(\?[A-Za-z0-9._~=&-]*)?$/;
const CORRELATION_RE = /^[A-Za-z0-9-]{8,64}$/;

function assertPath(path: string): void {
  if (!PATH_RE.test(path) || path.includes("..")) throw new Error("client: only same-origin relative API paths are allowed");
}

type Raw = { status: number; text: string; csrf: string | null } | "network" | "deadline" | "too_large";

async function send(path: string, init: RequestInit, fetchImpl: typeof fetch, extraHeaders: Record<string, string> = {}): Promise<Raw> {
  assertPath(path);
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), REQUEST_DEADLINE_MS);
  try {
    const res = await fetchImpl(path, { ...init, signal: controller.signal, credentials: "same-origin", redirect: "error",
      cache: "no-store", headers: { Accept: "application/json", ...(init.body ? { "Content-Type": "application/json" } : {}), ...extraHeaders } });
    const text = await res.text();
    if (new TextEncoder().encode(text).length > MAX_BODY_BYTES) return "too_large";
    return { status: res.status, text, csrf: res.headers.get("X-CSRF-Token") };
  } catch (e) {
    return controller.signal.aborted ? "deadline" : "network";
  } finally {
    clearTimeout(timer);
  }
}

function parse(text: string): unknown {
  try {
    return JSON.parse(text);
  } catch {
    return undefined;
  }
}

/**
 * Decode an error body against the ApiError schema (DR-012 D2): exactly {category, retryable, correlation_id,
 * field_errors?}, `retryable` fixed per category, no free-text message. Anything else, including a body without a
 * correlation id or `retryable`, is `internal` with no id. A category outside the browser-api boundary is `internal`.
 */
export function decodeError(body: unknown): { category: ErrorCategory; correlationId: string | null } {
  if (validate("ApiError", body).ok) {
    const o = body as { category: unknown; correlation_id: string };
    return { category: normaliseCategory(o.category), correlationId: CORRELATION_RE.test(o.correlation_id) ? o.correlation_id : null };
  }
  return { category: "internal", correlationId: null };
}

function interpret<T>(raw: Exclude<Raw, "network" | "deadline">, decode: Decoder<T>) {
  if (raw === "too_large") return { kind: "error" as const, category: "internal" as ErrorCategory, correlationId: null };
  const body = parse(raw.text);
  if (raw.status >= 200 && raw.status < 300) {
    const data = decode(body);
    return data === null
      ? { kind: "error" as const, category: "internal" as ErrorCategory, correlationId: null }
      : { kind: "ok" as const, data };
  }
  return { kind: "error" as const, ...decodeError(body) };
}

export async function read<T>(path: string, decode: Decoder<T>, fetchImpl: typeof fetch = fetch): Promise<ReadResult<T>> {
  const raw = await send(path, { method: "GET" }, fetchImpl);
  if (raw === "network" || raw === "deadline") return { kind: "unreachable" };
  return interpret(raw, decode);
}

/** A mutation carries an idempotency key chosen once per user intent; a user retry passes the same key. */
export async function mutate<T>(path: string, payload: Record<string, unknown>, idempotencyKey: string, decode: Decoder<T>,
  fetchImpl: typeof fetch = fetch): Promise<MutationResult<T>> {
  const raw = await send(path, { method: "POST", body: JSON.stringify({ ...payload, idempotency_key: idempotencyKey }) }, fetchImpl);
  if (raw === "network" || raw === "deadline") return { kind: "outcome_unknown" };
  return interpret(raw, decode);
}

/** A fresh idempotency key, kept in memory only (credential class; never stored or logged). */
export function newIdempotencyKey(): string {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

// ---- /healthz (Health in contracts/openapi.yaml: {status: "scaffold"}) ------------------------------------------
export const decodeHealth: Decoder<Health> = (v) => (validate("Health", v).ok ? (v as Health) : null);

export function health(fetchImpl: typeof fetch = fetch) {
  return read("/healthz", decodeHealth, fetchImpl);
}

// ---- cookie-authenticated exchange (M1-E04-S05, DR-015 D2) -----------------------------------------------------------
// Sign-in status, sign-in and sign-out. The session itself is an HttpOnly cookie the browser manages; JavaScript only
// ever sees the CSRF token, which arrives in the X-CSRF-Token response header, is held in memory and is sent back in
// the same header on state-changing requests. It is never stored (no cookies, no Web Storage) or logged.
export type ExchangeResult<T> =
  | { kind: "ok"; data: T; csrf: string | null }
  | { kind: "error"; category: ErrorCategory; correlationId: string | null }
  | { kind: "unreachable" };

const CSRF_RE = /^[A-Za-z0-9_-]{43}$/;

export async function exchange<T>(method: "GET" | "POST" | "DELETE", path: string, decode: Decoder<T>, opts: { body?: Record<string, unknown>;
  csrf?: string | null } = {}, fetchImpl: typeof fetch = fetch): Promise<ExchangeResult<T>> {
  const headers: Record<string, string> = opts.csrf ? { "X-CSRF-Token": opts.csrf } : {};
  const raw = await send(path, { method, ...(opts.body ? { body: JSON.stringify(opts.body) } : {}) }, fetchImpl, headers);
  if (raw === "network" || raw === "deadline") return { kind: "unreachable" };
  const r = interpret(raw, decode);
  if (r.kind === "ok") {
    const token = raw !== "too_large" ? raw.csrf : null;
    return { kind: "ok", data: r.data, csrf: token !== null && CSRF_RE.test(token) ? token : null };
  }
  return r;
}

// ---- WebSocket (serial console, M1-D) --------------------------------------------------------------------------------------------
/**
 * The only place that opens a WebSocket (like fetch, enforced by tools/check_frontend.py). Same-origin only: the URL is built from
 * the page's own scheme and host and a validated relative path, never from caller input, and carries no query string. The ticket
 * travels in the subprotocol list (a request header), never in the URL.
 */
export function openSocket(path: string, protocols: string[], loc: Pick<Location, "protocol" | "host"> = location,
  Impl: typeof WebSocket = WebSocket): WebSocket {
  assertPath(path);
  if (path.includes("?")) throw new Error("client: a socket path has no query string");
  const ws = new Impl(`${loc.protocol === "https:" ? "wss" : "ws"}://${loc.host}${path}`, protocols);
  ws.binaryType = "arraybuffer";
  return ws;
}
