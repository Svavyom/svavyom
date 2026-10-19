// Authentication session API (M1-E04-S05, DR-015 D2; contracts/openapi.yaml /api/v1/auth/session).
// The CSRF token lives in this module's memory only: it is never put in Web Storage or a cookie, never logged and
// never placed in a URL. The session cookie itself is HttpOnly and invisible to scripts.
import { exchange, type ExchangeResult } from "./client";
import { decoderFor } from "./decoders";
import type { AuthSession } from "./schema";

const decodeAuthSession = decoderFor<AuthSession>("AuthSession");

let csrf: string | null = null;

function remember<T>(r: ExchangeResult<T>): ExchangeResult<T> {
  // Only the session endpoints (re)issue a token; an operation reply carries none and must not erase the one in use.
  if (r.kind === "ok" && r.csrf) csrf = r.csrf;
  return r;
}

/** The CSRF token for state-changing requests of other modules (memory only; null before the first status/sign-in). */
export function csrfToken(): string | null {
  return csrf;
}

/** Test hook: forget the in-memory token. */
export function forgetCsrf(): void {
  csrf = null;
}

export function sessionStatus(fetchImpl: typeof fetch = fetch) {
  return exchange("GET", "/api/v1/auth/session", decodeAuthSession, {}, fetchImpl).then(remember);
}

export function signIn(username: string, password: string, fetchImpl: typeof fetch = fetch) {
  return exchange("POST", "/api/v1/auth/session", decodeAuthSession, { body: { username, password }, csrf }, fetchImpl).then(remember);
}

export function signOut(fetchImpl: typeof fetch = fetch) {
  return exchange("DELETE", "/api/v1/auth/session", decodeAuthSession, { csrf }, fetchImpl).then(remember);
}

// ---- VM create / start (DR-016) ---------------------------------------------------------------------------------------------
// A mutation is NEVER re-sent automatically: if the network fails after the request left, the outcome is unknown and only the
// administrator may retry (with the same idempotency key, so the server can recognise the replay).
import { decodeOperation } from "./decoders";

export function submitOperation(body: Record<string, unknown>, fetchImpl: typeof fetch = fetch) {
  return exchange("POST", "/api/v1/operations", decodeOperation, { body, csrf }, fetchImpl).then(remember);
}
