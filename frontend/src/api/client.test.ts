// fe-unit: client decode, deadline and idempotency behaviour (AC01; negative cases are in client.negative.test.ts).
import { afterEach, describe, expect, it, vi } from "vitest";
import { REQUEST_DEADLINE_MS, health, mutate, read } from "./client";
import { CORRELATION_ID, apiError, operation } from "./fixtures";

afterEach(() => vi.useRealTimers());

const ok = (body: unknown, status = 200) => vi.fn(async () => new Response(JSON.stringify(body), { status }));
const never = () => vi.fn((_u: RequestInfo | URL, init?: RequestInit) => new Promise<Response>((_r, reject) =>
  init?.signal?.addEventListener("abort", () => reject(new DOMException("aborted", "AbortError")))));

describe("api client", () => {
  it("health decodes the contract shape", async () => {
    expect(await health(ok({ status: "scaffold" }) as unknown as typeof fetch)).toEqual({ kind: "ok", data: { status: "scaffold" } });
  });

  it("read deadline gives unreachable", async () => {
    vi.useFakeTimers();
    const p = read("/healthz", () => ({}), never() as unknown as typeof fetch);
    await vi.advanceTimersByTimeAsync(REQUEST_DEADLINE_MS + 1);
    expect(await p).toEqual({ kind: "unreachable" });
  });

  it("mutation deadline gives outcome_unknown", async () => {
    vi.useFakeTimers();
    const p = mutate("/api/v1/operations", { type: "create" }, "k1", () => ({}), never() as unknown as typeof fetch);
    await vi.advanceTimersByTimeAsync(REQUEST_DEADLINE_MS + 1);
    expect(await p).toEqual({ kind: "outcome_unknown" });
  });

  it("typed error bodies map to their category", async () => {
    const r = await read("/api/v1/vms", () => null, ok(apiError("forbidden"), 403) as unknown as typeof fetch);
    expect(r).toEqual({ kind: "error", category: "forbidden", correlationId: CORRELATION_ID });
  });

  it("sends same-origin requests with the idempotency key in the body", async () => {
    const f = ok(operation());
    await mutate("/api/v1/operations", { type: "create", kind: "VM", id: "web-1" }, "key-1", (v) => v, f as unknown as typeof fetch);
    const [url, init] = f.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe("/api/v1/operations");
    expect(init.credentials).toBe("same-origin");
    expect(JSON.parse(init.body as string).idempotency_key).toBe("key-1");
  });
});
