// Serial console client (M1-D). The console route family (/console/v1/...) is separate from the OpenAPI /api/v1 convention (a WebSocket
// upgrade has no place in its JSON-only subset); its contract is docs/CONSOLE.md and contracts/console-channel.json. The same rules apply:
// same-origin relative paths, strict decoding, the typed Error envelope, a CSRF token held in memory only. A ticket is never stored,
// logged or put in a URL: it travels only in the WebSocket subprotocol header.
import { exchange, openSocket, read, type Decoder, type ExchangeResult, type ReadResult } from "./client";
import { csrfToken } from "./session";

export type SerialState = "unavailable" | "not_configured" | "no_output" | "available";
export interface SerialOutput { state: SerialState; text: string; truncated: boolean; running: boolean }
export interface ConsoleTicket { ticket: string; expires_at: string }

const STATES: ReadonlyArray<string> = ["unavailable", "not_configured", "no_output", "available"];
const MAX_TEXT = 128 * 1024;

export const decodeSerial: Decoder<SerialOutput> = (v) => {
  if (typeof v !== "object" || v === null || Array.isArray(v)) return null;
  const o = v as Record<string, unknown>;
  const keys = Object.keys(o).sort().join(",");
  if (keys !== "running,state,text,truncated") return null;
  if (typeof o.state !== "string" || !STATES.includes(o.state) || typeof o.text !== "string" || o.text.length > MAX_TEXT
    || typeof o.truncated !== "boolean" || typeof o.running !== "boolean") return null;
  return o as unknown as SerialOutput;
};

const TICKET_RE = /^[A-Za-z0-9_-]{43}$/;
export const decodeTicket: Decoder<ConsoleTicket> = (v) => {
  if (typeof v !== "object" || v === null || Array.isArray(v)) return null;
  const o = v as Record<string, unknown>;
  if (Object.keys(o).sort().join(",") !== "expires_at,ticket" || typeof o.ticket !== "string" || !TICKET_RE.test(o.ticket)
    || typeof o.expires_at !== "string" || Number.isNaN(Date.parse(o.expires_at))) return null;
  return o as unknown as ConsoleTicket;
};

const NAME_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$/;
function vmPath(vm: string, leaf: string): string {
  if (!NAME_RE.test(vm)) throw new Error("console: invalid VM name");
  return `/console/v1/vms/${vm}/${leaf}`;
}

export function readSerial(vm: string, fetchImpl: typeof fetch = fetch): Promise<ReadResult<SerialOutput>> {
  return read(vmPath(vm, "serial"), decodeSerial, fetchImpl);
}

export function mintTicket(vm: string, fetchImpl: typeof fetch = fetch): Promise<ExchangeResult<ConsoleTicket>> {
  return exchange("POST", vmPath(vm, "tickets"), decodeTicket, { csrf: csrfToken() }, fetchImpl);
}

export const CONSOLE_SUBPROTOCOL = "svavyom.console.v1";

/** The subprotocol list that carries the ticket. */
export function socketProtocols(ticket: string): string[] {
  if (!TICKET_RE.test(ticket)) throw new Error("console: invalid ticket");
  return [CONSOLE_SUBPROTOCOL, `t.${ticket}`];
}

/** Open the interactive console of a VM with a freshly minted ticket. */
export function openConsole(vm: string, ticket: string, Impl: typeof WebSocket = WebSocket): WebSocket {
  return openSocket(vmPath(vm, "socket"), socketProtocols(ticket), location, Impl);
}

// ---- terminal text -----------------------------------------------------------------------------------------------------------
const ESC_RE = /\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07\x1b]*(?:\x07|\x1b\\)|[@-Z\\-_])/g;

/** Append console output to the visible buffer: no escape sequences, backspace erases, a bare CR starts the line over, bounded size. */
export function appendTerminal(buffer: string, chunk: string, max = 200_000): string {
  let out = buffer;
  for (const ch of chunk.replace(ESC_RE, "")) {
    if (ch === "\b" || ch === "\x7f") {
      if (out.length > 0 && out[out.length - 1] !== "\n") out = out.slice(0, -1);
    } else if (ch === "\r") {
      continue;
    } else if (ch === "\n" || ch === "\t" || ch >= " ") {
      out += ch;
    }
  }
  return out.length > max ? out.slice(out.length - max) : out;
}

// ---- graphical console (DR-026 D1) -------------------------------------------------------------------------------------------
export const GRAPHICS_SUBPROTOCOL = "svavyom.graphics.v1";

export function mintGraphicsTicket(vm: string, fetchImpl: typeof fetch = fetch): Promise<ExchangeResult<ConsoleTicket>> {
  return exchange("POST", vmPath(vm, "graphics-tickets"), decodeTicket, { csrf: csrfToken() }, fetchImpl);
}

/** The subprotocol list that carries the ticket of a graphical console. */
export function graphicsProtocols(ticket: string): string[] {
  if (!TICKET_RE.test(ticket)) throw new Error("console: invalid ticket");
  return [GRAPHICS_SUBPROTOCOL, `t.${ticket}`];
}

/** The same-origin WebSocket address of a VM's graphical console. It has no query string; the ticket is not in it. */
export function graphicsSocketUrl(vm: string, loc: Pick<Location, "protocol" | "host"> = location): string {
  return `${loc.protocol === "https:" ? "wss" : "ws"}://${loc.host}${vmPath(vm, "graphics-socket")}`;
}
