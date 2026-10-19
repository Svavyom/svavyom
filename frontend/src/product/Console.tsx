// VM recovery view (M1-D-S04): the bounded serial boot output, the SSH knowledge Svavyom actually has, and the interactive serial
// console. Everything shown is observation: Svavyom never runs SSH, never logs in, and says plainly what this release does not offer
// (a graphical console and rescue mode). The interactive console is a full-power channel into the guest and is off unless the
// operator enabled it.
import { useCallback, useEffect, useRef, useState } from "react";
import { Button, Checkbox, ErrorState, LoadingRegion, StatusMessage, TextField, UnreachableBanner, ViewHeading } from "../design-system";
import { read, type ReadResult } from "../api/client";
import { decodeVm } from "../api/decoders";
import { appendTerminal, mintTicket, openConsole, readSerial, type SerialOutput, type SerialState } from "../api/console";
import type { VM } from "../api/schema";

const STATE_TEXT: Record<SerialState, string> = {
  available: "Boot output is available.",
  no_output: "No output has been received yet. A VM that is stopped, still starting, or whose guest writes nothing to its serial port shows nothing here.",
  not_configured: "This VM has no serial console Svavyom can use, or it was not created by Svavyom.",
  unavailable: "Svavyom could not read the console right now: the console service or the host is not reachable. Nothing is known about this VM's output.",
};

/** What Svavyom knows about reaching the VM over SSH: only what it observed. It never connects. */
export function sshKnowledge(vm: VM | null): string {
  if (!vm) return "Unknown";
  const o = vm.observed;
  if (o.power !== "running") return "Unknown: the VM is not running.";
  if (!o.ip_address) return "Unknown: no address has been observed for this VM yet.";
  if (!o.login_user) return `Address ${o.ip_address} observed; the login user is not known.`;
  return `Address ${o.ip_address} and login user ${o.login_user} observed. That does not prove SSH works: Svavyom never connects to the VM.`;
}

type Link = "idle" | "connecting" | "open" | "closed";

const CLOSE_TEXT: Record<number, string> = {
  1000: "The console was closed.", 1001: "The console connection ended (the VM stopped, or the time limit was reached).",
  1008: "Your session ended, so the console was closed.", 1009: "The console was closed because a message was too large.",
};

export function ConsoleView(props: { vm: string; onSessionEnded: () => void }) {
  const { vm, onSessionEnded } = props;
  const [serial, setSerial] = useState<SerialOutput | null>(null);
  const [failure, setFailure] = useState<ReadResult<unknown> | null>(null);
  const [machine, setMachine] = useState<VM | null>(null);
  const [loading, setLoading] = useState(true);
  const [link, setLink] = useState<Link>("idle");
  const [notice, setNotice] = useState<string | null>(null);
  const [screen, setScreen] = useState("");
  const [typed, setTyped] = useState("");
  const [confirmed, setConfirmed] = useState(false);
  const sock = useRef<WebSocket | null>(null);
  const alive = useRef(true);
  const decoder = useRef(new TextDecoder("utf-8", { fatal: false }));

  const load = useCallback(async () => {
    const [s, m] = await Promise.all([readSerial(vm), read(`/api/v1/vms/${vm}`, decodeVm)]);
    if (!alive.current) return;
    setLoading(false);
    if (m.kind === "ok") setMachine(m.data);
    if (s.kind === "ok") {
      setSerial(s.data);
      setFailure(null);
    } else if (s.kind === "error" && s.category === "unauthenticated") {
      onSessionEnded();
    } else {
      setFailure(s);
    }
  }, [vm, onSessionEnded]);

  useEffect(() => {
    alive.current = true;
    void load();
    return () => { alive.current = false; sock.current?.close(1000); };
  }, [load]);

  // While no interactive session is open, the boot output refreshes on its own.
  useEffect(() => {
    if (link === "open" || link === "connecting") return;
    const t = setInterval(() => { void load(); }, 4000);
    return () => clearInterval(t);
  }, [link, load]);

  async function connect() {
    setNotice(null);
    setLink("connecting");
    const t = await mintTicket(vm);
    if (!alive.current) return;
    if (t.kind !== "ok") {
      setLink("idle");
      if (t.kind === "error" && t.category === "unauthenticated") { onSessionEnded(); return; }
      setNotice(t.kind === "error"
        ? t.category === "prohibited" ? "The interactive console is not available: it is switched off on this installation, or this VM is not one Svavyom created."
          : t.category === "conflict" ? "The VM is not running, so there is no console to open."
          : t.category === "forbidden" ? "The request was refused. Reload the page and try again."
          : "The console could not be opened. Try again later."
        : "Svavyom could not be reached. Try again.");
      return;
    }
    let ws: WebSocket;
    try {
      ws = openConsole(vm, t.data.ticket);
    } catch {
      setLink("idle");
      setNotice("The console could not be opened.");
      return;
    }
    sock.current = ws;
    decoder.current = new TextDecoder("utf-8", { fatal: false });
    setScreen("");
    ws.onopen = () => { if (alive.current) setLink("open"); };
    ws.onmessage = (e: MessageEvent) => {
      if (!alive.current || Object.prototype.toString.call(e.data) !== "[object ArrayBuffer]") return; // binary frames only; text is never rendered
      const text = decoder.current.decode(new Uint8Array(e.data), { stream: true });
      setScreen((prev) => appendTerminal(prev, text));
    };
    ws.onclose = (e: CloseEvent) => {
      if (sock.current === ws) sock.current = null;
      if (!alive.current) return;
      setLink("closed");
      setNotice(CLOSE_TEXT[e.code] ?? "The console connection ended. Open it again with a new connection.");
      if (e.code === 1008) onSessionEnded();
    };
    ws.onerror = () => { /* the close event that follows carries the outcome */ };
  }

  function send(data: string) {
    const ws = sock.current;
    if (!ws || ws.readyState !== WebSocket.OPEN || data === "") return;
    ws.send(new TextEncoder().encode(data));
  }

  function disconnect() {
    sock.current?.close(1000);
  }

  const running = machine?.observed.power === "running";
  return (
    <>
      <ViewHeading title={`Console: ${vm}`} />
      <p><a className="ds-link" href="#/vms">Back to virtual machines</a></p>
      {failure?.kind === "unreachable" ? <UnreachableBanner lastKnown={null} onRetry={() => { void load(); }} /> : null}
      {failure?.kind === "error" ? <ErrorState category={failure.category} correlationId={failure.correlationId} onRetry={() => { void load(); }} /> : null}
      <LoadingRegion label="Console" loading={loading}>
        <section aria-label="Reaching this VM">
          <h2>Reaching this VM</h2>
          <p>Power: {machine ? machine.observed.power : "unknown"}. SSH: {sshKnowledge(machine)}</p>
          <p>When SSH does not work, the serial output below shows how far the guest got, and the serial console lets you log in if the guest allows it. For a screen, keyboard and pointer use the <a className="ds-link" href={`#/graphics/${vm}`}>graphical console</a>; for a lost password or a damaged boot loader, rescue mode on the VM&apos;s page boots a rescue system with this VM&apos;s disk attached.</p>
        </section>
        <section aria-label="Serial boot output">
          <h2>Serial boot output</h2>
          {serial ? <p>{STATE_TEXT[serial.state]}{serial.truncated ? " Only the most recent output is shown." : ""}</p> : null}
          {serial && serial.state === "available" ? <pre className="ds-code" tabIndex={0} aria-label="Serial boot output text">{serial.text}</pre> : null}
          <div className="ds-button-row"><Button onClick={() => { void load(); }}>Refresh output</Button></div>
        </section>
        <section aria-label="Serial console">
          <h2>Serial console</h2>
          <StatusMessage tone="warning">The serial console is a full-power channel into the VM: whatever you type goes straight to the guest, and what the guest prints is shown here. Only one console can be open per VM.</StatusMessage>
          {notice ? <StatusMessage tone="warning">{notice}</StatusMessage> : null}
          {link === "idle" || link === "closed" ? (
            <div className="ds-button-row">
              <Checkbox label="I understand this opens a live console into the VM" checked={confirmed} onChange={setConfirmed} />
              <Button variant="primary" onClick={() => { void connect(); }} disabled={!confirmed || !running}>{link === "closed" ? "Open the console again" : "Open serial console"}</Button>
            </div>
          ) : null}
          {link === "connecting" ? <StatusMessage tone="warning">Opening the console…</StatusMessage> : null}
          {link !== "idle" ? <pre className="ds-code" role="log" aria-live="off" tabIndex={0} aria-label="Serial console output">{screen}</pre> : null}
          {link === "open" ? (
            <form onSubmit={(e) => { e.preventDefault(); send(`${typed}\r`); setTyped(""); }}>
              <TextField label="Send to the console" description="Type a line and press Enter. It is sent to the VM exactly as typed." value={typed} onChange={setTyped} />
              <div className="ds-button-row">
                <Button type="submit" variant="primary">Send</Button>
                <Button onClick={() => send("\x03")}>Send Ctrl-C</Button>
                <Button onClick={() => send("\x04")}>Send Ctrl-D</Button>
                <Button variant="destructive" onClick={disconnect}>Disconnect</Button>
              </div>
            </form>
          ) : null}
        </section>
      </LoadingRegion>
    </>
  );
}
