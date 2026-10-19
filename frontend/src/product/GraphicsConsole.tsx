// Graphical console (DR-026 D1): the VM's screen, keyboard and pointer in the browser through noVNC. The page never talks to the VM's VNC server:
// it opens a same-origin WebSocket with a single-use ticket, the API and the console broker relay the RFB bytes, and the VNC server itself has no port.
// Like the serial console it is a full-power channel into the guest, off unless the operator enabled the console switch, and one viewer per VM.
import { useCallback, useEffect, useRef, useState } from "react";
import { Button, Checkbox, ErrorState, LoadingRegion, StatusMessage, UnreachableBanner, ViewHeading } from "../design-system";
import { read, type ReadResult } from "../api/client";
import { decodeVm } from "../api/decoders";
import { graphicsProtocols, graphicsSocketUrl, mintGraphicsTicket } from "../api/console";
import type { VM } from "../api/schema";

type Link = "idle" | "connecting" | "open" | "closed";

/** The part of noVNC's RFB object this view uses (the library is loaded when a console is opened, not with the page). */
interface Viewer {
  viewOnly: boolean;
  scaleViewport: boolean;
  disconnect(): void;
  sendCtrlAltDel(): void;
  focus(): void;
  addEventListener(type: string, fn: (e: Event) => void): void;
}

export function GraphicsConsole(props: { vm: string; onSessionEnded: () => void; loadViewer?: () => Promise<new (target: HTMLElement, url: string, o: { wsProtocols: string[]; shared: boolean }) => Viewer> }) {
  const { vm, onSessionEnded } = props;
  const [machine, setMachine] = useState<VM | null>(null);
  const [failure, setFailure] = useState<ReadResult<unknown> | null>(null);
  const [loading, setLoading] = useState(true);
  const [link, setLink] = useState<Link>("idle");
  const [notice, setNotice] = useState<string | null>(null);
  const [confirmed, setConfirmed] = useState(false);
  const [viewOnly, setViewOnly] = useState(false);
  const [name, setName] = useState("");
  const box = useRef<HTMLDivElement | null>(null);
  const viewer = useRef<Viewer | null>(null);
  const alive = useRef(true);

  const load = useCallback(async () => {
    const m = await read(`/api/v1/vms/${vm}`, decodeVm);
    if (!alive.current) return;
    setLoading(false);
    if (m.kind === "ok") { setMachine(m.data); setFailure(null); }
    else if (m.kind === "error" && m.category === "unauthenticated") onSessionEnded();
    else setFailure(m);
  }, [vm, onSessionEnded]);

  useEffect(() => {
    alive.current = true;
    void load();
    return () => { alive.current = false; viewer.current?.disconnect(); };
  }, [load]);

  async function connect() {
    setNotice(null);
    setLink("connecting");
    const t = await mintGraphicsTicket(vm);
    if (!alive.current) return;
    if (t.kind !== "ok") {
      setLink("idle");
      if (t.kind === "error" && t.category === "unauthenticated") { onSessionEnded(); return; }
      setNotice(t.kind === "error"
        ? t.category === "prohibited" ? "The console is not available: it is switched off on this installation, or this VM is not one Svavyom created."
          : t.category === "conflict" ? "The VM is not running or has no graphical console. A VM created before this release gets one with Enable graphical console while it is stopped."
          : t.category === "forbidden" ? "The request was refused. Reload the page and try again. Only operators and administrators can open a console."
          : "The console could not be opened. Try again later."
        : "Svavyom could not be reached. Try again.");
      return;
    }
    const target = box.current;
    if (!target) { setLink("idle"); return; }
    try {
      const RFB = await (props.loadViewer ? props.loadViewer() : import("@novnc/novnc").then((m) => m.default as unknown as new (t: HTMLElement, u: string, o: { wsProtocols: string[]; shared: boolean }) => Viewer));
      if (!alive.current) return;
      target.replaceChildren();
      const rfb = new RFB(target, graphicsSocketUrl(vm), { wsProtocols: graphicsProtocols(t.data.ticket), shared: false });
      rfb.scaleViewport = true;
      rfb.viewOnly = viewOnly;
      viewer.current = rfb;
      rfb.addEventListener("connect", () => { if (alive.current) { setLink("open"); rfb.focus(); } });
      rfb.addEventListener("desktopname", (e) => { const n = (e as CustomEvent<{ name: string }>).detail?.name; if (alive.current && typeof n === "string") setName(n.slice(0, 80)); });
      rfb.addEventListener("credentialsrequired", () => { rfb.disconnect(); }); // the VNC server asks for nothing; if it does, something is wrong
      rfb.addEventListener("disconnect", (e) => {
        if (viewer.current === rfb) viewer.current = null;
        if (!alive.current) return;
        const clean = (e as CustomEvent<{ clean: boolean }>).detail?.clean === true;
        setLink("closed");
        setNotice(clean ? "The console was closed." : "The console connection ended: the VM stopped, the time limit was reached, your session ended, or another viewer has it open. Open it again with a new connection.");
      });
    } catch {
      setLink("idle");
      setNotice("The console could not be opened.");
    }
  }

  function toggleViewOnly(v: boolean) {
    setViewOnly(v);
    if (viewer.current) viewer.current.viewOnly = v;
  }

  const running = machine?.observed.power === "running";
  const present = machine?.observed.graphical_console === "present";
  return (
    <>
      <ViewHeading title={`Graphical console: ${vm}`} />
      <p><a className="ds-link" href={`#/vms/${vm}`}>Back to {vm}</a> <a className="ds-link" href={`#/console/${vm}`}>Serial console</a></p>
      {failure?.kind === "unreachable" ? <UnreachableBanner lastKnown={null} onRetry={() => { void load(); }} /> : null}
      {failure?.kind === "error" ? <ErrorState category={failure.category} correlationId={failure.correlationId} onRetry={() => { void load(); }} /> : null}
      <LoadingRegion label="Graphical console" loading={loading}>
        <section aria-label="Graphical console status">
          <StatusMessage tone="warning">The graphical console is a full-power channel into the VM: what you type and click goes straight to the guest, and the guest&apos;s screen is shown here. Only one viewer can be open per VM, and it closes after an hour.</StatusMessage>
          {machine && !present ? <StatusMessage tone="warning">This VM has no graphical console device. A VM created before this release gets one when you stop it and choose Enable graphical console on its page.</StatusMessage> : null}
          {machine && present && !running ? <StatusMessage tone="warning">The VM is not running, so there is no screen to show. Start it first.</StatusMessage> : null}
          {machine?.observed.rescue ? <StatusMessage tone="warning">This VM is in rescue mode: it boots the rescue system, and its own disk is attached as an extra disk.</StatusMessage> : null}
          {notice ? <StatusMessage tone="warning">{notice}</StatusMessage> : null}
        </section>
        <section aria-label="Controls">
          {link === "idle" || link === "closed" ? (
            <div className="ds-button-row">
              <Checkbox label="I understand this opens a live console into the VM" checked={confirmed} onChange={setConfirmed} />
              <Button variant="primary" onClick={() => { void connect(); }} disabled={!confirmed || !running || !present}>{link === "closed" ? "Open the console again" : "Open graphical console"}</Button>
            </div>
          ) : null}
          {link === "connecting" ? <StatusMessage tone="warning">Opening the console…</StatusMessage> : null}
          {link === "open" ? (
            <div className="ds-button-row">
              <Button onClick={() => viewer.current?.sendCtrlAltDel()}>Send Ctrl-Alt-Del</Button>
              <Checkbox label="View only (keyboard and pointer are not sent)" checked={viewOnly} onChange={toggleViewOnly} />
              <Button variant="destructive" onClick={() => viewer.current?.disconnect()}>Disconnect</Button>
            </div>
          ) : null}
          {link === "open" && name ? <p className="ds-muted">Connected to {name}. Click the screen to type into the VM; to leave it, click outside the screen.</p> : null}
        </section>
        <div ref={box} className="ds-vnc" role="application" aria-label={`Screen of ${vm}`} hidden={link === "idle" || link === "closed"} />
      </LoadingRegion>
    </>
  );
}
