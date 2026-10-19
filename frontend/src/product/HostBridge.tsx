// Host bridge (M1-E03-S02, DR-024 D5): what svavyom-ctl recorded about putting the host's uplink on a bridge so VMs can join the host's own network.
// This card only reports. Planning, applying, confirming and undoing need root on the host (`svavyom-ctl bridge ...`): the API has no network privilege,
// so a mistake made in a browser can never take the host off the network. While a change is waiting for confirmation the countdown is shown here and
// the previous configuration returns by itself when it reaches zero.
import { useEffect, useState } from "react";
import { StatusMessage, StatusPill } from "../design-system";
import type { Host } from "../api/schema";

type Bridge = NonNullable<Host["observed"]["bridge"]>;

function Countdown(props: { seconds: number; onExpired: () => void }) {
  const [left, setLeft] = useState(props.seconds);
  useEffect(() => { setLeft(props.seconds); }, [props.seconds]);
  useEffect(() => {
    if (left <= 0) {
      const t = window.setTimeout(props.onExpired, 4000);
      return () => window.clearTimeout(t);
    }
    const t = window.setTimeout(() => setLeft((n) => n - 1), 1000);
    return () => window.clearTimeout(t);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [left]);
  return <strong>{left > 0 ? `${left} seconds left` : "no time left; the previous configuration is being restored"}</strong>;
}

export function HostBridgeCard(props: { bridge: Bridge | null; onExpired: () => void }) {
  const b = props.bridge;
  return (
    <section className="ds-card" aria-labelledby="host-bridge-title">
      <h2 id="host-bridge-title">Host bridge</h2>
      {b === null ? (
        <>
          <p>No host bridge. VMs on Svavyom-managed networks use NAT: they can reach outside through the host but are not on the host&apos;s own network.</p>
          <p>To let VMs join the host&apos;s own network, an administrator plans a bridge on the host with <code>sudo svavyom-ctl bridge plan</code>. The plan shows the exact change to the network configuration and nothing is changed until it is applied and confirmed.</p>
        </>
      ) : b.state === "planned" ? (
        <>
          <p><StatusPill tone="neutral">Planned</StatusPill> A bridge <strong>{b.bridge}</strong> for <strong>{b.interface}</strong> has been planned. Nothing on the host network has changed yet.</p>
          <p>An administrator applies it on the host with <code>sudo svavyom-ctl bridge apply</code>, typing the bridge name to confirm. Applying starts a countdown; the previous configuration returns by itself unless it is confirmed in time.</p>
        </>
      ) : b.state === "pending_confirmation" ? (
        <>
          <StatusMessage tone="warning">
            The host network is being changed. Bridge <strong>{b.bridge}</strong> now carries <strong>{b.interface}</strong>&apos;s addressing: <Countdown seconds={b.seconds_left ?? 0} onExpired={props.onExpired} />.
          </StatusMessage>
          <p>If you can read this page on the new setup, keep it: from a session on the host&apos;s address run <code>sudo svavyom-ctl bridge confirm</code>. If you do nothing, or if the network does not work, the previous configuration is restored automatically (also after a reboot).</p>
        </>
      ) : (
        <p><StatusPill tone="ok">Active</StatusPill> Bridge <strong>{b.bridge}</strong> carries the host&apos;s network{b.interface === "none" ? "" : <> (uplink <strong>{b.interface}</strong>)</>}. An administrator can undo it on the host with <code>sudo svavyom-ctl bridge rollback</code>.</p>
      )}
    </section>
  );
}
