// TEST-ONLY gallery app (M0-E02-S06 r5 sections 2, 9): every manifest state at #/state/<Primitive>/<state>,
// journey skeletons at #/journey/J<n>. Built only with `vite build --mode gallery` into dist-gallery/.
import { useEffect, useState } from "react";
import manifest from "../design-system/states.json";
import { AppShell, ViewHeading } from "../design-system";
import { RENDERERS } from "./states";
import { J1HostStatus, J2AuthState, J3Dashboard, J4Wizard, J5Operation, J6Errors, J7Delete, J9Power, J10Console } from "../journeys/journeys";

function useHash() {
  const [hash, setHash] = useState(location.hash);
  useEffect(() => {
    const on = () => setHash(location.hash);
    addEventListener("hashchange", on);
    return () => removeEventListener("hashchange", on);
  }, []);
  return hash;
}

function query(hash: string, key: string): string | null {
  const q = hash.split("?")[1];
  return q ? new URLSearchParams(q).get(key) : null;
}

const NAV = [{ href: "#/", label: "Gallery index" }];

function Index() {
  return (
    <AppShell nav={NAV}>
      <ViewHeading title="Design-system gallery (test only)" />
      <section className="ds-gallery-index" aria-labelledby="states-h">
        <h2 id="states-h">Primitive states</h2>
        <ul>
          {Object.entries(manifest.primitives).flatMap(([p, states]) => states.map((s) => (
            <li key={`${p}/${s}`}><a className="ds-link" href={`#/state/${p}/${s}`}>{p}: {s}</a></li>
          )))}
        </ul>
      </section>
      <section aria-labelledby="journeys-h">
        <h2 id="journeys-h">Journey skeletons</h2>
        <ul>
          {["J1", "J2", "J3", "J4", "J5", "J6", "J7", "J8", "J9", "J10"].map((j) => (
            <li key={j}><a className="ds-link" href={`#/journey/${j}`}>{j}</a></li>
          ))}
        </ul>
      </section>
    </AppShell>
  );
}

function StatePage({ primitive, state }: { primitive: string; state: string }) {
  const render = RENDERERS[primitive]?.[state];
  if (primitive === "AppShell") {
    return (
      <AppShell nav={[...NAV, { href: "#/state/AppShell/default", label: "App shell", current: true }]}>
        <ViewHeading title="AppShell: default" />
        <p>Banner, navigation and main landmarks with one h1.</p>
      </AppShell>
    );
  }
  return (
    <AppShell nav={NAV}>
      <ViewHeading title={`${primitive}: ${state}`} />
      <div data-gallery-state={`${primitive}/${state}`}>{render ? render() : <p>Unknown state.</p>}</div>
    </AppShell>
  );
}

function JourneyPage({ id, hash }: { id: string; hash: string }) {
  const vm = query(hash, "vm") ?? "vm-a";
  const opMatch = /^#\/journey\/J5\/operations\/([^?]+)/.exec(hash);
  const body = {
    J1: <J1HostStatus />, J2: <J2AuthState />, J3: <J3Dashboard />, J4: <J4Wizard />,
    J5: <J5Operation id={opMatch ? decodeURIComponent(opMatch[1]) : null} />, J6: <J6Errors />,
    J7: <J7Delete id={vm} />, J8: <J1HostStatus />, J9: <J9Power id={vm} />,
    J10: <J10Console id={vm} opened={hash.startsWith("#/journey/J10/console")} />,
  }[id];
  return <AppShell nav={NAV}>{body ?? <ViewHeading title="Unknown journey" />}</AppShell>;
}

export function Gallery() {
  const hash = useHash();
  const state = /^#\/state\/([A-Za-z]+)\/([A-Za-z0-9_-]+)$/.exec(hash);
  if (state) return <StatePage key={hash} primitive={state[1]} state={state[2]} />;
  const journey = /^#\/journey\/(J[0-9]{1,2})/.exec(hash);
  if (journey) return <JourneyPage key={hash} id={journey[1]} hash={hash} />;
  return <Index />;
}
