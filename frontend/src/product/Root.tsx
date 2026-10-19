// The signed-in product shell: sign-in -> dashboard -> sign-out, with loading, failure and session-expired states.
// A 401 anywhere after sign-in means the session ended (idle or absolute timeout, or sign-out elsewhere).
import { useCallback, useEffect, useState } from "react";
import { AppShell, LoadingRegion, StatusMessage, ViewHeading, Button } from "../design-system";
import { sessionStatus, signIn, signOut } from "../api/session";
import { Dashboard } from "./Dashboard";
import { VmDetail } from "./VmDetail";
import { CreateVm } from "./Create";
import { Inventory } from "./Inventory";
import { ConsoleView } from "./Console";
import { GraphicsConsole } from "./GraphicsConsole";
import { Storage } from "./Storage";
import { Activity } from "./Activity";
import { Alerts } from "./Alerts";
import { read } from "../api/client";
import { decodeHost } from "../api/decoders";
import { Networks } from "./Networks";
import { SignIn, type SignInFailure } from "./SignIn";
import { RoleContext, type Role } from "./role";

type View =
  | { kind: "loading" }
  | { kind: "unreachable" }
  | { kind: "anonymous"; reason: "none" | "expired" }
  | { kind: "authenticated"; username: string; role: Role | null };

export function Root() {
  const [view, setView] = useState<View>({ kind: "loading" });
  const [failure, setFailure] = useState<SignInFailure>(null);
  const [pending, setPending] = useState(false);

  const check = useCallback(async () => {
    setView({ kind: "loading" });
    const r = await sessionStatus();
    if (r.kind === "unreachable") setView({ kind: "unreachable" });
    else if (r.kind === "error") setView({ kind: "unreachable" });
    else setView(r.data.authenticated && r.data.username ? { kind: "authenticated", username: r.data.username, role: r.data.role } : { kind: "anonymous", reason: "none" });
  }, []);

  useEffect(() => { void check(); }, [check]);

  async function submit(username: string, password: string) {
    setPending(true);
    setFailure(null);
    const r = await signIn(username, password);
    setPending(false);
    if (r.kind === "ok" && r.data.authenticated && r.data.username) {
      setView({ kind: "authenticated", username: r.data.username, role: r.data.role });
    } else if (r.kind === "unreachable") {
      setFailure("unreachable");
    } else if (r.kind === "error") {
      setFailure({ category: r.category, correlationId: r.correlationId });
      if (r.category === "forbidden") await sessionStatus(); // the pre-sign-in token was stale: fetch a fresh one
    } else {
      setFailure({ category: "internal", correlationId: null });
    }
  }

  async function leave() {
    setPending(true);
    let r = await signOut();
    if (r.kind === "error" && r.category === "forbidden") {
      await sessionStatus(); // our in-memory token was stale (for example another tab signed in again): refresh, retry once
      r = await signOut();
    }
    setPending(false);
    setFailure(null);
    setView(r.kind === "ok" || (r.kind === "error" && r.category === "unauthenticated") ? { kind: "anonymous", reason: "none" } : view);
  }

  const [query, setQuery] = useState("");
  const [refreshKey, setRefreshKey] = useState(0);
  const vmDetail = () => /^#\/vms\/([A-Za-z0-9][A-Za-z0-9._-]{0,62})$/.exec(location.hash)?.[1] ?? null;
  const consoleVm = () => /^#\/console\/([A-Za-z0-9][A-Za-z0-9._-]{0,62})$/.exec(location.hash)?.[1] ?? null;
  const graphicsVm = () => /^#\/graphics\/([A-Za-z0-9][A-Za-z0-9._-]{0,62})$/.exec(location.hash)?.[1] ?? null;
  const routeOf = () => (graphicsVm() ? "graphics" : consoleVm() ? "console" : vmDetail() ? "vm" : location.hash === "#/vms" ? "vms" : location.hash === "#/create" ? "create" : location.hash === "#/storage" ? "storage" : location.hash === "#/networks" ? "networks" : location.hash === "#/activity" ? "activity" : location.hash === "#/alerts" ? "alerts" : "dashboard");
  const [route, setRoute] = useState(routeOf);
  const [, setHashTick] = useState(0); // the route can stay "vm" or "console" while the VM in the address changes: re-render on every hash change
  useEffect(() => {
    const on = () => { setRoute(routeOf()); setHashTick((n) => n + 1); };
    window.addEventListener("hashchange", on);
    return () => window.removeEventListener("hashchange", on);
  }, []);
  // The count of open alerts for the header. It is a convenience: when it cannot be read nothing is shown and nothing else changes.
  const [openAlerts, setOpenAlerts] = useState(0);
  const signedIn = view.kind === "authenticated";
  useEffect(() => {
    if (!signedIn) { setOpenAlerts(0); return; }
    let alive = true;
    const tick = async () => {
      const r = await read("/api/v1/hosts/local", decodeHost);
      if (alive && r.kind === "ok") setOpenAlerts(r.data.observed.alerts.open);
    };
    void tick();
    const t = setInterval(() => { void tick(); }, 60000);
    return () => { alive = false; clearInterval(t); };
  }, [signedIn, refreshKey, route]);
  const expired = () => { setFailure(null); setView({ kind: "anonymous", reason: "expired" }); void sessionStatus(); };
  const nav = view.kind === "authenticated"
    ? [{ href: "#/", label: "Dashboard", icon: "dashboard" as const, current: route === "dashboard" }, { href: "#/vms", label: "Virtual machines", icon: "vms" as const, current: route === "vms" || route === "vm" || route === "create" || route === "console" || route === "graphics" },
      { href: "#/storage", label: "Storage and recovery", icon: "storage" as const, current: route === "storage" },
      { href: "#/networks", label: "Networks", icon: "networks" as const, current: route === "networks" },
      { href: "#/alerts", label: "Alerts", icon: "alerts" as const, current: route === "alerts" },
      { href: "#/activity", label: "Activity", icon: "activity" as const, current: route === "activity" }]
    : [{ href: "#main", label: "Sign in", icon: "signin" as const, current: true }];
  return (
    <AppShell nav={nav} user={view.kind === "authenticated" ? view.username : undefined} role={view.kind === "authenticated" ? view.role : null}
      search={view.kind === "authenticated" ? { value: query, onChange: (v) => { setQuery(v); if (route !== "vms" && route !== "activity" && route !== "alerts" && v !== "") location.hash = "#/vms"; } } : undefined}
      alerts={signedIn ? { open: openAlerts, href: "#/alerts" } : undefined}
      onRefresh={view.kind === "authenticated" ? () => setRefreshKey((k) => k + 1) : undefined}
      onSignOut={view.kind === "authenticated" ? leave : undefined} signingOut={pending}>
      {view.kind === "loading" ? (
        <>
          <ViewHeading title="Svavyom" focusOnMount={false} />
          <LoadingRegion label="Your session" loading />
        </>
      ) : null}
      {view.kind === "unreachable" ? (
        <>
          <ViewHeading title="Svavyom" />
          <StatusMessage tone="warning">Svavyom could not be reached. Check that the service is running, then try again.</StatusMessage>
          <div className="ds-button-row"><Button onClick={check}>Try again</Button></div>
        </>
      ) : null}
      {view.kind === "anonymous" ? <SignIn reason={view.reason} failure={failure} pending={pending} onSubmit={submit} /> : null}
      {view.kind === "authenticated" ? (
        <RoleContext.Provider value={view.role}>
          {route === "graphics" && graphicsVm() ? <GraphicsConsole key={`${graphicsVm()!}-${refreshKey}`} vm={graphicsVm()!} onSessionEnded={expired} /> : route === "console" && consoleVm() ? <ConsoleView key={`${consoleVm()!}-${refreshKey}`} vm={consoleVm()!} onSessionEnded={expired} /> : route === "create" ? <CreateVm key={refreshKey} onSessionEnded={expired} /> : route === "storage" ? <Storage refresh={refreshKey} query={query} onSessionEnded={expired} /> : route === "networks" ? <Networks refresh={refreshKey} query={query} onSessionEnded={expired} /> : route === "alerts" ? <Alerts refresh={refreshKey} query={query} onSessionEnded={expired} /> : route === "activity" ? <Activity refresh={refreshKey} query={query} onSessionEnded={expired} /> : route === "vm" && vmDetail() ? <VmDetail key={vmDetail()!} vmId={vmDetail()!} refresh={refreshKey} onSessionEnded={expired} /> : route === "vms" ? <Inventory refresh={refreshKey} query={query} onSessionEnded={expired} /> : <Dashboard refresh={refreshKey} onSessionEnded={expired} />}
        </RoleContext.Provider>
      ) : null}
    </AppShell>
  );
}
