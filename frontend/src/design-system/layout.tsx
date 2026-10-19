// Layout primitives (M0-E02-S06 r5 sections 2, 4, 5, 8): skip link, app shell landmarks, view heading focus,
// data table in its own labelled scroll region.
import { useEffect, useRef, useState, type ReactNode } from "react";
import { Bell, Database, History, LayoutDashboard, LogIn, LogOut, Menu, Monitor, Moon, Network, RefreshCw, Search, Server, Sun, type LucideIcon } from "lucide-react";

export function SkipLink() {
  return (
    <a className="ds-skip-link" href="#main"
      onClick={(e) => { e.preventDefault(); document.getElementById("main")?.focus(); }}>
      Skip to main content
    </a>
  );
}

export type NavIcon = "dashboard" | "vms" | "storage" | "networks" | "alerts" | "activity" | "signin";
const NAV_ICONS: Record<NavIcon, LucideIcon> = { dashboard: LayoutDashboard, vms: Server, storage: Database, networks: Network, alerts: Bell, activity: History, signin: LogIn };

export type ThemeMode = "system" | "light" | "dark";
const THEME_NEXT: Record<ThemeMode, ThemeMode> = { system: "light", light: "dark", dark: "system" };
const THEME_LABEL: Record<ThemeMode, string> = { system: "System", light: "Light", dark: "Dark" };

/** Theme choice: System (follow the operating system), Light or Dark. Held in memory for this page only: the frontend never uses
 * browser storage or cookies (tools/check_frontend.py), so a reload returns to System. */
export function ThemeToggle() {
  const [mode, setMode] = useState<ThemeMode>("system");
  useEffect(() => {
    const root = document.documentElement;
    if (mode === "system") root.removeAttribute("data-theme");
    else root.setAttribute("data-theme", mode);
  }, [mode]);
  const Icon = mode === "light" ? Sun : mode === "dark" ? Moon : Monitor;
  return (
    <button type="button" className="ds-iconbutton" onClick={() => setMode(THEME_NEXT[mode])}
      aria-label={`Theme: ${THEME_LABEL[mode]}. Activate to switch to ${THEME_LABEL[THEME_NEXT[mode]]}.`}>
      <Icon size={18} aria-hidden="true" /><span className="ds-iconbutton-label" aria-hidden="true">{THEME_LABEL[mode]}</span>
    </button>
  );
}

export interface ShellSearch { value: string; onChange: (v: string) => void }

/** Application shell. Page-independent controls live here, once: search, refresh and theme in the header; sign out in the rail. */
export function AppShell({ nav, user, role, search, onRefresh, onSignOut, signingOut, alerts, children }: {
  nav: ReadonlyArray<{ href: string; label: string; current?: boolean; icon?: NavIcon }>; user?: string; role?: string | null;
  search?: ShellSearch; onRefresh?: () => void; onSignOut?: () => void; signingOut?: boolean; children: ReactNode;
  /** Open alerts: a link in the header while there is at least one. */
  alerts?: { open: number; href: string };
}) {
  const [open, setOpen] = useState(false);
  return (
    <>
      <SkipLink />
      <div className="ds-app">
        <aside className={`ds-side${open ? " ds-side--open" : ""}`} id="ds-side">
          <div className="ds-side-brand"><span className="ds-logo" aria-hidden="true">S</span><span>Svavyom</span></div>
          <nav className="ds-shell-nav" aria-label="Primary">
            <ul>
              {nav.map((n) => {
                const Icon = NAV_ICONS[n.icon ?? "dashboard"];
                return (
                  <li key={n.href}>
                    <a className="ds-navlink" href={n.href} aria-current={n.current ? "page" : undefined} onClick={() => setOpen(false)}>
                      <Icon size={18} aria-hidden="true" /><span>{n.label}</span>
                    </a>
                  </li>
                );
              })}
            </ul>
          </nav>
          <div className="ds-side-foot">
            {onSignOut ? (
              <button type="button" className="ds-navlink ds-signout" onClick={onSignOut} aria-disabled={signingOut ? "true" : undefined}>
                <LogOut size={18} aria-hidden="true" /><span>Sign out</span>
                {signingOut ? <span className="ds-visually-hidden"> (in progress)</span> : null}
              </button>
            ) : null}
            <p>Development Preview<br />Single host</p>
            <p className="ds-licence"><a href="/licence.txt">Free software (AGPL-3.0-or-later): licence and source</a></p>
          </div>
        </aside>
        <div className="ds-body">
          <header className="ds-shell-header">
            <button type="button" className="ds-iconbutton ds-menu-button" aria-expanded={open} aria-controls="ds-side"
              onClick={() => setOpen(!open)}>
              <Menu size={18} aria-hidden="true" /><span className="ds-iconbutton-label">Menu</span>
            </button>
            <span className="ds-shell-brand">Svavyom</span>
            {search ? (
              <label className="ds-search">
                <Search size={16} aria-hidden="true" />
                <span className="ds-visually-hidden">Search virtual machines</span>
                <input type="search" value={search.value} onChange={(e) => search.onChange(e.target.value)} placeholder="Search VMs" autoComplete="off" />
              </label>
            ) : null}
            {onRefresh ? (
              <button type="button" className="ds-iconbutton" onClick={onRefresh}>
                <RefreshCw size={16} aria-hidden="true" /><span className="ds-iconbutton-label">Refresh</span>
              </button>
            ) : null}
            {alerts && alerts.open > 0 ? (
              <a className="ds-alertlink" href={alerts.href}><span className="ds-pill ds-pill--bad">{alerts.open === 1 ? "1 open alert" : `${alerts.open} open alerts`}</span></a>
            ) : null}
            <ThemeToggle />
            {user ? <p className="ds-user">Signed in as <strong>{user}</strong>{role ? <> <span className="ds-badge">{role}</span></> : null}</p> : null}
          </header>
          <main id="main" tabIndex={-1} className="ds-shell-main">
            {children}
          </main>
        </div>
      </div>
    </>
  );
}

/** Page title row: the single h1 on the left, page-level actions on the right. */
export function PageHead({ title, actions, children }: { title: string; actions?: ReactNode; children?: ReactNode }) {
  return (
    <div className="ds-pagehead">
      <div className="ds-pagehead-main"><ViewHeading title={title} />{children}</div>
      {actions ? <div className="ds-pagehead-actions">{actions}</div> : null}
    </div>
  );
}

/** The single h1 of a view: on view change it receives focus and document.title names the view (r5 section 5). */
export function ViewHeading({ title, focusOnMount = true }: { title: string; focusOnMount?: boolean }) {
  const ref = useRef<HTMLHeadingElement>(null);
  useEffect(() => {
    document.title = `${title} - Svavyom`;
    if (focusOnMount) ref.current?.focus();
  }, [title, focusOnMount]);
  return <h1 ref={ref} tabIndex={-1}>{title}</h1>;
}

export function DataTable<T>(props: {
  caption: string; rows: ReadonlyArray<T>; rowKey: (r: T) => string;
  columns: ReadonlyArray<{ header: string; cell: (r: T) => ReactNode; rowHeader?: boolean }>;
}) {
  return (
    // A scrollable region must be focusable and named so keyboard users can scroll it (1.4.10, 2.1.1).
    <div className="ds-table-region" role="region" aria-label={props.caption} tabIndex={0}>
      <table className="ds-table">
        <caption>{props.caption}</caption>
        <thead>
          <tr>{props.columns.map((c) => <th key={c.header} scope="col">{c.header}</th>)}</tr>
        </thead>
        <tbody>
          {props.rows.map((r) => (
            <tr key={props.rowKey(r)}>
              {props.columns.map((c) => c.rowHeader
                ? <th key={c.header} scope="row">{c.cell(r)}</th>
                : <td key={c.header}>{c.cell(r)}</td>)}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
