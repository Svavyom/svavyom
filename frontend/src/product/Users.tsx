// Users (DR-041 D2): who can sign in and in which role. Administrators only. A new user gets a temporary password that they must change at their next
// sign-in; the same goes for a reset. An administrator is offered nothing on their own row (a slip could lock the installation out: the host's
// `api user-*` commands stay the recovery path, and Account is where you change your own password). Passwords are never shown again.
import { useCallback, useEffect, useRef, useState } from "react";
import { Button, DataTable, Dialog, ErrorState, LoadingRegion, PageHead, Select, StaleNotice, StatusMessage, StatusPill, TextField, UnreachableBanner } from "../design-system";
import type { ReadResult } from "../api/client";
import { createUser, listUsers, resetUserPassword, setUserDisabled, setUserRole, type Role } from "../api/users";
import type { User, UserList } from "../api/schema";

const ROLES: { value: Role; label: string }[] = [{ value: "viewer", label: "Viewer (can look)" }, { value: "operator", label: "Operator (can also create and change VMs)" }, { value: "admin", label: "Admin (can also manage networks and users)" }];
const NAME_RE = /^[a-z][a-z0-9._-]{2,31}$/;
const when = (iso: string) => iso.replace("T", " ").replace("Z", " UTC");

type Dlg = { kind: "role"; user: User } | { kind: "reset"; user: User } | { kind: "disable"; user: User } | { kind: "enable"; user: User } | null;

export function Users(props: { refresh: number; onSessionEnded: () => void }) {
  const [loading, setLoading] = useState(true);
  const [list, setList] = useState<UserList | null>(null);
  const [lastAt, setLastAt] = useState<Date | null>(null);
  const [failure, setFailure] = useState<ReadResult<unknown> | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [name, setName] = useState("");
  const [role, setRole] = useState<Role>("viewer");
  const [pw, setPw] = useState("");
  const [formError, setFormError] = useState<string | null>(null);
  const [dlg, setDlg] = useState<Dlg>(null);
  const [dRole, setDRole] = useState<Role>("viewer");
  const [dPw, setDPw] = useState("");
  const [dError, setDError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const alive = useRef(true);

  const load = useCallback(async () => {
    setLoading(true);
    const r = await listUsers();
    if (!alive.current) return;
    setLoading(false);
    if (r.kind === "ok") { setList(r.data); setLastAt(new Date()); setFailure(null); }
    else if (r.kind === "error" && r.category === "unauthenticated") props.onSessionEnded();
    else setFailure(r);
  }, [props]);
  useEffect(() => {
    alive.current = true;
    void load();
    return () => { alive.current = false; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);
  const first = useRef(true);
  useEffect(() => {
    if (first.current) { first.current = false; return; }
    void load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [props.refresh]);

  const why = (r: { kind: string; category?: string }): string =>
    r.kind === "unreachable" ? "Svavyom could not be reached; check the list before trying again."
      : ({ validation: "Not accepted: a user name is 3 to 32 lower-case letters, digits, . _ or -, starting with a letter; a password is 12 to 128 characters, not the user name and not one repeated character.",
        conflict: "That would not work: the name is taken, or it would leave no enabled administrator.", forbidden: "You may not do that (an administrator cannot change themselves here).",
        not_found: "That user no longer exists." } as Record<string, string>)[r.category ?? ""] ?? "That could not be done. Try again.";

  async function add(e: React.FormEvent) {
    e.preventDefault();
    setNotice(null);
    if (!NAME_RE.test(name)) { setFormError("A user name is 3 to 32 lower-case letters, digits, . _ or -, starting with a letter"); return; }
    if (pw.length < 12) { setFormError("The temporary password needs at least 12 characters"); return; }
    setFormError(null);
    setBusy(true);
    const r = await createUser(name, role, pw);
    setBusy(false);
    if (r.kind === "ok") { setNotice(`Created ${r.data.username}. Give them the temporary password through a safe channel: they must change it when they first sign in.`); setName(""); setPw(""); void load(); return; }
    if (r.kind === "error" && r.category === "unauthenticated") { props.onSessionEnded(); return; }
    setFormError(why(r));
  }

  function open(d: Dlg) { setDlg(d); setDError(null); setDPw(""); if (d?.kind === "role") setDRole(d.user.role); }

  async function confirm() {
    if (!dlg) return;
    setDError(null);
    if (dlg.kind === "reset" && dPw.length < 12) { setDError("The temporary password needs at least 12 characters"); return; }
    setBusy(true);
    const u = dlg.user;
    const r = dlg.kind === "role" ? await setUserRole(u.username, dRole) : dlg.kind === "reset" ? await resetUserPassword(u.username, dPw) : await setUserDisabled(u.username, dlg.kind === "disable");
    setBusy(false);
    if (r.kind === "ok") {
      setNotice(dlg.kind === "role" ? `${u.username} is now ${dRole}; they were signed out.` : dlg.kind === "reset" ? `${u.username} has a new temporary password and was signed out. Give it to them through a safe channel.`
        : dlg.kind === "disable" ? `${u.username} is disabled and was signed out.` : `${u.username} can sign in again.`);
      setDlg(null); setDPw(""); void load(); return;
    }
    if (r.kind === "error" && r.category === "unauthenticated") { props.onSessionEnded(); return; }
    setDError(why(r));
  }

  return (
    <>
      <PageHead title="Users"><p>Who can sign in, and in which role. A new user, and a user whose password you reset, must choose their own password at the next sign-in.</p></PageHead>
      {failure?.kind === "unreachable" ? <UnreachableBanner lastKnown={lastAt} onRetry={() => load()} /> : null}
      {failure?.kind === "error" ? <ErrorState category={failure.category} correlationId={failure.correlationId} onRetry={() => load()} /> : null}
      {notice ? <StatusMessage>{notice}</StatusMessage> : null}
      <LoadingRegion label="Users" loading={loading && !list}>
        {list && failure && lastAt ? <StaleNotice lastUpdated={lastAt} now={new Date()} /> : null}
        {list ? (
          <DataTable caption="Users of this installation" rows={list.items} rowKey={(u: User) => u.username} columns={[
            { header: "User", cell: (u: User) => u.username, rowHeader: true },
            { header: "Role", cell: (u: User) => u.role },
            { header: "State", cell: (u: User) => (u.disabled ? <StatusPill tone="bad">Disabled</StatusPill> : u.must_change_password ? <StatusPill tone="warn">Must choose a password</StatusPill> : <StatusPill tone="ok">Active</StatusPill>) },
            { header: "Created", cell: (u: User) => when(u.created_at) },
            { header: "Actions", cell: (u: User) => (u.allowed_actions.length === 0 ? "You (use Account)" : (
              <span className="ds-button-row">
                {u.allowed_actions.includes("set_role") ? <Button size="sm" ariaLabel={`Change role of ${u.username}`} onClick={() => open({ kind: "role", user: u })}>Role</Button> : null}
                {u.allowed_actions.includes("reset_password") ? <Button size="sm" ariaLabel={`Reset password of ${u.username}`} onClick={() => open({ kind: "reset", user: u })}>Reset password</Button> : null}
                {u.allowed_actions.includes("disable") ? <Button size="sm" ariaLabel={`Disable ${u.username}`} onClick={() => open({ kind: "disable", user: u })}>Disable</Button> : null}
                {u.allowed_actions.includes("enable") ? <Button size="sm" ariaLabel={`Enable ${u.username}`} onClick={() => open({ kind: "enable", user: u })}>Enable</Button> : null}
              </span>)) },
          ]} />
        ) : null}
        {list && list.allowed_actions.includes("create") ? (
          <section className="ds-card" aria-labelledby="user-add-title">
            <h2 id="user-add-title">Add a user</h2>
            <form onSubmit={add} noValidate>
              <TextField id="user-name" label="User name" value={name} onChange={setName} autoComplete="off" />
              <Select id="user-role" label="Role" value={role} onChange={(v) => setRole(v as Role)} options={ROLES} />
              <TextField id="user-pw" label="Temporary password" value={pw} onChange={setPw} secret autoComplete="new-password" description="At least 12 characters. The user must change it when they first sign in." error={formError ?? undefined} />
              <div className="ds-button-row"><Button type="submit" variant="primary" pending={busy}>Add user</Button></div>
            </form>
          </section>
        ) : null}
      </LoadingRegion>
      <Dialog title={dlg?.kind === "role" ? "Change role" : dlg?.kind === "reset" ? "Reset password" : dlg?.kind === "disable" ? "Disable user" : "Enable user"} open={dlg !== null} onClose={() => setDlg(null)}>
        {dlg?.kind === "role" ? (
          <>
            <p>Change the role of {dlg.user.username}. They are signed out and the new role applies when they sign in again.</p>
            <Select id="dlg-role" label="New role" value={dRole} onChange={(v) => setDRole(v as Role)} options={ROLES} />
          </>
        ) : null}
        {dlg?.kind === "reset" ? (
          <>
            <p>Set a temporary password for {dlg.user.username}. They are signed out and must choose their own password at the next sign-in.</p>
            <TextField id="dlg-pw" label="Temporary password" value={dPw} onChange={setDPw} secret autoComplete="new-password" description="At least 12 characters." />
          </>
        ) : null}
        {dlg?.kind === "disable" ? <p>{dlg.user.username} will be signed out and cannot sign in until you enable them again. Their VMs and keys are not touched.</p> : null}
        {dlg?.kind === "enable" ? <p>{dlg.user.username} will be able to sign in again with their current password.</p> : null}
        {dError ? <StatusMessage tone="warning">{dError}</StatusMessage> : null}
        <div className="ds-button-row">
          <Button onClick={() => setDlg(null)}>Cancel</Button>
          <Button variant="primary" pending={busy} onClick={() => void confirm()}>{dlg?.kind === "role" ? "Change role" : dlg?.kind === "reset" ? "Reset password" : dlg?.kind === "disable" ? "Disable" : "Enable"}</Button>
        </div>
      </Dialog>
    </>
  );
}
