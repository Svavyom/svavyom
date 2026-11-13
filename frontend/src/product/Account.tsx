// Account (DR-041 D1): change your own password. The same screen is the only thing a user with a temporary password can reach (D3).
// Both passwords live in this component's state until the request is sent; nothing is stored in the browser and nothing is shown again.
import { useState } from "react";
import { Button, PageHead, StatusMessage, TextField } from "../design-system";
import { changePassword } from "../api/users";

const MIN = 12;

export function Account(props: { username: string; required: boolean; onChanged: () => void; onSessionEnded: () => void }) {
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [again, setAgain] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [done, setDone] = useState(false);
  const [busy, setBusy] = useState(false);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setDone(false);
    const p = current === "" ? "Type your current password"
      : next.length < MIN ? `The new password needs at least ${MIN} characters`
      : next === current ? "The new password must differ from the current one"
      : next !== again ? "The two new passwords are not the same" : null;
    if (p) { setError(p); return; }
    setError(null);
    setBusy(true);
    const r = await changePassword(current, next);
    setBusy(false);
    if (r.kind === "ok") {
      setCurrent(""); setNext(""); setAgain("");
      setDone(true);
      props.onChanged();
      return;
    }
    if (r.kind === "error" && r.category === "unauthenticated") { props.onSessionEnded(); return; }
    setError(r.kind === "unreachable" ? "Svavyom could not be reached; the password may or may not have changed. Try signing in again."
      : ({ forbidden: "The current password is not correct.", validation: "The new password was not accepted: use 12 to 128 characters, not your user name and not one repeated character.",
        rate_limited: "Too many attempts. Wait a minute and try again." } as Record<string, string>)[r.category] ?? "The password could not be changed. Try again.");
  }

  return (
    <>
      <PageHead title={props.required ? "Choose a new password" : "Account"}>
        <p>{props.required ? `You are signed in as ${props.username} with a temporary password. Choose your own before you continue.` : `You are signed in as ${props.username}. Changing your password signs you out everywhere else.`}</p>
      </PageHead>
      {done ? <StatusMessage>Password changed. Every other session of yours was signed out.</StatusMessage> : null}
      <section className="ds-card" aria-labelledby="pw-title">
        <h2 id="pw-title">Change password</h2>
        <form onSubmit={submit} noValidate>
          <TextField id="pw-current" label="Current password" value={current} onChange={setCurrent} secret autoComplete="current-password" />
          <TextField id="pw-new" label="New password" value={next} onChange={setNext} secret autoComplete="new-password" description={`At least ${MIN} characters.`} />
          <TextField id="pw-again" label="New password again" value={again} onChange={setAgain} secret autoComplete="new-password" error={error ?? undefined} />
          <div className="ds-button-row"><Button type="submit" variant="primary" pending={busy}>Change password</Button></div>
        </form>
      </section>
    </>
  );
}
