// Sign-in view (M1-E04-S05, journey J2). One generic failure message for every credential problem; the server never
// says whether the username exists. The password stays in component state only until submit and is cleared after.
import { useState, type FormEvent } from "react";
import { Button, ErrorSummary, StatusMessage, TextField, ViewHeading } from "../design-system";
import { ERROR_PRESENTATION, type ErrorCategory } from "../api/errors";

export type SignInFailure = { category: ErrorCategory; correlationId: string | null } | "unreachable" | null;

export function SignIn(props: { reason: "none" | "expired"; failure: SignInFailure; pending: boolean; onSubmit: (username: string, password: string) => void }) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [errors, setErrors] = useState<ReadonlyArray<{ fieldId: string; message: string }>>([]);

  function submit(e: FormEvent) {
    e.preventDefault();
    const found = [];
    if (username.trim() === "") found.push({ fieldId: "signin-username", message: "Enter your username" });
    if (password === "") found.push({ fieldId: "signin-password", message: "Enter your password" });
    setErrors(found);
    if (found.length > 0) return;
    props.onSubmit(username.trim(), password);
    setPassword("");
  }

  const f = props.failure;
  return (
    <>
      <ViewHeading title="Sign in" />
      {props.reason === "expired" ? (
        <StatusMessage tone="warning">Your session has ended. Sign in again to continue.</StatusMessage>
      ) : null}
      <ErrorSummary errors={errors} />
      {f === "unreachable" ? (
        <StatusMessage tone="warning">The server could not be reached. Check that Svavyom is running, then try again.</StatusMessage>
      ) : null}
      {f && f !== "unreachable" ? (
        <div role="alert" className="ds-alert">
          <h2>{f.category === "unauthenticated" ? "Sign-in failed" : ERROR_PRESENTATION[f.category].title}</h2>
          <p>
            {f.category === "unauthenticated" ? "The username or password is incorrect." : ERROR_PRESENTATION[f.category].recovery}
          </p>
          {f.correlationId ? <p>Correlation id: <span className="ds-badge">{f.correlationId}</span></p> : null}
        </div>
      ) : null}
      <form onSubmit={submit} noValidate aria-label="Sign in">
        <TextField id="signin-username" label="Username" value={username} onChange={setUsername} autoComplete="username"
          error={errors.find((x) => x.fieldId === "signin-username")?.message} />
        <TextField id="signin-password" label="Password" value={password} onChange={setPassword} autoComplete="current-password" secret
          error={errors.find((x) => x.fieldId === "signin-password")?.message} />
        <div className="ds-button-row">
          <Button type="submit" variant="primary" pending={props.pending}>Sign in</Button>
        </div>
      </form>
    </>
  );
}
