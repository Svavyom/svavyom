// SSH keys (DR-040): the public keys saved for this installation, which the create, reinstall and restore forms offer, and a way to make a key pair here.
// The private key of a pair made on this page exists only in this page's memory until it is downloaded; it is never sent to the server, never written to the
// browser's storage and is dropped when the dialog closes or the page is left. Only the public line is saved, and only when the person presses Save.
import { useCallback, useEffect, useRef, useState } from "react";
import { Button, DataTable, Dialog, EmptyState, ErrorState, LoadingRegion, PageHead, StaleNotice, StatusMessage, TextArea, TextField, UnreachableBanner } from "../design-system";
import type { ReadResult } from "../api/client";
import { addSshKey, deleteSshKey, listSshKeys } from "../api/sshkeys";
import type { SshKey, SshKeyList } from "../api/schema";
import { canGenerate, generateKeyPair, type KeyPair } from "./keygen";

const NAME_RE = /^[A-Za-z0-9][A-Za-z0-9 ._()+-]{0,62}$/;
const when = (iso: string) => iso.replace("T", " ").replace("Z", " UTC");

function keyProblem(k: string): string | null {
  const t = k.trim();
  if (t === "") return "Paste one public key";
  if (/PRIVATE KEY/.test(t) || /[\r\n]/.test(t) || !/^(ssh-|ecdsa-)/.test(t)) return "This must be one public key on one line, starting with ssh-ed25519, ssh-rsa or ecdsa-. Never paste a private key";
  return null;
}

const safeFile = (name: string) => (name.replace(/[^A-Za-z0-9._-]+/g, "_").replace(/^[._-]+/, "") || "svavyom_key");

export function SshKeys(props: { refresh: number; onSessionEnded: () => void }) {
  const [loading, setLoading] = useState(true);
  const [list, setList] = useState<SshKeyList | null>(null);
  const [lastAt, setLastAt] = useState<Date | null>(null);
  const [failure, setFailure] = useState<ReadResult<unknown> | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [name, setName] = useState("");
  const [key, setKey] = useState("");
  const [formError, setFormError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [confirm, setConfirm] = useState<SshKey | null>(null);
  const [made, setMade] = useState<KeyPair | null>(null); // the private key lives here, in memory, until the dialog closes
  const [genName, setGenName] = useState("");
  const [genError, setGenError] = useState<string | null>(null);
  const [downloaded, setDownloaded] = useState(false);
  const alive = useRef(true);

  const load = useCallback(async () => {
    setLoading(true);
    const r = await listSshKeys();
    if (!alive.current) return;
    setLoading(false);
    if (r.kind === "ok") { setList(r.data); setLastAt(new Date()); setFailure(null); }
    else if (r.kind === "error" && r.category === "unauthenticated") props.onSessionEnded();
    else setFailure(r);
  }, [props]);

  useEffect(() => {
    alive.current = true;
    void load();
    return () => { alive.current = false; setMade(null); }; // leaving the page drops a private key that was not downloaded
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);
  const first = useRef(true);
  useEffect(() => {
    if (first.current) { first.current = false; return; }
    void load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [props.refresh]);

  const mayAdd = list?.allowed_actions.includes("add") === true;

  async function save(n: string, k: string): Promise<boolean> {
    setBusy(true);
    const r = await addSshKey(n.trim(), k.trim());
    setBusy(false);
    if (r.kind === "ok") { setNotice(`Saved ${r.data.name} (${r.data.fingerprint}).`); void load(); return true; }
    if (r.kind === "error" && r.category === "unauthenticated") { props.onSessionEnded(); return false; }
    const why = r.kind === "error"
      ? ({ validation: "The name or the key was not accepted. The name uses letters, digits, spaces and . _ ( ) + -; the key must be one public key of type ed25519, ecdsa or rsa (3072 bits or more).",
        conflict: "That name or that key is already saved, or the library is full (64 keys).", forbidden: "Your role may not save keys." } as Record<string, string>)[r.category] ?? "The key could not be saved. Try again."
      : "Svavyom could not be reached; check whether the key was saved before trying again.";
    setFormError(why);
    return false;
  }

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setNotice(null);
    const p = !NAME_RE.test(name.trim()) ? "Give the key a name: letters, digits, spaces and . _ ( ) + -, up to 63 characters" : keyProblem(key);
    if (p) { setFormError(p); return; }
    setFormError(null);
    if (await save(name, key)) { setName(""); setKey(""); }
  }

  async function remove(k: SshKey) {
    setBusy(true);
    const r = await deleteSshKey(k.id);
    setBusy(false);
    setConfirm(null);
    if (r.kind === "ok") { setNotice(`Deleted ${k.name}. VMs already created with it keep it; it is no longer offered for new ones.`); void load(); }
    else if (r.kind === "error" && r.category === "unauthenticated") props.onSessionEnded();
    else setNotice("The key could not be deleted. Reload the list and try again.");
  }

  async function make() {
    setGenError(null);
    if (!NAME_RE.test(genName.trim())) { setGenError("Give the key a name first: letters, digits, spaces and . _ ( ) + -, up to 63 characters"); return; }
    try {
      setDownloaded(false);
      setMade(await generateKeyPair(`${genName.trim().replace(/\s+/g, "-")}@svavyom`));
    } catch {
      setGenError("This browser could not make a key. Create one on your computer with ssh-keygen -t ed25519 and paste its public key above.");
    }
  }

  function download(k: KeyPair) {
    const url = URL.createObjectURL(new Blob([k.privateFile], { type: "application/octet-stream" }));
    const a = document.createElement("a");
    a.href = url;
    a.download = safeFile(genName);
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 0);
    setDownloaded(true);
  }

  function closeMade() { setMade(null); setDownloaded(false); setGenName(""); }

  async function saveMade() {
    if (made && (await save(genName, made.publicLine))) closeMade();
  }

  const secure = canGenerate();
  return (
    <>
      <PageHead title="SSH keys"><p>Public keys saved here are offered when you create, reinstall or restore a VM, so you do not paste the key each time. Only public keys are stored.</p></PageHead>
      {failure?.kind === "unreachable" ? <UnreachableBanner lastKnown={lastAt} onRetry={() => load()} /> : null}
      {failure?.kind === "error" ? <ErrorState category={failure.category} correlationId={failure.correlationId} onRetry={() => load()} /> : null}
      {notice ? <StatusMessage>{notice}</StatusMessage> : null}
      <LoadingRegion label="SSH keys" loading={loading && !list}>
        {list && failure && lastAt ? <StaleNotice lastUpdated={lastAt} now={new Date()} /> : null}
        {list && list.items.length === 0 ? <EmptyState title="No saved keys" reason={mayAdd ? "Add a public key below, or make a key pair here." : "No keys are saved yet. An operator or administrator saves them."} /> : null}
        {list && list.items.length > 0 ? (
          <DataTable caption="Saved SSH public keys" rows={list.items} rowKey={(k: SshKey) => k.id} columns={[
            { header: "Name", cell: (k: SshKey) => k.name, rowHeader: true },
            { header: "Type", cell: (k: SshKey) => k.type },
            { header: "Fingerprint", cell: (k: SshKey) => <code>{k.fingerprint}</code> },
            { header: "Added by", cell: (k: SshKey) => k.added_by },
            { header: "Added", cell: (k: SshKey) => when(k.added_at) },
            { header: "Actions", cell: (k: SshKey) => (k.allowed_actions.includes("delete") ? <Button size="sm" ariaLabel={`Delete ${k.name}`} onClick={() => setConfirm(k)}>Delete</Button> : "-") },
          ]} />
        ) : null}
        {list && mayAdd ? (
          <>
            <section className="ds-card" aria-labelledby="key-add-title">
              <h2 id="key-add-title">Add a public key</h2>
              <form onSubmit={submit} noValidate>
                <TextField id="key-name" label="Name" value={name} onChange={setName} />
                <TextArea id="key-text" label="Public key" value={key} onChange={setKey} description="One public key, for example the contents of id_ed25519.pub. Never paste a private key." error={formError ?? undefined} />
                <div className="ds-button-row"><Button type="submit" variant="primary" pending={busy}>Save key</Button></div>
              </form>
            </section>
            <section className="ds-card" aria-labelledby="key-make-title">
              <h2 id="key-make-title">Make a key pair here</h2>
              {secure ? (
                <>
                  <p>The key pair is made in this browser. You download the <strong>private key</strong> once; it is never sent to Svavyom and not stored anywhere, so keep the file safe. Only the public key is saved here, when you press Save.</p>
                  <TextField id="gen-name" label="Name for the new key" value={genName} onChange={setGenName} error={genError ?? undefined} />
                  <div className="ds-button-row"><Button onClick={() => void make()}>Make a key pair</Button></div>
                </>
              ) : (
                <StatusMessage tone="warning">This page cannot make a key: it needs HTTPS (a self-signed certificate that your browser was told to accept is enough) and a current browser. Create one on your computer with <code>ssh-keygen -t ed25519</code> and paste its public key above.</StatusMessage>
              )}
            </section>
          </>
        ) : null}
      </LoadingRegion>
      <Dialog title="Delete this key?" open={confirm !== null} onClose={() => setConfirm(null)}>
        <p>{confirm?.name} will no longer be offered when you create, reinstall or restore a VM. VMs that already have it keep it.</p>
        <div className="ds-button-row">
          <Button onClick={() => setConfirm(null)}>Cancel</Button>
          <Button variant="primary" pending={busy} onClick={() => confirm && void remove(confirm)}>Delete key</Button>
        </div>
      </Dialog>
      <Dialog title="Your new key pair" open={made !== null} onClose={closeMade}>
        {made ? (
          <>
            <StatusMessage tone="warning">Download the private key now. It exists only on this page and is gone when you close this window or leave the page. It is not protected by a passphrase: keep it private, run <code>chmod 600 FILE</code>, and add one with <code>ssh-keygen -p -f FILE</code> if you like.</StatusMessage>
            <p>Fingerprint: <code>{made.fingerprint}</code></p>
            <TextArea id="made-public" label="Public key" value={made.publicLine} onChange={() => undefined} description="This is what Svavyom saves. It is safe to share." />
            <div className="ds-button-row">
              <Button variant="primary" onClick={() => download(made)}>Download private key</Button>
              <Button disabled={!downloaded} pending={busy} onClick={() => void saveMade()}>Save public key</Button>
              <Button onClick={closeMade}>Close</Button>
            </div>
            {!downloaded ? <p>Save the public key after you have downloaded the private key.</p> : null}
            {formError ? <StatusMessage tone="warning">{formError}</StatusMessage> : null}
          </>
        ) : null}
      </Dialog>
    </>
  );
}
