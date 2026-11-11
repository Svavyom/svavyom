// The SSH public key field of the create, reinstall and restore forms (DR-040 D3): a list of the saved keys to choose from, and the same text box as before
// for pasting one. A chosen key is sent as its text, so the form shows the same fingerprint check as for a pasted key.
import { useEffect, useState } from "react";
import { Select, TextArea } from "../design-system";
import { listSshKeys } from "../api/sshkeys";
import type { SshKey } from "../api/schema";

const short = (f: string) => f.slice(0, 19);

export function SshKeyField(props: { id: string; label: string; description: string; value: string; onChange: (v: string) => void; error?: string }) {
  const [keys, setKeys] = useState<SshKey[]>([]);
  const [chosen, setChosen] = useState("");
  useEffect(() => {
    let alive = true;
    void listSshKeys().then((r) => { if (alive && r.kind === "ok") setKeys(r.data.items); }); // a failure only means no list: pasting still works
    return () => { alive = false; };
  }, []);
  const pick = (id: string) => {
    setChosen(id);
    const k = keys.find((x) => x.id === id);
    if (k) props.onChange(k.public_key);
  };
  return (
    <>
      {keys.length > 0 ? (
        <Select id={`${props.id}-saved`} label="Saved key" value={chosen} onChange={pick}
          description="Choose one of the keys saved under SSH keys, or paste a key below."
          options={[{ value: "", label: "Choose a saved key…" }, ...keys.map((k) => ({ value: k.id, label: `${k.name} (${short(k.fingerprint)}…)` }))]} />
      ) : null}
      <TextArea id={props.id} label={props.label} value={props.value} onChange={(v) => { setChosen(""); props.onChange(v); }} description={props.description} error={props.error} />
    </>
  );
}
