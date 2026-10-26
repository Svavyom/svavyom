// Create VM (journey J4, M1-E02-S02 / M1-E04-S02): exactly six inputs, a review step, then typed progress. Nothing here sends a
// path, XML, URL or script: the server chooses the network and derives every host path itself. Create makes a STOPPED VM; Start
// is a separate action in the VM list.
import { useEffect, useRef, useState } from "react";
import { Button, ErrorSummary, LoadingRegion, PageHead, RadioGroup, Select, StatusMessage, TextArea, TextField, Link } from "../design-system";
import { newIdempotencyKey, read } from "../api/client";
import { decodeHost, decodeImageList, decodeNetworkList } from "../api/decoders";
import { submitOperation } from "../api/session";
import type { Host, Image, Operation, VirtualNetwork } from "../api/schema";
import { OperationProgress, OperationStatus } from "./OperationProgress";
import { guidance, imageAccessText, imageStateLabel } from "./guidance";
import { availableProfiles } from "./profiles";
import { atLeast, useRole } from "./role";

const NAME_RE = /^[a-z]([a-z0-9-]{0,61}[a-z0-9])?$/;

export async function keyFingerprint(key: string): Promise<string | null> {
  try {
    const blob = key.trim().split(/\s+/)[1];
    if (!blob || !crypto?.subtle) return null;
    const bytes = Uint8Array.from(atob(blob), (c) => c.charCodeAt(0));
    const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
    return "SHA256:" + btoa(String.fromCharCode(...digest)).replace(/=+$/, "");
  } catch {
    return null;
  }
}

type Draft = { name: string; image: string; vcpus: string; memory: string; disk: string; key: string; network: string; profile: string; guest: string };
type Phase = { kind: "form" } | { kind: "review" } | { kind: "submitting" } | { kind: "progress"; id: string } | { kind: "done"; op: Operation };

export function CreateVm(props: { onSessionEnded: () => void }) {
  const [loading, setLoading] = useState(true);
  const [host, setHost] = useState<Host | null>(null);
  const [images, setImages] = useState<Image[]>([]);
  const [failed, setFailed] = useState(false);
  const [networks, setNetworks] = useState<VirtualNetwork[]>([]);
  const [draft, setDraft] = useState<Draft>({ name: "", image: "", vcpus: "", memory: "", disk: "", key: "", network: "", profile: "custom", guest: "linux" });
  const [errors, setErrors] = useState<ReadonlyArray<{ fieldId: string; message: string }>>([]);
  const [phase, setPhase] = useState<Phase>({ kind: "form" });
  const [step, setStep] = useState<1 | 2>(1);
  const [submitError, setSubmitError] = useState<string | null>(null);
  const [fp, setFp] = useState<string | null>(null);
  const keyRef = useRef<{ sig: string; key: string } | null>(null);

  useEffect(() => {
    let alive = true;
    void (async () => {
      const [h, i, n] = await Promise.all([read("/api/v1/hosts/local", decodeHost), read("/api/v1/images", decodeImageList), read("/api/v1/virtual-networks", decodeNetworkList)]);
      if (!alive) return;
      setLoading(false);
      if ((h.kind === "error" && h.category === "unauthenticated") || (i.kind === "error" && i.category === "unauthenticated")) { props.onSessionEnded(); return; }
      if (h.kind !== "ok" || i.kind !== "ok") { setFailed(true); return; }
      setHost(h.data);
      setImages(i.data.items);
      if (n.kind === "ok") setNetworks(n.data.items.filter((x) => x.observed.managed && x.observed.state === "active")); // the default network is always offered; a failed read just hides the others
      const c = h.data.observed.creation;
      setDraft((d) => ({ ...d, image: i.data.items.find((x) => x.observed.qualification !== "registered")?.id ?? "", vcpus: String(c.vcpu_options[0] ?? ""), memory: String(c.memory_mib_options[0] ?? ""), disk: "" }));
    })();
    return () => { alive = false; };
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const creation = host?.observed.creation;
  const choosable = images.filter((x) => x.observed.qualification !== "registered");
  const image = choosable.find((x) => x.id === draft.image);
  const isIso = image?.observed.media === "iso"; // installation media: no SSH key, no cloud-init (DR-023 D3)
  const diskOptions = (creation?.disk_gib_options ?? []).filter((g) => g >= (image?.observed.min_disk_gib ?? 1));
  useEffect(() => {
    if (diskOptions.length > 0 && !diskOptions.includes(Number(draft.disk))) setDraft((d) => ({ ...d, disk: String(diskOptions[0]), profile: "custom" }));
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [draft.image, creation]);

  const set = (k: keyof Draft) => (v: string) => setDraft((d) => ({ ...d, [k]: v }));
  // Choosing one of the three sizes by hand is "Custom"; choosing a profile fills them from the host's own choices.
  const setSize = (k: "vcpus" | "memory" | "disk") => (v: string) => setDraft((d) => ({ ...d, [k]: v, profile: "custom" }));
  const profiles = creation ? availableProfiles(creation, image?.observed.min_disk_gib ?? 1) : [];
  const chooseProfile = (id: string) => setDraft((d) => {
    const pr = profiles.find((x) => x.id === id);
    return pr ? { ...d, profile: id, vcpus: String(pr.vcpus), memory: String(pr.memoryMiB), disk: String(pr.diskGiB) } : { ...d, profile: "custom" };
  });

  function nameProblem(): Array<{ fieldId: string; message: string }> {
    return NAME_RE.test(draft.name) ? [] : [{ fieldId: "create-name", message: "Use 1-63 lower-case letters, digits or hyphens, starting with a letter and not ending with a hyphen" }];
  }

  function next() {
    const found = nameProblem();
    setErrors(found);
    if (found.length === 0) setStep(2);
  }

  function review() {
    const found = nameProblem();
    const k = draft.key.trim();
    if (isIso) {
      // installation media is reached through the installer, not an injected key
    } else if (k === "") found.push({ fieldId: "create-key", message: "Paste one SSH public key" });
    else if (/PRIVATE KEY/.test(k) || /[\r\n]/.test(k) || !/^(ssh-|ecdsa-)/.test(k)) {
      if (/PRIVATE KEY/.test(k)) setDraft((d) => ({ ...d, key: "" })); // never keep a private key in the page
      found.push({ fieldId: "create-key", message: "This must be one public key on one line, starting with ssh-ed25519, ssh-rsa or ecdsa-. Never paste a private key" });
    }
    setErrors(found);
    if (found.length > 0) { if (found.some((f) => f.fieldId === "create-name")) setStep(1); return; }
    setFp(null);
    if (!isIso) void keyFingerprint(k).then(setFp);
    setPhase({ kind: "review" });
  }

  async function submit() {
    const body: Record<string, unknown> = { vcpus: Number(draft.vcpus), memory_mib: Number(draft.memory), image_id: draft.image, disk_gib: Number(draft.disk) };
    if (!isIso) body.ssh_public_key = draft.key.trim();
    if (draft.network !== "") body.network = draft.network; // omitted = the configured default network
    if (isIso && draft.guest === "windows") body.guest_profile = "windows"; // omitted = linux: a Linux request is exactly what it always was
    const sig = JSON.stringify([draft.name, body]);
    // One idempotency key per intent: the same key is reused when the same details are submitted again after an unknown outcome.
    if (!keyRef.current || keyRef.current.sig !== sig) keyRef.current = { sig, key: newIdempotencyKey() };
    setSubmitError(null);
    setPhase({ kind: "submitting" });
    const r = await submitOperation({ type: "create", kind: "VM", id: draft.name, idempotency_key: keyRef.current.key, create: body });
    if (r.kind === "ok") { setPhase({ kind: "progress", id: r.data.id }); return; }
    setPhase({ kind: "review" });
    if (r.kind === "unreachable") { setSubmitError("Svavyom could not confirm that the request arrived. Check the VM list before trying again; submitting again is safe, it will not create a second VM."); return; }
    switch (r.category) {
      case "unauthenticated": props.onSessionEnded(); return;
      case "conflict": setSubmitError(`A VM named "${draft.name}" already exists, or this request was already used with different details.`); return;
      case "unavailable": setSubmitError("The host is not ready to create VMs right now (network or storage unavailable). Nothing was changed."); return;
      case "prohibited": setSubmitError("VM creation is not enabled on this installation."); return;
      case "validation": setSubmitError("Some details were not accepted. Go back and check the name, image, sizes and key."); return;
      case "forbidden": setSubmitError("The request was refused. Reload the page and sign in again if this persists."); return;
      default: setSubmitError("Something went wrong. Try again later.");
    }
  }

  const role = useRole();
  const mayCreate = atLeast(role, "operator");
  const ready = creation?.ready === true && mayCreate;
  return (
    <>
      <PageHead title="Create VM"><p>Three steps. Nothing is created until you confirm.</p></PageHead>
      <ol className="ds-steps" aria-label="Steps">
        {["Basics", "Access", "Review"].map((label, i) => {
          const at = phase.kind === "form" ? step : 3;
          return <li key={label} className={`ds-step${at === i + 1 ? " ds-step--on" : at > i + 1 ? " ds-step--done" : ""}`} aria-current={at === i + 1 ? "step" : undefined}><span className="ds-step-n" aria-hidden="true">{at > i + 1 ? "✓" : i + 1}</span>{label}</li>;
        })}
      </ol>
      <StatusMessage tone="warning">Development Preview: VM creation is experimental and has not been qualified on real hardware.</StatusMessage>
      <LoadingRegion label="Create form" loading={loading}>
        {!mayCreate ? <StatusMessage tone="warning">Your role ({role ?? "unknown"}) can look but not create virtual machines. Ask an administrator for the operator role.</StatusMessage> : null}
        {failed ? <StatusMessage tone="warning">The details needed to create a VM could not be loaded. Go back and try again.</StatusMessage> : null}
        {mayCreate && host && creation && !creation.ready ? (
          <StatusMessage tone="warning">
            Creating a VM is not available right now.
            {guidance(creation.reasons).blocking.map((t) => <span key={t} className="ds-block"> {t}</span>)}
          </StatusMessage>
        ) : null}
        {ready ? guidance(creation.reasons).notices.map((t) => <StatusMessage key={t} tone="warning">{t}</StatusMessage>) : null}
        {ready && choosable.length > 0 && phase.kind === "form" ? (
          <form onSubmit={(e) => { e.preventDefault(); if (step === 1) next(); else review(); }} noValidate aria-label="Create VM" className="ds-card">
            <ErrorSummary errors={errors} />
            {step === 1 ? (
              <>
                <TextField id="create-name" label="Name" value={draft.name} onChange={set("name")} required
                  description="Also the VM's host name." error={errors.find((x) => x.fieldId === "create-name")?.message} />
                <Select label="Image" value={draft.image} onChange={set("image")} options={choosable.map((i) => ({ value: i.id, label: i.observed.media === "iso" ? `${i.name} (installation media)` : `${i.name} (login user ${i.observed.login_user ?? "unknown"}, ${imageStateLabel(i.observed.qualification)})` }))} />
                <div className="ds-field">
                  <span className="ds-label" id="size-label">Size profile</span>
                  <div className="ds-presets" role="group" aria-labelledby="size-label">
                    {profiles.map((p) => (
                      <button key={p.id} type="button" className="ds-preset" aria-pressed={draft.profile === p.id} onClick={() => chooseProfile(p.id)}>
                        <strong>{p.label}</strong> <span>{`${p.vcpus} vCPU, ${p.memoryMiB} MiB memory, ${p.diskGiB} GiB disk`}</span>
                      </button>
                    ))}
                    <button type="button" className="ds-preset ds-preset--custom" aria-pressed={draft.profile === "custom"} onClick={() => chooseProfile("custom")}>Custom</button>
                  </div>
                  <span className="ds-description">A profile only fills the three sizes below from what this host offers; you can still change them.</span>
                </div>
                <Select label="vCPUs" value={draft.vcpus} onChange={setSize("vcpus")} options={creation.vcpu_options.map((v) => ({ value: String(v), label: String(v) }))} />
                <Select label="Memory" value={draft.memory} onChange={setSize("memory")} options={creation.memory_mib_options.map((m) => ({ value: String(m), label: `${m} MiB` }))} />
                <Select label="Root disk" value={draft.disk} onChange={setSize("disk")} options={diskOptions.map((g) => ({ value: String(g), label: `${g} GiB` }))} />
              </>
            ) : (
              <>
                <Select label="Network" value={draft.network} onChange={set("network")} description="The default network, or a network Svavyom created that is running."
                  options={[{ value: "", label: "Default network" }, ...networks.map((n) => ({ value: n.id, label: `${n.name} (${n.observed.subnet ?? "no address range"})` }))]} />
                {isIso ? (
                  <RadioGroup legend="Guest type" name="guest" value={draft.guest} onChange={set("guest")}
                    options={[{ value: "linux", label: "Linux or other (default)" }, { value: "windows", label: "Windows" }]} />
                ) : null}
                {isIso && draft.guest === "windows" ? (
                  <>
                    <StatusMessage tone="warning">Windows Server and older Windows clients on BIOS firmware. The disk and network card use drivers that Windows Setup already has. Windows 11 needs UEFI and a TPM and is not supported yet.</StatusMessage>
                    <p className="ds-muted">After the install you can attach the virtio-win driver disc as a second installation medium from the VM page; the VM stays on the SATA disk and the e1000e network card until you change that yourself.</p>
                  </>
                ) : null}
                {isIso ? (
                  <StatusMessage tone="warning">This VM boots the installer from the ISO. There is no SSH key and no automatic setup: you install the system yourself. Start the VM, then follow the installer in the <strong>Graphical console</strong> on the VM&apos;s page (the serial console is also there, but many installers, Windows among them, only draw on the graphical one). Eject the media afterwards so the VM boots from its disk.</StatusMessage>
                ) : (
                  <TextArea id="create-key" label="SSH public key" value={draft.key} onChange={set("key")}
                    description="One public key (for example the contents of id_ed25519.pub). It is the only way to sign in to the VM; passwords are disabled. Never paste a private key."
                    error={errors.find((x) => x.fieldId === "create-key")?.message} />
                )}
              </>
            )}
            <div className="ds-button-row">
              {step === 2 ? <Button onClick={() => { setErrors([]); setStep(1); }}>Back</Button> : <Link href="#/vms">Cancel</Link>}
              <Button type="submit" variant="primary">{step === 1 ? "Continue" : "Review"}</Button>
            </div>
          </form>
        ) : null}
        {ready && (phase.kind === "review" || phase.kind === "submitting") ? (
          <section aria-labelledby="review-heading" className="ds-card">
            <h2 id="review-heading">Review</h2>
            {submitError ? <StatusMessage tone="warning">{submitError}</StatusMessage> : null}
            <dl>
              <dt>Name</dt><dd>{draft.name}</dd>
              <dt>Image</dt><dd>{image?.name} {image ? (isIso ? "(installation media)" : `(login user ${image.observed.login_user ?? "unknown"})`) : ""}</dd>
              <dt>Size</dt><dd>{draft.vcpus} vCPU, {draft.memory} MiB memory, {draft.disk} GiB root disk</dd>
              <dt>Guest type</dt><dd>{isIso && draft.guest === "windows" ? "Windows" : isIso ? "Linux or other" : "Linux (cloud image)"}</dd>
              <dt>Network</dt><dd>{draft.network === "" ? "Default network" : draft.network}</dd>
              <dt>SSH key</dt><dd>{isIso ? "None: the installer sets up access" : fp ?? "fingerprint unavailable"}</dd>
              <dt>Result</dt><dd>A stopped VM. Starting it is a separate step.</dd>
              <dt>Access</dt><dd>{isIso ? "The VM starts the installer from the ISO. Follow it in the graphical console; the serial console helps only if the installer offers one." : imageAccessText(image?.observed.qualification ?? "verified")}</dd>
            </dl>
            <div className="ds-button-row">
              <Button variant="primary" onClick={() => { void submit(); }} pending={phase.kind === "submitting"}>Create VM</Button>
              <Button onClick={() => { setStep(2); setPhase({ kind: "form" }); }}>Back</Button>
            </div>
          </section>
        ) : null}
        {phase.kind === "progress" ? (
          <>
            <OperationProgress id={phase.id} onDone={(op) => setPhase({ kind: "done", op })} onSessionEnded={props.onSessionEnded} />
          </>
        ) : null}
        {phase.kind === "done" ? (
          <>
            <OperationStatus op={phase.op} />
            {phase.op.status === "succeeded" && fp ? (
              <p>The SSH key sent to this VM is <code>{fp}</code>. Check it against your key with <code>ssh-keygen -lf your-key.pub</code>: if they differ, the VM was created with a different key than the one you meant.</p>
            ) : null}
            {phase.op.status === "succeeded" ? (
              <p>The VM <strong>{phase.op.resource_id}</strong> is created but <strong>stopped</strong>: creating a VM does not start it. Open its page and choose Start{isIso ? ", then open the Graphical console to follow the installer" : ""}.</p>
            ) : null}
            {phase.op.status === "succeeded" && isIso && draft.guest === "windows" ? (
              <p>Start the VM, then follow Windows Setup in the Graphical console. The installation disc is the only drive Windows Setup needs. If it ignores a shutdown request during setup, use Force off.</p>
            ) : null}
            <div className="ds-button-row">
              {phase.op.status === "succeeded" ? <Link href={`#/vms/${phase.op.resource_id}`}>{`Open ${phase.op.resource_id}`}</Link> : null}
              <Link href="#/vms">Go to the VM list</Link>
            </div>
          </>
        ) : null}
      </LoadingRegion>
    </>
  );
}
