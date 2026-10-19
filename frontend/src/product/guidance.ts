// Operator guidance for the closed creation-readiness codes (DR-017). The server sends codes only; the words live here so that no
// host path, libvirt message or configuration detail can ever reach the page.
import type { Host } from "../api/schema";

export type Reason = Host["observed"]["creation"]["reasons"][number];

const BLOCKING: Record<Reason, string> = {
  mutation_disabled: "VM creation is not enabled on this installation. The server operator turns it on with the Development Preview setting (--experimental-mutation).",
  no_usable_image: "No image can be chosen yet. The host administrator (root) imports one with `api register-image` and declares its cloud-init support with --cloud-init; an image that is only imported cannot be used.",
  storage_unavailable: "The storage pool for VM disks is not available. Check that the Svavyom libvirt storage pool exists and is active.",
  network_unavailable: "The NAT network for VMs is not available. Check that the Svavyom libvirt network exists and is active.",
  virtualization_unavailable: "This host does not offer hardware virtualization (KVM). See the readiness details on the dashboard.",
  host_not_qualified: "",
  image_unqualified: "",
};

const NOTICE: Partial<Record<Reason, string>> = {
  host_not_qualified: "This host has not been qualified for Svavyom; creating a VM here is not guaranteed to work.",
  image_unqualified: "No image has been qualified on real hardware yet, so a new VM may not boot or accept your SSH key.",
};

/** Honest wording for an image's internal state. "verified" is NOT a boot result: it means the operator declared compatibility. */
export function imageStateLabel(q: string): string {
  switch (q) {
    case "qualified": return "real-host qualified";
    case "verified": return "compatibility declared, not yet qualified";
    case "registered": return "imported";
    default: return "disabled";
  }
}

export function imageAccessText(q: string): string {
  return q === "qualified"
    ? "This image was booted and reached over SSH in a real-host qualification run."
    : "The operator declared this image compatible (cloud-init, login user); Svavyom has not booted it on real hardware. The VM may not boot, or may not accept this key. Svavyom shows an address when the host reports one; it does not test SSH.";
}

/** Blocking reasons explain why the form is unavailable; notices are shown beside a working form. */
export function guidance(reasons: ReadonlyArray<Reason>): { blocking: string[]; notices: string[] } {
  return {
    blocking: reasons.filter((r) => BLOCKING[r] !== "").map((r) => BLOCKING[r]),
    notices: reasons.flatMap((r) => (NOTICE[r] ? [NOTICE[r] as string] : [])),
  };
}
