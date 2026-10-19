// Size profiles (M3-S08): a small, fixed set of resource presets that fill the vCPU, memory and root-disk choices of the create form. A profile is a
// convenience over the host's own choice lists, never a new capability: it is offered only when every one of its values is among the choices the host
// offers (and the disk is at least the image's minimum), it carries no secret, and it never selects an image. "Custom" leaves the three choices free.
import type { Host } from "../api/schema";

export interface Profile { id: "small" | "medium" | "large"; label: string; vcpus: number; memoryMiB: number; diskGiB: number }

export const PROFILES: ReadonlyArray<Profile> = [
  { id: "small", label: "Small", vcpus: 1, memoryMiB: 1024, diskGiB: 10 },
  { id: "medium", label: "Medium", vcpus: 2, memoryMiB: 2048, diskGiB: 20 },
  { id: "large", label: "Large", vcpus: 4, memoryMiB: 4096, diskGiB: 40 },
];

/** The profiles this host can honour for an image with the given minimum disk size. */
export function availableProfiles(c: Host["observed"]["creation"], minDiskGiB: number): Profile[] {
  return PROFILES.filter((p) => c.vcpu_options.includes(p.vcpus) && c.memory_mib_options.includes(p.memoryMiB) && c.disk_gib_options.includes(p.diskGiB) && p.diskGiB >= minDiskGiB);
}

export function profileLabel(p: Profile): string {
  return `${p.label}: ${p.vcpus} vCPU, ${p.memoryMiB} MiB memory, ${p.diskGiB} GiB disk`;
}
