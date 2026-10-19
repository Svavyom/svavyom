// Strict decoders for the resource shapes in contracts/openapi.yaml (M0-E01-S04, DR-012 D4). The types are
// generated (./schema.ts); the checks are the schema itself (./validate.ts), so a response with an unknown key,
// a wrong type or an out-of-range value decodes to null, which the client turns into the `internal` state.
import type { Decoder } from "./client";
import type { BackupList, EventList, Host, ImageList, Operation, OperationList, VM, VMList, VirtualNetworkList, VolumeList } from "./schema";
import type { SchemaName } from "./schema";
import { validate } from "./validate";

export function decoderFor<T>(name: SchemaName): Decoder<T> {
  return (value) => (validate(name, value).ok ? (value as T) : null);
}

export const decodeHost = decoderFor<Host>("Host");
export const decodeVm = decoderFor<VM>("VM");
export const decodeVmList = decoderFor<VMList>("VMList");
export const decodeOperation = decoderFor<Operation>("Operation");
export const decodeImageList = decoderFor<ImageList>("ImageList");
export const decodeBackupList = decoderFor<BackupList>("BackupList");
export const decodeOperationList = decoderFor<OperationList>("OperationList");
export const decodeVolumeList = decoderFor<VolumeList>("VolumeList");
export const decodeNetworkList = decoderFor<VirtualNetworkList>("VirtualNetworkList");
export const decodeEventList = decoderFor<EventList>("EventList");
