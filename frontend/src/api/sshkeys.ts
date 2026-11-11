// The saved SSH public keys (DR-040; contracts/openapi.yaml /api/v1/ssh-keys). Public keys only: nothing in this module ever holds a private key.
import { exchange, read } from "./client";
import { decoderFor } from "./decoders";
import { csrfToken } from "./session";
import type { SshKey, SshKeyList } from "./schema";

export const decodeSshKey = decoderFor<SshKey>("SshKey");
export const decodeSshKeyList = decoderFor<SshKeyList>("SshKeyList");

export const listSshKeys = () => read("/api/v1/ssh-keys", decodeSshKeyList);
export const addSshKey = (name: string, publicKey: string) => exchange("POST", "/api/v1/ssh-keys", decodeSshKey, { body: { name, public_key: publicKey }, csrf: csrfToken() });
export const deleteSshKey = (id: string) => exchange("DELETE", `/api/v1/ssh-keys/${id}`, decodeSshKey, { csrf: csrfToken() });
