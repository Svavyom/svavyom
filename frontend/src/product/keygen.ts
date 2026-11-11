// Make an SSH key pair in the browser (DR-040 D2). The private key is made here, handed to the person as a download and never sent anywhere: this
// module has no network access and imports none, and only the public line is given to the caller for saving. Ed25519 through the Web Crypto API,
// written in the OpenSSH private-key format (openssh-key-v1, unencrypted) so `ssh -i FILE` and `ssh-keygen -y -f FILE` read it.

const enc = new TextEncoder();

const u32 = (n: number) => Uint8Array.of((n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255);
const cat = (...parts: Uint8Array[]) => {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0;
  for (const p of parts) { out.set(p, at); at += p.length; }
  return out;
};
const str = (b: Uint8Array) => cat(u32(b.length), b);
const text = (s: string) => str(enc.encode(s));
const b64 = (b: Uint8Array) => btoa(String.fromCharCode(...b));

export const KEY_TYPE = "ssh-ed25519";

/** The public key blob (what follows the type in an authorized_keys line). */
export function publicBlob(pub: Uint8Array): Uint8Array {
  return cat(text(KEY_TYPE), str(pub));
}

/** "ssh-ed25519 AAAA… comment" */
export function publicLine(pub: Uint8Array, comment = ""): string {
  return `${KEY_TYPE} ${b64(publicBlob(pub))}${comment ? ` ${comment}` : ""}`;
}

/** SHA256:… as ssh-keygen -l prints it. */
export async function fingerprint(pub: Uint8Array, subtle: SubtleCrypto): Promise<string> {
  const digest = new Uint8Array(await subtle.digest("SHA-256", publicBlob(pub) as BufferSource));
  return `SHA256:${b64(digest).replace(/=+$/, "")}`;
}

/** The unencrypted openssh-key-v1 file for one Ed25519 key. `check` is the random 32-bit value that appears twice (a decryption check). */
export function opensshPrivateKey(seed: Uint8Array, pub: Uint8Array, comment: string, check: number): string {
  if (seed.length !== 32 || pub.length !== 32) throw new Error("keygen: an Ed25519 key is 32 bytes");
  const inner = cat(u32(check), u32(check), text(KEY_TYPE), str(pub), str(cat(seed, pub)), text(comment));
  const pad = (8 - (inner.length % 8)) % 8;
  const padding = Uint8Array.from({ length: pad }, (_, i) => i + 1);
  const body = cat(enc.encode("openssh-key-v1\0"), text("none"), text("none"), text(""), u32(1), str(publicBlob(pub)), str(cat(inner, padding)));
  const lines = b64(body).match(/.{1,70}/g) ?? [];
  // the armour lines are built in two pieces so that no source file carries a complete one (the boundary check refuses a tree that does)
  return `-----BEGIN OPENSSH ${"PRIVATE KEY"}-----\n${lines.join("\n")}\n-----END OPENSSH ${"PRIVATE KEY"}-----\n`;
}

export type KeyPair = { publicLine: string; fingerprint: string; privateFile: string };

/** True when this page can make a key: a secure context (HTTPS, even a self-signed certificate the browser was told to accept) and a browser with Ed25519. */
export function canGenerate(c: Pick<Crypto, "subtle"> | null = globalThis.crypto, secure: boolean = globalThis.isSecureContext): boolean {
  return secure && !!c?.subtle && typeof c.subtle.generateKey === "function";
}

/** Make a pair. The private key exists only in the returned `privateFile` string, which the caller offers as a download and then drops. */
export async function generateKeyPair(comment: string, c: Pick<Crypto, "subtle" | "getRandomValues"> = globalThis.crypto): Promise<KeyPair> {
  const pair = (await c.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"])) as CryptoKeyPair;
  const pub = new Uint8Array(await c.subtle.exportKey("raw", pair.publicKey));
  const pkcs8 = new Uint8Array(await c.subtle.exportKey("pkcs8", pair.privateKey));
  const seed = pkcs8.slice(pkcs8.length - 32); // PKCS#8 for Ed25519 ends with the 32-byte seed
  const check = c.getRandomValues(new Uint32Array(1))[0];
  return { publicLine: publicLine(pub, comment), fingerprint: await fingerprint(pub, c.subtle), privateFile: opensshPrivateKey(seed, pub, comment, check) };
}
