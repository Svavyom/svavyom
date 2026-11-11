// fe-unit: the browser-made SSH key (DR-040 D2). The file format is pinned by a golden file that the Go tests parse with golang.org/x/crypto/ssh, an independent
// implementation of the OpenSSH format: backend/internal/sshkeys/testdata/browser-generated.key. If the format changes on purpose, copy the "received" value
// of the failing comparison into those two files; the Go test then proves the new bytes still parse.
import { describe, expect, it } from "vitest";
import goldenKey from "../../../backend/internal/sshkeys/testdata/browser-generated.key?raw";
import goldenPub from "../../../backend/internal/sshkeys/testdata/browser-generated.pub?raw";
import { canGenerate, fingerprint, generateKeyPair, opensshPrivateKey, publicLine } from "./keygen";

const c = globalThis.crypto;
const SEED = Uint8Array.from({ length: 32 }, (_, i) => i + 1);
const PKCS8_PREFIX = Uint8Array.from("302e020100300506032b657004220420".match(/../g)!.map((h) => parseInt(h, 16)));
const unb64 = (s: string) => Uint8Array.from(atob(s), (ch) => ch.charCodeAt(0));
const b64 = (b: Uint8Array) => btoa(String.fromCharCode(...b));
const b64url = (s: string) => unb64(s.replace(/-/g, "+").replace(/_/g, "/"));
/** The public key of a seed, taken from the JWK export of the imported private key (an implementation independent of keygen.ts). */
async function publicOf(seed: Uint8Array): Promise<Uint8Array> {
  const priv = await c.subtle.importKey("pkcs8", new Uint8Array([...PKCS8_PREFIX, ...seed]), { name: "Ed25519" }, true, ["sign"]);
  return b64url(((await c.subtle.exportKey("jwk", priv)) as JsonWebKey).x!);
}
const body = (file: string) => unb64(file.split("\n").slice(1, -2).join(""));

describe("OpenSSH key file", () => {
  it("matches the golden file that the Go tests parse with x/crypto/ssh", async () => {
    const pub = await publicOf(SEED);
    expect(opensshPrivateKey(SEED, pub, "golden@svavyom", 0x01020304)).toBe(goldenKey);
    expect(publicLine(pub, "golden@svavyom") + "\n").toBe(goldenPub);
  });

  it("has the openssh-key-v1 layout: unencrypted, one key, the same check value twice, padding to a multiple of 8", async () => {
    const file = opensshPrivateKey(SEED, await publicOf(SEED), "golden@svavyom", 0x01020304);
    expect(file.startsWith("-----BEGIN OPENSSH PRIVATE KEY-----\n") && file.endsWith("-----END OPENSSH PRIVATE KEY-----\n")).toBe(true);
    const b = body(file);
    const dv = new DataView(b.buffer);
    expect(String.fromCharCode(...b.subarray(0, 15))).toBe("openssh-key-v1\0");
    let at = 15;
    const read = () => { const n = dv.getUint32(at); const v = b.subarray(at + 4, at + 4 + n); at += 4 + n; return v; };
    expect(String.fromCharCode(...read())).toBe("none");
    expect(String.fromCharCode(...read())).toBe("none");
    expect(read().length).toBe(0);
    expect(dv.getUint32(at)).toBe(1); at += 4;
    expect(String.fromCharCode(...read())).toContain("ssh-ed25519");
    const priv = read();
    expect(at).toBe(b.length);
    const pdv = new DataView(priv.buffer, priv.byteOffset, priv.length);
    expect(pdv.getUint32(0)).toBe(0x01020304);
    expect(pdv.getUint32(4)).toBe(0x01020304);
    expect(priv.length % 8).toBe(0);
  });

  it("computes the fingerprint ssh-keygen prints (SHA-256 of the key blob, base64 without padding)", async () => {
    const pub = await publicOf(SEED);
    const blob = unb64(publicLine(pub).split(" ")[1]);
    const want = "SHA256:" + b64(new Uint8Array(await c.subtle.digest("SHA-256", blob))).replace(/=+$/, "");
    expect(await fingerprint(pub, c.subtle)).toBe(want);
  });
});

describe("generateKeyPair", () => {
  it("makes an Ed25519 pair whose public line and private file belong together, and returns nothing else", async () => {
    const k = await generateKeyPair("me@laptop", c);
    expect(Object.keys(k).sort()).toEqual(["fingerprint", "privateFile", "publicLine"]);
    expect(k.publicLine).toMatch(/^ssh-ed25519 [A-Za-z0-9+/]+=* me@laptop$/);
    expect(k.fingerprint).toMatch(/^SHA256:[A-Za-z0-9+/]{43}$/);
    const pubBytes = unb64(k.publicLine.split(" ")[1]).subarray(-32);
    expect(String.fromCharCode(...body(k.privateFile))).toContain(String.fromCharCode(...pubBytes)); // the private file embeds the same public key
    expect((await generateKeyPair("me@laptop", c)).fingerprint).not.toBe(k.fingerprint);
  });

  it("reports whether a key can be made here", () => {
    expect(canGenerate(c, true)).toBe(true);
    expect(canGenerate(c, false)).toBe(false);
    expect(canGenerate(null, true)).toBe(false);
  });
});
