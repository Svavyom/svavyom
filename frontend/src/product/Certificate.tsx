// The console's TLS certificate (DR-034): what is in use, how long it is good for, whether it renews by itself, and the exact commands to run on the host to
// get a free certificate from Let's Encrypt. Read-only: issuing and renewing need root, port 80 or 443 and the host's own DNS name, so they are done with
// svavyom-ctl on the host. Words live here, keyed by the closed codes the server sends: no message from the host reaches the page.
import { DataTable, StatusMessage } from "../design-system";
import type { Host } from "../api/schema";

type Cert = NonNullable<Host["observed"]["certificate"]>;

const SOURCE: Record<Cert["source"], string> = {
  self_signed: "Self-signed (made by Svavyom's installer)", lets_encrypt: "Let's Encrypt", lets_encrypt_staging: "Let's Encrypt STAGING (a test certificate)", other: "Another authority (your own certificate)",
};

// What a failed attempt means and what to do, by closed code.
const WHY: Record<string, string> = {
  dns_mismatch: "The name does not resolve to an address of this host. Point its DNS record at the host (a record that is only DNS, not a proxy), or, behind NAT, add --skip-dns-check.",
  port_in_use: "Port 80 (or 443 for tls-alpn-01) is used by another program on the host. Free it for the minute the request takes.",
  validation_failed: "Let's Encrypt could not validate the name. Check that the DNS record points at this host and that port 80 (or 443) is reachable from the internet through the host's firewall and the provider's.",
  rate_limited: "Let's Encrypt's rate limit is reached. Nothing is asked again for 12 hours; the staging service has higher limits.",
  account_registration_failed: "Registering the account with Let's Encrypt failed. Check that the host can reach the internet, then try again.",
  terms_not_accepted: "The terms of service were not accepted (--accept-terms).",
  bad_input: "The name or the e-mail address was not accepted.",
  staging_first: "Run the staging rehearsal first (--staging).",
  issue_failed: "The request failed. See the command's own message on the host.",
};

export function certificateTone(c: Cert): "ok" | "warn" | "bad" {
  if (c.days_left <= 3) return "bad";
  return c.days_left <= 14 || c.source === "lets_encrypt_staging" ? "warn" : "ok";
}

const day = (iso: string) => iso.slice(0, 10);

export function CertificateSection(props: { cert: Cert | null }) {
  const c = props.cert;
  if (c === null) {
    return (
      <section aria-labelledby="sys-cert-title">
        <h2 id="sys-cert-title">Certificate</h2>
        <p>Svavyom is not ending TLS itself here: a proxy in front of it does, so the certificate your browser sees is the proxy&apos;s.</p>
      </section>
    );
  }
  const tone = certificateTone(c);
  const lastOk = c.last_result === "ok";
  return (
    <section aria-labelledby="sys-cert-title">
      <h2 id="sys-cert-title">Certificate</h2>
      {tone === "bad" ? <StatusMessage tone="warning">{c.days_left < 0 ? "This certificate has expired." : `This certificate expires in ${c.days_left} day${c.days_left === 1 ? "" : "s"}.`} Browsers will refuse it.</StatusMessage> : null}
      {tone === "warn" && c.source !== "lets_encrypt_staging" ? <StatusMessage tone="warning">This certificate expires in {c.days_left} days.</StatusMessage> : null}
      {c.source === "lets_encrypt_staging" ? <StatusMessage tone="warning">This is a Let&apos;s Encrypt staging certificate: browsers do not trust it. Run the production request.</StatusMessage> : null}
      <DataTable caption="The certificate in use" rows={[
        ["Names", c.names.join(", ")],
        ["Issuer", SOURCE[c.source]],
        ["Valid", `${day(c.not_before)} to ${day(c.not_after)} (${c.days_left < 0 ? "expired" : `${c.days_left} days left`})`],
        ["Renewal", c.managed ? `Automatic, from ${day(c.renews_from)} (when a third of its life is left)` : c.source === "self_signed" ? "Not renewed: replace it before it expires" : "Not renewed by Svavyom"],
        ["Last attempt", c.last_attempt === null ? "None recorded" : `${day(c.last_attempt)}: ${lastOk ? "succeeded" : "failed"}`],
      ] as ReadonlyArray<[string, string]>} rowKey={(r) => r[0]} columns={[
        { header: "Item", cell: (r) => r[0], rowHeader: true },
        { header: "Value", cell: (r) => r[1] },
      ]} />
      {c.last_result !== null && !lastOk ? <StatusMessage tone="warning">The last attempt failed ({c.last_result}). {WHY[c.last_result] ?? "See the command's own message on the host."}</StatusMessage> : null}
      {c.source === "self_signed" ? (
        <>
          <p>Browsers warn about a self-signed certificate. If this host has a public DNS name that points straight at it, you can switch to a free certificate from Let&apos;s Encrypt. On the host, as root, first rehearse (nothing is installed):</p>
          <pre><code>sudo svavyom-ctl tls acme-issue --name YOUR.NAME.EXAMPLE --email YOU@EXAMPLE --accept-terms --staging</code></pre>
          <p>then ask for the real one (the console picks it up within a minute, with no restart, and a daily timer renews it):</p>
          <pre><code>sudo svavyom-ctl tls acme-issue --name YOUR.NAME.EXAMPLE --email YOU@EXAMPLE --accept-terms</code></pre>
          <p>Let&apos;s Encrypt must reach port 80 of this host from the internet for the minute it takes (<code>--challenge tls-alpn-01</code> uses port 443 instead); Svavyom opens a listener only for that time and changes no firewall rule, so allow the port first. A name behind a proxy such as Cloudflare does not need this: keep the self-signed certificate (SSL mode Full) or install the proxy&apos;s origin certificate.</p>
        </>
      ) : null}
      {c.source === "lets_encrypt" && !c.managed ? <p>This certificate is not renewed by Svavyom. To have it renewed, run <code>sudo svavyom-ctl tls acme-issue</code> as above.</p> : null}
      {c.managed ? <p>To go back to a self-signed certificate: <code>sudo svavyom-ctl tls use-self-signed --name YOUR.NAME.EXAMPLE</code>. To renew now: <code>sudo svavyom-ctl tls acme-renew</code> (it does nothing until a third of the lifetime is left).</p> : null}
    </section>
  );
}
