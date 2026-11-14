# Security

Svavyom is a **Development Preview**. It runs services with access to your virtualization host, so please report vulnerabilities privately and responsibly.

Svavyom has **one maintainer**. There is no security team, no on-call rota and no fallback contact: reports are handled on a best-effort basis, as quickly as one person can.

## Reporting a vulnerability
Use GitHub's **private vulnerability reporting** on this repository (the *Security* tab, *Report a vulnerability*). Do not open a public issue for a vulnerability. Please include the version (`svavyom-ctl version`), what you did, what you expected and what happened; **never include passwords, session cookies, console tickets, private keys or a support bundle that you have not read through**.

The maintainer will acknowledge a report, say whether it is considered a vulnerability, and agree a disclosure date with you. There is no committed response time; please allow reasonable time.

## What to expect of the product
* The design and its known gaps are in [Safety design](https://docs.svavyom.com/concepts/safety/), [Security](https://docs.svavyom.com/security/) and [Known limitations](https://docs.svavyom.com/known-limitations/). Read them before you rely on Svavyom.
* Releases from 0.1.0-preview.16 are **signed** with the maintainer's Ed25519 key (fingerprint `247e9193c933b6fa`, `ci/sign/README.md`). `svavyom-ctl install` and `upgrade` refuse an artifact that is not signed with the key you give them (or, for one you built yourself, that is not out of reach of everyone but root). Compare the fingerprint with the one in this repository before you trust a key, and verify the signature **before** you run anything from the artifact (`INSTALLING.md`). Earlier releases are unsigned.
* The decisions that shaped the product were recorded by the maintainer and were **not independently reviewed** (there is no second reviewer); the release notes say so.
* The web console is served over HTTPS with a self-signed certificate unless you install your own. Bind it to loopback and use an SSH tunnel or a reverse proxy you control if you are unsure.

## Scope
In scope: the services in this repository (`backend/`, `frontend/`, `packages/`) and the installer. Out of scope: vulnerabilities in QEMU, libvirt, the guest operating systems you run, or your own network.
