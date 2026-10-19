# Security

Svavyom is a **Development Preview**. It runs services with access to your virtualization host, so please report vulnerabilities privately and responsibly.

## Reporting a vulnerability
Use GitHub's **private vulnerability reporting** on this repository (the *Security* tab, *Report a vulnerability*). Do not open a public issue for a vulnerability. Please include the version (`svavyom-ctl version`), what you did, what you expected and what happened; **never include passwords, session cookies, console tickets, private keys or a support bundle that you have not read through**.

We will acknowledge a report, tell you whether we consider it a vulnerability, and agree a disclosure date with you. This is a small project: please allow reasonable time.

## What to expect of the product
* The design and its known gaps are in [`THREAT-MODEL.md`](https://github.com/Svavyom/svavyom-docs/blob/main/THREAT-MODEL.md), [`SECURITY-BASELINE.md`](https://github.com/Svavyom/svavyom-docs/blob/main/SECURITY-BASELINE.md) and [`KNOWN-LIMITATIONS.md`](https://github.com/Svavyom/svavyom-docs/blob/main/KNOWN-LIMITATIONS.md). Read them before you rely on Svavyom.
* Release artifacts are **not signed** yet; verify them against the published `SHA256SUMS` over a channel you trust (`INSTALLING.md`).
* The web console is served over HTTPS with a self-signed certificate unless you install your own. Bind it to loopback and use an SSH tunnel or a reverse proxy you control if you are unsure.

## Scope
In scope: the services in this repository (`backend/`, `frontend/`, `packages/`) and the installer. Out of scope: vulnerabilities in QEMU, libvirt, the guest operating systems you run, or your own network.
