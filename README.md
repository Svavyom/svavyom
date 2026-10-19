# Svavyom

**Svavyom is a Development Preview / Pre-Alpha.** It is a free, open control plane for **KVM/libvirt virtualization on dedicated Linux servers**: you manage VMs, storage, backups, networks and consoles from a web page, and the tool installs on the server you already have. It is for evaluation and for non-critical use; read [`RELEASE-NOTES-DEVELOPMENT-PREVIEW.md`](https://github.com/Svavyom/svavyom-docs/blob/main/RELEASE-NOTES-DEVELOPMENT-PREVIEW.md) and [`KNOWN-LIMITATIONS.md`](https://github.com/Svavyom/svavyom-docs/blob/main/KNOWN-LIMITATIONS.md) for exactly what is supported, what has been qualified on real hardware and what is not offered.

* **Source and releases:** <https://github.com/Svavyom/svavyom>. **Documentation:** <https://github.com/Svavyom/svavyom-docs> (architecture, operations, security, qualification records).
* **Free to use on as many servers as you like.** No limit, licence key, trial or call home (`LICENSING.md`).
* **Tested on:** Ubuntu 24.04 LTS, x86_64, KVM, libvirt `qemu:///system`. One host per installation.
* **Not claimed:** high availability, multi-host management, stability guarantees, or suitability for production workloads. Release artifacts are **not signed** yet.

## What you get
VM lifecycle (create from a qualified cloud image with an SSH key, start, stop, reboot, force off, delete), serial and graphical (VNC) consoles in the browser, installation media and rescue mode, snapshots, backups and restore (local and to a directory or SSH target), scheduled backups, managed NAT networks and an optional host bridge, alerts with a webhook, a nightly guest boot check, usage graphs, three roles (admin, operator, viewer), and an installer, upgrader and support-bundle tool (`svavyom-ctl`).

## Start here
| I want to | Read |
|---|---|
| Build it from source | `BUILDING.md` |
| Install it on a server | `INSTALLING.md` |
| Use it | `USING.md` |
| Know what is and is not supported | [`KNOWN-LIMITATIONS.md`](https://github.com/Svavyom/svavyom-docs/blob/main/KNOWN-LIMITATIONS.md), [`RELEASE-NOTES-DEVELOPMENT-PREVIEW.md`](https://github.com/Svavyom/svavyom-docs/blob/main/RELEASE-NOTES-DEVELOPMENT-PREVIEW.md), [`LAUNCH-CLAIMS.md`](https://github.com/Svavyom/svavyom-docs/blob/main/LAUNCH-CLAIMS.md) |
| Understand how it is built and secured | [`ARCHITECTURE.md`](https://github.com/Svavyom/svavyom-docs/blob/main/ARCHITECTURE.md), [`THREAT-MODEL.md`](https://github.com/Svavyom/svavyom-docs/blob/main/THREAT-MODEL.md), [`SECURITY-BASELINE.md`](https://github.com/Svavyom/svavyom-docs/blob/main/SECURITY-BASELINE.md) |
| Report a vulnerability | `SECURITY.md` |
| Contribute | `CONTRIBUTING.md` |
| Know the licence | `LICENSING.md`, `LICENSE`, `NOTICE`, `THIRD-PARTY-NOTICES.md` |

## What is in the tree
| Path | Content |
|---|---|
| `backend/` | Go services: `api`, read-only `agent`, `mutation-supervisor` and short-lived `mutation-helper`, `console-broker`, `offsite`, and the operator tool `svavyom-ctl`; domain packages under `internal/` |
| `frontend/` | React + TypeScript web console |
| `contracts/` | the HTTP API contract (`openapi.yaml`, Apache-2.0), interface contracts, threat register |
| `packages/` | Ubuntu deployment package: systemd units, sysusers, tmpfiles |
| `tools/`, `tests/`, `toolchain/` | build, gates, qualification harnesses and their tests; the pinned Docker toolchain |
| `docs/sbom/` | the software bill of materials and the third-party licence inventory (the rest of the documentation is in the separate documentation repository, https://github.com/Svavyom/svavyom-docs) |

## Safety design in one paragraph
Local-admin authentication with server-side sessions and derived CSRF; a non-root API; a separate read-only libvirt agent, a separate mutation supervisor and a separate console broker; a closed mutation protocol that carries names, never paths or XML; root-owned trust anchors that no runtime identity can write; AppArmor required; ownership proven before anything destructive. No arbitrary shell or libvirt call is reachable from the browser ([`ARCHITECTURE.md`](https://github.com/Svavyom/svavyom-docs/blob/main/ARCHITECTURE.md)).

## Licence
Copyright 2026 Dhanraj Sheth. The server product is **AGPL-3.0-or-later**; contracts, tools and documentation are **Apache-2.0** (`LICENSING.md`). "Svavyom" is not a registered trademark.
