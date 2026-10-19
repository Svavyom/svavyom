# Licensing

Copyright 2026 Dhanraj Sheth. Svavyom is free software; **no limit, licence key, trial, nag screen or call home exists in it** (and `make boundary` fails if one is added).

| What | Where | Licence |
|---|---|---|
| The server product: services, web console, installer and operator tool, deployment packages, build toolchain, tests | `backend/`, `frontend/`, `agent/`, `packages/`, `toolchain/`, `ci/`, `.github/`, `tests/`, `release/`, build files | **GNU AGPL-3.0-or-later** (`LICENSE`, `LICENSES/AGPL-3.0-or-later.txt`) |
| The interface contracts (the HTTP API, the console channel) | `contracts/` | **Apache-2.0** (`LICENSES/Apache-2.0.txt`) |
| Tools (qualification harnesses, gates, release scripts) | `tools/` | **Apache-2.0** |
| Documentation | `docs/`, the top-level `*.md` files | **Apache-2.0** |
| Third-party components | `THIRD-PARTY-NOTICES.md`, `docs/sbom/` | their own licences (permissive, plus weak copyleft that is only dynamically linked or a runtime prerequisite and is not bundled) |

The exact map is `REUSE.toml`, generated from `release/open-core.json`.

## What this means in practice
* **You may use Svavyom on as many servers as you like, for any purpose, including commercially, at no cost.**
* **You may modify it.** If you run a **modified** version as a network service that other people use, the AGPL requires you to offer those users the corresponding source of your modified version (section 13). If you only use it, or run it unmodified, you have no such duty.
* **Anyone may build tools on the API contract and the tools under Apache-2.0**, including closed-source ones.
* **Separate programmes that talk to Svavyom through its documented HTTP API are not part of it** and may use any licence.
* Svavyom is built so that commercially licensed add-on modules, if any exist, are separate programmes in a separate repository that use only the documented API; nothing in this repository depends on them (`release/open-core.json`, `tools/check_open_core.py`).
* A commercial licence for those who cannot accept the AGPL, and paid support, may be offered by the copyright owner; nothing here depends on them.

## Contributions
Outside code contributions need a signed contributor licence agreement (`CONTRIBUTING.md`, `CLA.md`) so that the project can keep offering the code under these licences and, where needed, under others. Until the agreement is in place, pull requests are not accepted; issues are welcome.

## Name
"Svavyom" is the name of this project. It is **not a registered trademark**; the project does not claim rights in the name beyond those that use gives.

This file describes the intent and the structure; the licence texts govern. It is not legal advice.
