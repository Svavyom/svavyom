# Building Svavyom from source

This takes you from an empty Linux machine to a **verified release artifact** that `INSTALLING.md` installs. Everything is built and tested inside a pinned, unprivileged Docker toolchain, so the machine needs no Go, Node or Python toolchain of its own.

## 1. What you need
| Need | Detail |
|---|---|
| Machine | Linux x86_64, 4 vCPU, 16 GiB RAM, 60 GiB free disk. Ubuntu 24.04 is the reference. |
| Docker | Docker Engine with Compose v2. Your user must run `docker` **without sudo and must not be root** (the `make docker-*` targets refuse root). |
| Other tools | GNU `make`, `git` 2.44 or newer, Python 3. |
| Network | The first build pulls the pinned base images and the dependency caches; two gates (`go-vuln`, `fe-audit`) need outbound access to `vuln.go.dev` and the npm registry. |

```
git clone https://github.com/Svavyom/svavyom.git
cd svavyom
```

## 2. The pinned toolchain
`toolchain/versions.env` pins Go, Node, Python, staticcheck, gosec, govulncheck and gitleaks (base images by digest). `make docker-image` builds the development image from `toolchain/Dockerfile`; the first time takes several minutes.

## 3. Build and test
| Command | What it does | Time |
|---|---|---|
| `make docker-public-check` | every gate a public checkout can run: format, vet, staticcheck, gosec, Go tests with the race detector, vulnerability scan, the Python gate tests, frontend install, type-check, build, audit and unit tests, secret scan, CI policy, launch claims, public/private and open-core boundary, licence and SBOM currency | about 7 min |
| `make docker-fe-browser` | the Chromium tier against the real API process and a simulated host (accessibility included) | about 5 min |
| `make docker-release` | build the release artifact (section 4) | about 2 min |

`make docker-check` is the project's **own full set**: it additionally validates against the maintainers' separate requirements repository (decision records, the API baseline history, evidence records, backlog linkage) and needs it checked out next to this one at `../cloud-product-docs`. It is not available to a public checkout; `make docker-public-check` is the set to use.

Real-KVM qualification is a separate, manual, privileged tier on a disposable authorised host (the `QUALIFICATION-*.md` documents in the documentation repository); it never runs in a gate. Gate tests never manipulate the host's libvirt networking.

## 4. The release artifact
Commit or stash your changes (the artifact records the commit it was built from), then:
```
make docker-release
```
It builds the Go binaries on an Ubuntu 24.04 builder (`toolchain/release/`), builds the web bundle, assembles `release-out/svavyom-<version>/` from **tracked files only**, writes `MANIFEST.json` (every file with SHA-256, size and mode) and `SHA256SUMS`, and verifies the result. It refuses to overwrite an existing directory and **signs and publishes nothing**.

Contents: `bin/` (the seven binaries: `api`, `agent`, `mutation-supervisor`, `mutation-helper`, `console-broker`, `offsite`, `svavyom-ctl`), `web/`, `packages/ubuntu/` (systemd units and installer inputs), `docs/sbom/` (the bill of materials), the top-level documents, `LICENSE`, `LICENSES/`, `NOTICE`, `THIRD-PARTY-NOTICES.md`, `VERSION`, `SOURCE-OFFER.md`.

Verify any artifact with its own tool: `release-out/svavyom-<version>/bin/svavyom-ctl verify-artifact release-out/svavyom-<version>`.

## 5. Working on the code
| Area | Where | Notes |
|---|---|---|
| Go services | `backend/` | `cd backend && go test ./...` works with a local Go toolchain of the pinned version; the libvirt-linked packages need `-tags "libvirt libvirt_test"` and `libvirt-dev` |
| Web console | `frontend/` | `npm ci && npm run build && npm test`; strict TypeScript; the API types are generated from `contracts/openapi.yaml` (`python3 tools/gen_api_types.py --write`) |
| API contract | `contracts/openapi.yaml` | edit it first; generated code and the types follow |
| Operator tool | `backend/cmd/svavyom-ctl` | install, upgrade, bridge and diagnostics |

Changing the version: edit `VERSION`, run `toolchain/regen-sbom.sh` (regenerates `docs/sbom/*` and `THIRD-PARTY-NOTICES.md`; the licence gate fails if they are stale), update the version named in [`RELEASE-NOTES-DEVELOPMENT-PREVIEW.md`](https://github.com/Svavyom/svavyom-docs/blob/main/RELEASE-NOTES-DEVELOPMENT-PREVIEW.md), run the gates, then build the artifact.

## 6. If something fails
| Symptom | Cause and fix |
|---|---|
| `make docker-* refuses to run as root` | run as a normal user in the `docker` group |
| `go-vuln` or `fe-audit` fail without a code change | no network, or a newly published advisory: fix the network or update the dependency |
| `release-out/svavyom-<v> exists` | move or delete the old artifact directory on purpose |
| the browser tier fails on accessibility only | a colour, target size or label regression: the rule and element are printed |
| the licence gate says SBOM drift | run `toolchain/regen-sbom.sh` and commit the result |
| `make boundary` fails on a new file | add it to a tier in `release/open-core.json` and to `release/boundary.json`; run `python3 tools/check_open_core.py --write` to regenerate `REUSE.toml` |

## 7. Honest limits
The build is not yet proven reproducible byte for byte, no hosted CI has run it, and the artifact is unsigned ([`TECH-DEBT.md`](https://github.com/Svavyom/svavyom-docs/blob/main/TECH-DEBT.md)). Signing options are in [`SIGNING-OPTIONS.md`](https://github.com/Svavyom/svavyom-docs/blob/main/SIGNING-OPTIONS.md).
