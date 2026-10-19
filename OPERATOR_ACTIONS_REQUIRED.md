# Operator actions required (external; not performed by the coder)

Each item needs an account, an administrator, the qualification-host operator or the Sponsor. None is represented as complete. Status values: OPEN until a human records otherwise.
Nothing in the M0-M4 train was published, signed, announced or launched.

## Sponsor
| # | Action | Why it is external | Blocks |
|---|---|---|---|
| L1 | ~~Licence~~ **CLOSED (2026-10-19): open core.** AGPL-3.0-or-later for the server product, Apache-2.0 for contracts, tools and documentation, premium modules (if any) separate and commercially licensed; no limits (`LICENSING.md`, `LICENSE`). Applied in the files named there, the SBOM root component, the manifest `license` field and `docs/LAUNCH-CLAIMS.md` | - | - |
| L2 | **Copyright owner: Dhanraj Sheth (named 2026-10-19).** Still open: **counsel review** of the licence structure, the contributor agreement (`CLA.md`, a draft) and the notices, and the trademark decision (the name is not registered) | needs legal review | accepting outside contributions; any claim of trademark rights |
| S1 | ~~Ratify DR-019, DR-020 and DR-021~~ **CLOSED:** ratified by the Human Product Sponsor (docs `SPONSOR-CONFIRMATION-2026-10-12.md`; DR-021 with an amendment) | - | - |
| S2 | ~~Amend DR-021's reservation wording~~ **CLOSED:** amended by the Sponsor ratification; TD-AD remains only as a product limitation | - | - |
| S3 | **Decide how releases are signed and distributed** (key custody, channel). The Development Preview artifact is unsigned and was built locally; integrity rests on `MANIFEST.json`/`SHA256SUMS` compared with a digest received out of band (TD-AG) | a key and a channel are an operator/Sponsor choice | any distribution of the artifact |

## Release engineering (Jenkins, signing)
| # | Action | Exact steps | Status |
|---|---|---|---|
| J1 | Create the Jenkins VMs (controller, build agent) and run the pipeline once with `SIGNING_METHOD=none` | `docs/JENKINS-SETUP.md`; the files have never been executed, send fixes back | OPEN |
| J2 | Decide the signing format, key custody and distribution channel (S3), generate the key, publish its fingerprint in two places, rehearse with a test artifact | `docs/SIGNING-OPTIONS.md` | OPEN |
| J3 | Lift the hold on CT-LAUNCH-SIGNING-001 and approve the Publish step | requirements: `docs/SIGNING-OPTIONS.md` section 7 | OPEN |
| J4 | Move development to a dedicated VM | `docs/DEVELOPMENT-ENVIRONMENT.md` | OPEN |

## Qualification-host operator (`the-qualification-host`)
| # | Action | Exact steps | Status |
|---|---|---|---|
| H1 | **Reboot the host once and confirm recovery** (not authorised in the qualification window; TD-AI) | `sudo reboot`; after it is back: `sudo /usr/libexec/svavyom/svavyom-ctl status` must say PASS, `virsh -r net-list --all` shows `default` active; units are enabled and the pool/network are autostart. The clean-room VM reboot already passed | OPEN |
| H2 | Review and remove `/etc/svavyom/provision.json.pre-m4` (the hand-made configuration that was set aside because it lacked the console identity and the backup path) once you have compared it with `/etc/svavyom/provision.json` | `sudo diff /etc/svavyom/provision.json.pre-m4 /etc/svavyom/provision.json`, then `sudo rm` | OPEN |
| H3 | Decide whether the installed system stays (version 0.1.0-preview.0, listening on `127.0.0.1:8443`, one administrator created for the qualification) or is removed: `sudo svavyom-ctl uninstall --apply` keeps data; `--purge --confirm-purge DELETE-SVAVYOM-DATA` removes Svavyom's own configuration, database and accounts. The administrator's password was generated randomly for the qualification and its file has been deleted, so nobody knows it: set a new one first (stop `svavyom-api`, `sudo -u svavyom-api /usr/libexec/svavyom/api reset-admin-password --db /var/lib/svavyom/api/svavyom.db --username admin < PASSWORD_FILE`, start it) | | OPEN |
| H4 | Provide a real TLS certificate and a reverse proxy or non-loopback listener if the host is to be reached remotely (`--tls-self-signed` is for labs) | `docs/INSTALL.md` | OPEN |

## Repository administrator (hosted CI and review controls)
| # | Action | Exact steps | Status |
|---|---|---|---|
| R1 | Create/identify the hosted repository, push `main`, create the repository variable `DOCS_REPOSITORY` (`owner/cloud-product-docs`) | Settings -> Secrets and variables -> Actions -> Variables -> New | OPEN |
| R2 | Create the teams named in `.github/CODEOWNERS` (`@svavyom/product-owners`, `@svavyom/security-reviewers`) or replace them with real owners | Organization -> Teams; then edit CODEOWNERS | OPEN |
| R3 | Import `.github/rulesets/main-protection.json` | Settings -> Rules -> Rulesets -> New ruleset -> Import a ruleset; choose how milestone merges are done (see `docs/BRANCH-PROTECTION.md`, "Linear history note") | OPEN |
| R4 | Verify the pinned action SHAs of `docs/CI-PINS.md` against the upstream tags, then run the workflow once and record the run URL | `git ls-remote https://github.com/actions/checkout <tag>` and compare; then Actions -> CI -> Run workflow | OPEN |
| R5 | Confirm that the hosted runner has Docker, outbound access to `vuln.go.dev` and the npm registry, and enough disk (the gate needs ~6 GiB) | runner image documentation | OPEN |

Hosted CI execution status: **not run** (no hosted repository is reachable from this workspace).

## Launch workspace
| # | Action | Notes |
|---|---|---|
| W1 | The launch coder consumes the immutable snapshot and manifests produced at the final handoff (`release/`, and the release artifact's `MANIFEST.json` audience column) | the product coder never modifies `/home/user/Svavyom-Web` |
| W2 | Rebuild the release artifact from the final commit with `make docker-release` and compare the binaries' digests with the qualified build before any distribution | `docs/OPERATIONS.md` section 5 |
