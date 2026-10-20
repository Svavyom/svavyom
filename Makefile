# Quality gates (story M0-E02-S02). Each target exits non-zero on failure;
# recipes use `set -eu` and never pipe a gate's output through another command.
# Run `make docker-check` for the pinned toolchain; `make check` assumes you are
# already inside it (or have identical tool versions).
SHELL := /bin/sh
.SHELLFLAGS := -eu -c
.DEFAULT_GOAL := check

DOCS_REPO ?= ../cloud-product-docs
LINKAGE_BASE ?= main
LINKAGE_MODE ?= full
REQUIRE_COMMITS ?= 0
COMPOSE := HOST_UID=$$(id -u) HOST_GID=$$(id -g) docker compose --env-file toolchain/versions.env
# Linkage parameters reach recipes only through the environment and are
# validated before use; never expanded into shell text (S02 review F7, N8).
# Defaults must be assigned before `export` (review cycle 2, N2).
export DOCS_REPO LINKAGE_BASE LINKAGE_MODE REQUIRE_COMMITS

GO_GATES := go-fmt go-vet go-staticcheck go-gosec go-test go-test-libvirt go-vuln
FE_GATES := fe-install fe-check fe-build fe-audit fe-unit fe-negative
GATES := versions $(GO_GATES) py-check $(FE_GATES) secrets ci-policy interfaces openapi threats evidence evidence-faults capability decisions installer-safety claims boundary licenses

# The gates a public checkout can run on its own (no access to the separate requirements repository). `make check` is the full set.
PUBLIC_GATES := versions go-fmt go-vet go-staticcheck go-gosec go-test go-test-libvirt go-vuln public-py fe-install fe-check fe-build fe-audit public-fe-unit fe-negative secrets ci-policy claims boundary licenses

.PHONY: docker-demo-video public-fe-unit public-check public-py docker-public-check claims boundary licenses docker-qualify-libvirt-ro docker-qualify-libvirt-create docker-qualify-libvirt-lifecycle docker-qualify-libvirt-console docker-qualify-libvirt-storage docker-qualify-libvirt-network docker-qualify-libvirt-cleanup docker-release qualify-preflight check $(GATES) capability decisions fe-browser docker-fe-browser evidence-report evidence-replay require-nonroot docker-image docker-check docker-shell test-integration \
        test-container verify-backlog verify-linkage docker-linkage

check: $(GATES)
	@echo "make check: all gates passed"

public-check: $(PUBLIC_GATES)
	@echo "make public-check: all gates passed"

# Python gate tests that need only this repository (the governance tests read the separate requirements repository and run in `make check`).
public-py:
	python3 tools/check_syntax.py tools tests
	PYTHONDONTWRITEBYTECODE=1 python3 -m unittest $$(ls tests/unit_*.py | grep -v -E 'unit_check_(decisions|evidence|linkage|openapi|threats)|unit_ux_catalogue|unit_support_matrix' | sed 's/\.py$$//; s#/#.#')

versions:
	python3 tools/check_versions.py

go-fmt:
	@unformatted="$$(cd backend && gofmt -l .)"; \
	if [ -n "$$unformatted" ]; then echo "gofmt: unformatted files:"; echo "$$unformatted"; exit 1; fi

# LIBVIRT_TAGS builds the libvirt-linked host agent and the read-only adapter (cgo, libvirt-dev in the image) and their
# test-driver tests; the unprivileged API binary is built without them and never links libvirt.
LIBVIRT_TAGS := libvirt libvirt_test
# The shipped mutation helper (-tags libvirt) has no fault hook; the test build of it (-tags libvirt faultinject) is checked too.
HELPER_TAGS := libvirt faultinject

go-vet:
	cd backend && go vet ./...
	cd backend && go vet -tags "$(LIBVIRT_TAGS)" ./...
	cd backend && go vet -tags "$(HELPER_TAGS)" ./cmd/mutation-helper/

go-staticcheck:
	cd backend && staticcheck ./...
	cd backend && staticcheck -tags "$(LIBVIRT_TAGS)" ./...
	cd backend && staticcheck -tags "$(HELPER_TAGS)" ./cmd/mutation-helper/

go-gosec:
	cd backend && gosec -quiet ./...
	cd backend && gosec -quiet -tags "$(LIBVIRT_TAGS)" ./...
	cd backend && gosec -quiet -tags "$(HELPER_TAGS)" ./cmd/mutation-helper/

# GO_TEST_FLAGS and GO_ENV must equal tools/check_threats.py (the threats gate lists
# tests with the same flags; review cycle 5 C5-1, pinned by a unit test).
GO_TEST_FLAGS := -race -count=1
GO_ENV := GOFLAGS=-mod=readonly GOTOOLCHAIN=local GOWORK=off

go-test:
	cd backend && $(GO_ENV) go test $(GO_TEST_FLAGS) ./...

# M0-E02-S03 (T1, simulated): Hypervisor contract suite against libvirt's
# in-process test:///default driver via the cgo adapter. Never a real host.
go-test-libvirt:
	cd backend && go test -tags libvirt_test -race -count=1 -v ./internal/hypervisor/libvirttest/
	cd backend && go test -tags "$(LIBVIRT_TAGS)" -race -count=1 -v ./internal/hypervisor/libvirtro/ ./internal/agent/
	cd backend && go test -tags "$(LIBVIRT_TAGS)" -race -count=1 -v ./internal/hypervisor/libvirtmut/
	cd backend && go test -tags "$(LIBVIRT_TAGS)" -race -count=1 -v ./internal/console/libvirtcon/
	cd backend && go build -tags libvirt -o /dev/null ./cmd/mutation-helper/ && go build -tags "$(HELPER_TAGS)" -o /dev/null ./cmd/mutation-helper/
	cd backend && go build -tags libvirt -o /dev/null ./cmd/console-broker/

go-vuln:
	cd backend && govulncheck ./...

py-check:
	python3 tools/check_syntax.py tools tests
	PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -p 'unit_*.py'

fe-install:
	@test -f frontend/package-lock.json || { echo "ERROR frontend/package-lock.json missing; npm ci requires the committed lockfile"; exit 1; }
	cd frontend && npm ci --ignore-scripts --no-audit

fe-check: fe-install
	cd frontend && npm run check

fe-build: fe-install
	cd frontend && npm run build

fe-audit: fe-install
	cd frontend && npm audit --audit-level=moderate

# M0-E02-S06 (DR-010): AC01 positive unit/contract tests (jsdom, axe) plus the journey-catalogue contract test at
# the pinned docs commit; AC02 negative tests, frontend source rules and production-bundle rules.
fe-unit: fe-install
	cd frontend && npx vitest run --exclude 'src/**/*.negative.test.*'
	@case "$$DOCS_REPO" in ''|-*|*[!A-Za-z0-9._/-]*) echo "ERROR invalid DOCS_REPO"; exit 1;; esac; \
	PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests/unit_ux_catalogue.py

# The frontend unit tests without the journey-catalogue contract test, which reads the requirements repository.
public-fe-unit: fe-install
	cd frontend && npx vitest run --exclude 'src/**/*.negative.test.*'

fe-negative: fe-install
	cd frontend && npx vitest run negative
	cd frontend && npx vite build
	python3 tools/check_frontend.py --source frontend/src --bundle frontend/dist
	PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests/unit_check_frontend.py

# AC03 browser tier: ONLY inside the no-network dev-offline service (not in `make check`).
fe-browser:
	sh toolchain/fe-browser.sh

# gitleaks exits 0 when git itself fails, so require usable history first
# (review cycle 2, N3).
secrets:
	@git rev-parse --git-dir >/dev/null 2>&1 || { echo "ERROR secrets: git history unavailable (not a usable git repository)"; exit 1; }
	@count="$$(git rev-list --count HEAD)"; [ "$$count" -gt 0 ] || { echo "ERROR secrets: no commits to scan"; exit 1; }
	gitleaks git --no-banner --redact --config .gitleaks.toml .
	gitleaks dir --no-banner --redact --config .gitleaks-dir.toml .

ci-policy:
	python3 tools/check_ci_policy.py --pins docs/CI-PINS.md .github/workflows

# M0-S09: the release classification is Development Preview / Pre-Alpha; no gate-free overclaim.
claims:
	python3 tools/check_claims.py .

# M0-S08: every tracked file is classified public or internal; nothing private is tracked; no private-key block in the tree.
boundary:
	python3 tools/check_boundary.py .
	python3 tools/check_open_core.py .

# M0-S05: SBOM (CycloneDX), licence inventory and third-party notices are current and every licence is approved. Needs `go` and the module cache.
licenses:
	python3 tools/gen_sbom.py

# M0-E01-S01 (DRAFT): interface contracts and request fixtures.
interfaces:
	python3 tools/check_interfaces.py

# M0-E01-S04 (DR-012): contracts/openapi.yaml is the checked source of the browser-api shapes. The checker (read-only)
# pins it against the S01/S02 contracts and the compatibility baseline; the generator drift check compares the committed
# TypeScript types and Go route table; the Go tests prove /healthz conforms and rejections are typed. The negative
# mutation tests are tests/unit_check_openapi.py (py-check); fixture conformance is frontend/src/api/conformance.test.ts.
openapi:
	@case "$$DOCS_REPO" in ''|-*|*[!A-Za-z0-9._/-]*) echo "ERROR invalid DOCS_REPO"; exit 1;; esac; \
	python3 tools/check_openapi.py --docs-repo "$$DOCS_REPO"
	python3 tools/gen_api_types.py
	cd backend && $(GO_ENV) go test $(GO_TEST_FLAGS) ./internal/api/... ./cmd/api/...

# M0-E01-S02: threat register, mitigations and data classes (reads the
# backlog at the pinned docs commit via DOCS_REPO, and the Go test inventory
# from the pinned go toolchain; fails closed without either).
threats:
	@case "$$DOCS_REPO" in ''|-*|*[!A-Za-z0-9._/-]*) echo "ERROR invalid DOCS_REPO"; exit 1;; esac; \
	python3 tools/check_threats.py --docs-repo "$$DOCS_REPO"

# M0-E02-S04: test-evidence records, classification and taxonomy (docs repo, pinned
# commit). Read-only. STALE records are reported, not failed. Records are made
# on the host with tools/record_evidence.py and replayed with evidence-replay.
evidence:
	@case "$$DOCS_REPO" in ''|-*|*[!A-Za-z0-9._/-]*) echo "ERROR invalid DOCS_REPO"; exit 1;; esac; \
	python3 tools/check_evidence.py --docs-repo "$$DOCS_REPO"

# AC03 recorder fault injection and replay (fake runner; real processes, signals, git).
evidence-faults:
	PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests/integration_evidence.py

# M0-E02-S05 (DR-007): read-only distribution capability checker. Go tests on fixture roots,
# the docs-repo support matrix at the pinned commit, and the CLI/fault integration test (AC03).
capability:
	@case "$$DOCS_REPO" in ''|-*|*[!A-Za-z0-9._/-]*) echo "ERROR invalid DOCS_REPO"; exit 1;; esac; \
	python3 tools/support_matrix.py --docs-repo "$$DOCS_REPO" --check tests/fixtures/distribution/support-matrix.json
	cd backend && $(GO_ENV) go test $(GO_TEST_FLAGS) ./internal/capability/... ./cmd/capability-check/...
	PYTHONDONTWRITEBYTECODE=1 python3 tests/integration_capability.py

# M0-E01-S03 (DR-008): declared decision dependencies (contracts/decision-deps.json) must be
# approved with the required options in the docs register at the pinned commit AND the
# trusted docs tip; undeclared ADR/DR references outside tests/ fail. Read-only.
decisions:
	@case "$$DOCS_REPO" in ''|-*|*[!A-Za-z0-9._/-]*) echo "ERROR invalid DOCS_REPO"; exit 1;; esac; \
	PYTHONDONTWRITEBYTECODE=1 python3 tools/check_decisions.py --docs-repo "$$DOCS_REPO"

evidence-report:
	@case "$$DOCS_REPO" in ''|-*|*[!A-Za-z0-9._/-]*) echo "ERROR invalid DOCS_REPO"; exit 1;; esac; \
	python3 tools/check_evidence.py --docs-repo "$$DOCS_REPO" --report

installer-safety:
	sh packages/installer/inspect-only.sh

# --- Host-side targets (require Docker; never privileged) ---
# The dev container inherits the invoking UID; refuse root (S02 review F8).
require-nonroot:
	@if [ "$$(id -u)" = "0" ]; then echo "ERROR refusing to run the dev container as root; use an unprivileged user"; exit 1; fi

docker-image: require-nonroot
	$(COMPOSE) build dev

# The checkout is mounted read-only; gates run on a container-local copy.
docker-check: docker-image
	$(COMPOSE) run --rm dev toolchain/run-in-copy.sh make check

# The compose file mounts the requirements repository read-only; a public checkout has none, so an empty directory stands in (no gate in public-check reads it).
docker-public-check: docker-image
	@d="$$(mktemp -d)"; trap 'rmdir "$$d"' EXIT; DOCS_REPO_HOST="$$d" $(COMPOSE) run --rm dev toolchain/run-in-copy.sh make public-check

# The product tour video: a silent, captioned screen recording of the real web console over the simulated host (frontend/demo/tour.demo.ts), written to demo-out/svavyom-tour.webm.
docker-demo-video: docker-image
	@mkdir -p demo-out
	@d="$${DOCS_REPO_HOST:-}"; if [ -z "$$d" ] && [ ! -d ../cloud-product-docs ]; then d="$$(mktemp -d)"; trap 'rmdir "$$d"' EXIT; fi; \
	if [ -n "$$d" ]; then export DOCS_REPO_HOST="$$d"; fi; \
	$(COMPOSE) run --rm -v "$(CURDIR)/demo-out:/out" dev-offline toolchain/run-in-copy.sh sh toolchain/record-demo.sh

docker-fe-browser: docker-image
	@d="$${DOCS_REPO_HOST:-}"; if [ -z "$$d" ] && [ ! -d ../cloud-product-docs ]; then d="$$(mktemp -d)"; trap 'rmdir "$$d"' EXIT; fi; \
	if [ -n "$$d" ]; then DOCS_REPO_HOST="$$d" $(COMPOSE) run --rm dev-offline toolchain/run-in-copy.sh make fe-browser; else $(COMPOSE) run --rm dev-offline toolchain/run-in-copy.sh make fe-browser; fi

# Higher-tier, READ-ONLY qualification against a real local qemu:///system (CT-PRODUCT-DELIVERY-004 s16). Only for an authorised
# disposable host. The container gets no capabilities, no network, a read-only root and exactly one mounted file: libvirt's read-only
# socket. NOT_RUN (exit 0) when that socket does not exist. Not part of `make check`. See docs/QUALIFICATION-LIBVIRT-READONLY.md.
LIBVIRT_RO_SOCK := /var/run/libvirt/libvirt-sock-ro
docker-qualify-libvirt-ro: docker-image require-nonroot
	@if [ ! -S "$(LIBVIRT_RO_SOCK)" ]; then echo "NOT_RUN: $(LIBVIRT_RO_SOCK) not found (no libvirt daemon on this host); higher-tier qualification pending"; exit 0; fi; \
	docker run --rm -u "$$(id -u):$$(id -g)" --cap-drop ALL --security-opt no-new-privileges:true --read-only --network none \
	  --tmpfs /tmp:exec,mode=1777,size=2g -v "$(CURDIR)":/workspace/cloud-platform:ro -v "$(LIBVIRT_RO_SOCK)":"$(LIBVIRT_RO_SOCK)" \
	  -e SVAVYOM_QUALIFY_SYSTEM_LIBVIRT=1 -e GOMODCACHE=/opt/go-mod-cache -e GOPROXY=off -e HOME=/tmp -e GOCACHE=/tmp/go-cache \
	  -w /workspace/cloud-platform/backend dedicatedcloud-dev:local \
	  go test -tags "$(LIBVIRT_TAGS)" -count=1 -v -run TestSystemHypervisorQualification ./internal/hypervisor/libvirtro/

# Higher-tier, MUTATING qualification of VM creation against a real qemu:///system (CT-PRODUCT-DELIVERY-007). Authorised
# disposable Ubuntu hosts only. tools/qualify_create.py runs the read-only host preflight, then the Go qualification in a locked-down
# container (no capabilities, no network, read-only root; mounts only the libvirt RW socket, the read-only config and catalog, the
# PUBLIC key and one output directory), then the guest checks on the host with the operator's disposable private key (QUALIFY_SSH_KEY,
# a path; never mounted, read or recorded). Every criterion is reported PASS / FAIL / NOT_RUN; missing prerequisites are NOT_RUN
# (exit 0). Not part of `make check`. See docs/QUALIFICATION-LIBVIRT-CREATE.md.
QUALIFY_CONFIG ?=
QUALIFY_PUBKEY ?=
QUALIFY_IMAGE ?=
QUALIFY_SSH_KEY ?=
QUALIFY_RUN_ID ?=
QUALIFY_OUT ?= qualification-out
export QUALIFY_CONFIG QUALIFY_PUBKEY QUALIFY_IMAGE QUALIFY_SSH_KEY QUALIFY_RUN_ID QUALIFY_OUT
docker-qualify-libvirt-create: docker-image require-nonroot
	python3 tools/qualify_create.py --stage create

# Removes ONE qualification run's VM and its two volumes, and only after proving they are that run's (marker, derived uuid and
# fingerprint, managed-store backing image). Refuses and reports "manual cleanup required" otherwise. Never deletes by name alone.
# Higher-tier, MUTATING qualification of the M1-E VM lifecycle (reboot, stop, start, force off, ownership-proving delete) against a real
# qemu:///system, continuing a run whose create stage left the VM Running. See docs/QUALIFICATION-LIFECYCLE.md. Not part of `make check`.
docker-qualify-libvirt-lifecycle: docker-image require-nonroot
	python3 tools/qualify_lifecycle.py

# Higher-tier qualification of the M1-D serial console (boot output, interactive session, ticket negatives) against a real qemu:///system, in
# a container with no network. Continues a run whose create stage left the VM Running. See docs/QUALIFICATION-CONSOLE.md.
docker-qualify-libvirt-console: docker-image require-nonroot
	python3 tools/qualify_console.py

# Higher-tier qualification of M2 storage and recovery (grow, snapshot, backup, restore, reinstall) against a real qemu:///system, continuing a run
# whose create stage left the VM Running. See docs/QUALIFICATION-STORAGE.md. Not part of `make check`.
docker-qualify-libvirt-storage: docker-image require-nonroot
	python3 tools/qualify_storage.py

# Higher-tier network qualification (M3): a managed NAT network, a VM attached to it, DHCP, a compute change and a static reservation, all derived from
# the run id. See docs/QUALIFICATION-NETWORKS.md. Not part of `make check`.
docker-qualify-libvirt-network: docker-image require-nonroot
	python3 tools/qualify_network.py

# Assembles the Development Preview release artifact under release-out/ (M4-S11): binaries built on an Ubuntu 24.04 builder, the web bundle, packages, docs, SBOM,
# MANIFEST.json and SHA256SUMS. It publishes and signs nothing. See docs/OPERATIONS.md.
RELEASE_OUT ?= release-out
docker-release: docker-image require-nonroot
	python3 tools/make_release.py --out "$(RELEASE_OUT)"

docker-qualify-libvirt-cleanup: docker-image require-nonroot
	@case "$(QUALIFY_RUN_ID)" in qr-[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]-[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]) ;; *) echo "ERROR set QUALIFY_RUN_ID=qr-YYYYMMDD-xxxxxx (printed by the create run)"; exit 2;; esac
	python3 tools/qualify_create.py --stage cleanup

# Read-only host preflight for the qualification operator (changes nothing). Optional: QUALIFY_CONFIG=/etc/svavyom/provision.json
qualify-preflight:
	python3 tools/qualify_preflight.py $(if $(QUALIFY_CONFIG),--config "$(QUALIFY_CONFIG)",)

docker-shell: docker-image
	$(COMPOSE) run --rm dev bash

# AC02 gate-defect tests (inside the container) and AC04 container safety (host).
test-integration: docker-image
	$(COMPOSE) run --rm dev python3 tests/integration_gates.py

test-container: docker-image
	PYTHONDONTWRITEBYTECODE=1 python3 tests/integration_container.py

# --- Evidence replay (M0-E02-S04 AC03, DR-006 D3); host-side, needs Docker ---
EVIDENCE_WORKDIR ?= ../evidence-replay-work
evidence-replay: require-nonroot docker-image
	@case "$$DOCS_REPO" in ''|-*|*[!A-Za-z0-9._/-]*) echo "ERROR invalid DOCS_REPO"; exit 1;; esac; \
	case "$(EVIDENCE_WORKDIR)" in ''|-*|*[!A-Za-z0-9._/-]*) echo "ERROR invalid EVIDENCE_WORKDIR"; exit 1;; esac; \
	python3 tools/replay_evidence.py --docs-repo "$$DOCS_REPO" --workdir "$(EVIDENCE_WORKDIR)"

# --- Docs linkage (M0-E02-S01); needs the docs repo ---
# docker-linkage runs backlog validation and linkage inside the container with
# the docs repo mounted read-only. LINKAGE_MODE=lock checks only the lock;
# REQUIRE_COMMITS=1 fails on an empty range (review finding F14).
docker-linkage: docker-image
	$(COMPOSE) run --rm -e LINKAGE_BASE -e LINKAGE_MODE -e REQUIRE_COMMITS dev \
	  make verify-backlog verify-linkage DOCS_REPO=/workspace/cloud-product-docs

verify-backlog:
	@case "$$DOCS_REPO" in ''|-*|*[!A-Za-z0-9._/-]*) echo "ERROR invalid DOCS_REPO"; exit 1;; esac; \
	python3 "$$DOCS_REPO/tools/validate_backlog.py"

verify-linkage:
	@case "$$DOCS_REPO" in ''|-*|*[!A-Za-z0-9._/-]*) echo "ERROR invalid DOCS_REPO"; exit 1;; esac; \
	python3 tools/check_linkage.py lock --docs-repo "$$DOCS_REPO"
	@case "$$LINKAGE_MODE" in full|lock) ;; *) echo "ERROR LINKAGE_MODE must be full or lock"; exit 1;; esac; \
	case "$$REQUIRE_COMMITS" in 0|1) ;; *) echo "ERROR REQUIRE_COMMITS must be 0 or 1"; exit 1;; esac; \
	if [ "$$LINKAGE_MODE" = "full" ]; then \
	  case "$$LINKAGE_BASE" in ''|-*|*[!A-Za-z0-9._/~^-]*|*..*) echo "ERROR invalid LINKAGE_BASE"; exit 1;; esac; \
	  if [ "$$REQUIRE_COMMITS" = "1" ] && [ -z "$$(git rev-list --end-of-options "$$LINKAGE_BASE..HEAD" --)" ]; then \
	    echo "ERROR empty linkage range"; exit 1; fi; \
	  python3 tools/check_linkage.py commits --docs-repo "$$DOCS_REPO" --range="$$LINKAGE_BASE..HEAD"; fi
