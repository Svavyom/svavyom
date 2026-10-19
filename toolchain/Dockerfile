# Development and CI toolchain image (story M0-E02-S02).
# Base images are passed in digest-pinned from toolchain/versions.env.
ARG GO_IMAGE
ARG NODE_IMAGE
ARG PYTHON_IMAGE

FROM ${GO_IMAGE} AS gotools
ENV GOTOOLCHAIN=local GOFLAGS=-mod=readonly CGO_ENABLED=0 GOTELEMETRY=off
WORKDIR /src
COPY toolchain/gotools/go.mod toolchain/gotools/go.sum ./
RUN go mod download && go mod verify
RUN go build -trimpath -o /out/ \
      honnef.co/go/tools/cmd/staticcheck \
      github.com/securego/gosec/v2/cmd/gosec \
      golang.org/x/vuln/cmd/govulncheck \
      github.com/zricethezav/gitleaks/v8

# Browser product tier (CT-PRODUCT-DELIVERY-003 s3): the no-network `dev-offline` service builds and runs the real API
# process against the production bundle. Its Go modules come from this image-build-time cache (the only networked
# step), like the npm cache below; the tier itself never downloads anything. go.sum verifies every module.
FROM ${GO_IMAGE} AS gomodcache
ENV GOTOOLCHAIN=local GOFLAGS=-mod=readonly GOTELEMETRY=off GOMODCACHE=/opt/go-mod-cache
WORKDIR /src
COPY backend/go.mod backend/go.sum ./
RUN go mod download && go mod verify && chmod -R a+rX /opt/go-mod-cache

FROM ${NODE_IMAGE} AS node

# M0-E02-S06 (DR-010 D4 = A): the npm cache for frontend/package-lock.json and the Playwright-matched Chromium
# headless shell are populated here, at image build (the only networked step), OUTSIDE /tmp (a per-run tmpfs).
# `make fe-browser` computes the runtime browser tree's manifest digest and compares it with
# toolchain/playwright-browser.lock (trust on first use; re-reviewed on every version change).
FROM ${NODE_IMAGE} AS fecache
ENV npm_config_update_notifier=false PLAYWRIGHT_BROWSERS_PATH=/opt/ms-playwright
WORKDIR /build
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --ignore-scripts --no-audit --cache /opt/npm-cache \
 && node node_modules/playwright-core/cli.js install --only-shell chromium

FROM ${PYTHON_IMAGE}
# git: linkage/secret scanning; make: gate runner; gcc/libc6-dev: go test -race;
# libvirt-dev/pkg-config: cgo libvirt test-driver adapter (M0-E02-S03, LGPL-2.1+ dynamic).
RUN apt-get update \
 && apt-get install -y --no-install-recommends git make gcc libc6-dev libstdc++6 ca-certificates \
      libvirt-dev pkg-config \
 && rm -rf /var/lib/apt/lists/*
# CI policy checker dependency, hash-locked (M0-E02-S02 review N18 remediation).
COPY toolchain/requirements-ci-policy.txt /tmp/requirements-ci-policy.txt
RUN python3 -m pip install --no-cache-dir --disable-pip-version-check --require-hashes \
      --only-binary=:all: --no-deps -r /tmp/requirements-ci-policy.txt \
 && rm /tmp/requirements-ci-policy.txt
COPY --from=gotools /usr/local/go /usr/local/go
COPY --from=gotools /out/ /usr/local/bin/
COPY --from=fecache /opt/npm-cache /opt/npm-cache
COPY --from=gomodcache /opt/go-mod-cache /opt/go-mod-cache
COPY --from=fecache /opt/ms-playwright /opt/ms-playwright
COPY --from=fecache /build/node_modules/playwright-core /tmp/pwcore
COPY --from=node /usr/local/bin/node /usr/local/bin/node
COPY --from=node /usr/local/lib/node_modules/npm /usr/local/lib/node_modules/npm
RUN ln -s ../lib/node_modules/npm/bin/npm-cli.js /usr/local/bin/npm \
 && ln -s ../lib/node_modules/npm/bin/npx-cli.js /usr/local/bin/npx \
 && node /tmp/pwcore/cli.js install-deps chromium-headless-shell \
 && rm -rf /tmp/pwcore /var/lib/apt/lists/* \
 && chmod -R a+rX,go-w /opt/npm-cache /opt/ms-playwright \
 && dpkg-query -W -f '${Package}=${Version}\n' | LC_ALL=C sort > /usr/local/share/apt-versions.txt
ENV PATH=/usr/local/go/bin:/usr/local/bin:/usr/bin:/bin \
    GOTOOLCHAIN=local GOFLAGS=-mod=readonly GOTELEMETRY=off \
    HOME=/tmp GOCACHE=/tmp/go-cache GOPATH=/tmp/go GOMODCACHE=/tmp/go/pkg/mod \
    npm_config_cache=/tmp/npm-cache npm_config_update_notifier=false \
    PYTHONDONTWRITEBYTECODE=1 CGO_ENABLED=1 PLAYWRIGHT_BROWSERS_PATH=/opt/ms-playwright
USER 65534:65534
WORKDIR /workspace/cloud-platform
