#!/bin/sh
# M0-E02-S06 AC03 browser tier (DR-010 D4 = A; r5 section 10). Runs inside the no-network `dev-offline`
# service on the run-in-copy.sh copy. Steps 1-5 of the approved mechanism.
set -eu
lock=toolchain/playwright-browser.lock
# 1. The browser tree (paths, types, modes, symlink targets and file contents) must match the recorded manifest
#    digest and version; then a private npm cache copy.
want=$(python3 -c "import json;print(json.load(open('$lock'))['tree_manifest_sha256'])")
dirs=$(python3 -c "import json;print(' '.join(json.load(open('$lock'))['browsers']))")
got=$(cd /opt/ms-playwright && { find . \( -type f -o -type l \) -printf '%y %m %p -> %l\n' | LC_ALL=C sort; find . -type f -print0 | LC_ALL=C sort -z | xargs -0 sha256sum; } | sha256sum | cut -d' ' -f1)
have=$(ls /opt/ms-playwright | tr '\n' ' ' | sed 's/ $//')
[ "$got" = "$want" ] || { echo "ERROR BROWSER_DIGEST /opt/ms-playwright manifest $got != recorded $want"; exit 1; }
[ "$have" = "$dirs" ] || { echo "ERROR BROWSER_VERSION found [$have], recorded [$dirs]"; exit 1; }
echo "OK browser: $have (manifest $got)"
rm -rf /tmp/npm-cache && cp -a /opt/npm-cache /tmp/npm-cache
cd frontend
# 2. Offline install from the image's cache only.
npm ci --offline --ignore-scripts --no-audit --cache /tmp/npm-cache
# 3. Production bundle and the test-only gallery bundle.
npx vite build
npx vite build --mode gallery
# 3b. The real API process for the product journeys (e2e/product.spec.ts): built offline from the image's Go module cache.
(cd ../backend && GOMODCACHE=/opt/go-mod-cache GOPROXY=off CGO_ENABLED=0 go build -trimpath -o /tmp/svavyom-api ./cmd/api)
(cd ../backend && GOMODCACHE=/opt/go-mod-cache GOPROXY=off CGO_ENABLED=0 go build -trimpath -o /tmp/svavyom-agent-fixture ./cmd/agent-fixture)
(cd ../backend && GOMODCACHE=/opt/go-mod-cache GOPROXY=off CGO_ENABLED=0 go build -trimpath -o /tmp/svavyom-mutation-supervisor ./cmd/mutation-supervisor)
(cd ../backend && GOMODCACHE=/opt/go-mod-cache GOPROXY=off CGO_ENABLED=0 go build -trimpath -o /tmp/svavyom-helper-sim ./cmd/mutation-helper-sim)
(cd ../backend && GOMODCACHE=/opt/go-mod-cache GOPROXY=off CGO_ENABLED=0 go build -trimpath -o /tmp/svavyom-console-sim ./cmd/console-broker-sim)
export SVAVYOM_API_BIN=/tmp/svavyom-api SVAVYOM_FIXTURE_BIN=/tmp/svavyom-agent-fixture
export SVAVYOM_SUPERVISOR_BIN=/tmp/svavyom-mutation-supervisor SVAVYOM_HELPER_SIM_BIN=/tmp/svavyom-helper-sim SVAVYOM_CONSOLE_SIM_BIN=/tmp/svavyom-console-sim
# Chromium sandbox: used when it can start under the unchanged hardening; otherwise the accepted risk applies.
if node e2e/sandbox-probe.mjs; then FE_NO_SANDBOX=0; else FE_NO_SANDBOX=1; fi
export FE_NO_SANDBOX
# 4 and 5. vite preview on 127.0.0.1 (playwright.config.ts webServer) and the Playwright suite.
npx playwright test
