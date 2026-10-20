#!/bin/sh
# Records the silent, captioned product tour (frontend/demo/tour.demo.ts) over the simulated host. Runs inside the no-network dev-offline image on a
# container-local copy (toolchain/run-in-copy.sh), like the browser tier. Output: $DEMO_OUT (default /out), the recording as WebM.
set -eu
out=${DEMO_OUT:-/out}
rm -rf /tmp/npm-cache && cp -a /opt/npm-cache /tmp/npm-cache
cd frontend
npm ci --offline --ignore-scripts --no-audit --cache /tmp/npm-cache
npx vite build
(cd ../backend && GOMODCACHE=/opt/go-mod-cache GOPROXY=off CGO_ENABLED=0 go build -trimpath -o /tmp/svavyom-api ./cmd/api)
(cd ../backend && GOMODCACHE=/opt/go-mod-cache GOPROXY=off CGO_ENABLED=0 go build -trimpath -o /tmp/svavyom-agent-fixture ./cmd/agent-fixture)
(cd ../backend && GOMODCACHE=/opt/go-mod-cache GOPROXY=off CGO_ENABLED=0 go build -trimpath -o /tmp/svavyom-mutation-supervisor ./cmd/mutation-supervisor)
(cd ../backend && GOMODCACHE=/opt/go-mod-cache GOPROXY=off CGO_ENABLED=0 go build -trimpath -o /tmp/svavyom-helper-sim ./cmd/mutation-helper-sim)
(cd ../backend && GOMODCACHE=/opt/go-mod-cache GOPROXY=off CGO_ENABLED=0 go build -trimpath -o /tmp/svavyom-console-sim ./cmd/console-broker-sim)
export SVAVYOM_API_BIN=/tmp/svavyom-api SVAVYOM_FIXTURE_BIN=/tmp/svavyom-agent-fixture
export SVAVYOM_SUPERVISOR_BIN=/tmp/svavyom-mutation-supervisor SVAVYOM_HELPER_SIM_BIN=/tmp/svavyom-helper-sim SVAVYOM_CONSOLE_SIM_BIN=/tmp/svavyom-console-sim
if node e2e/sandbox-probe.mjs; then FE_NO_SANDBOX=0; else FE_NO_SANDBOX=1; fi
export FE_NO_SANDBOX DEMO_OUT=/tmp/demo-results
status=0
npx playwright test -c playwright.demo.config.ts || status=$?
mkdir -p "$out/results" && cp -a /tmp/demo-results/. "$out/results/" 2>/dev/null || true
[ "$status" = 0 ] || exit "$status"
f=$(find /tmp/demo-results -name '*.webm' | head -1)
[ -n "$f" ] || { echo "ERROR no recording was produced"; exit 1; }
cp "$f" "$out/svavyom-tour.webm"
echo "OK recording: $out/svavyom-tour.webm"
