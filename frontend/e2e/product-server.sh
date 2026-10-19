#!/bin/sh
# Test-only: a real `api serve` on a fresh database with a TEST administrator, serving dist/ on 127.0.0.1:4175, plus the
# TEST-ONLY fixture agent (same read-only Unix-socket protocol as the real host agent, state in /tmp/svavyom-e2e/state.json
# which the browser tests rewrite). The credential below exists only here; production code has no default.
set -eu
: "${SVAVYOM_API_BIN:?built by toolchain/fe-browser.sh}"
: "${SVAVYOM_FIXTURE_BIN:?built by toolchain/fe-browser.sh}"
dir=/tmp/svavyom-e2e
rm -rf "$dir" && mkdir -p "$dir"
umask 077
printf '%s\n' '{"mode":"up","domains":[]}' > "$dir/state.json"
printf '%s\n' "e2e-only-passphrase-not-a-real-credential" > "$dir/pw"
"$SVAVYOM_API_BIN" bootstrap-admin --db "$dir/svavyom.db" --username admin < "$dir/pw"
rm -f "$dir/pw"
SVAVYOM_FIXTURE_AGENT=1 "$SVAVYOM_FIXTURE_BIN" --socket "$dir/agent.sock" --state "$dir/state.json" &
agent=$!
trap 'kill $agent 2>/dev/null || true' EXIT INT TERM
i=0
while [ ! -S "$dir/agent.sock" ]; do i=$((i+1)); [ $i -lt 100 ] || { echo "fixture agent did not start"; exit 1; }; sleep 0.1; done
"$SVAVYOM_API_BIN" serve --db "$dir/svavyom.db" --listen 127.0.0.1:4175 --static-dir dist --host-name e2e-host --agent-socket "$dir/agent.sock"
