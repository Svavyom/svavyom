#!/bin/sh
# Test-only: the CREATE journey stack on 127.0.0.1:4176 with the Development Preview switch OPEN, all real processes except the
# host itself, which is the file-backed simulation (package simhost): API (+ operation worker), mutation supervisor, the
# simulated mutation helper (one process per request) and the fixture read-only agent reading the same simulated host. A
# second instance with the switch CLOSED (the default) runs on :4177; a third (:4178, "storage") is the open one plus a real-host-qualified image and a
# backup store for the storage and recovery journeys. Simulation only: this is not libvirt or KVM evidence.
set -eu
: "${SVAVYOM_API_BIN:?built by toolchain/fe-browser.sh}"
: "${SVAVYOM_FIXTURE_BIN:?built by toolchain/fe-browser.sh}"
: "${SVAVYOM_SUPERVISOR_BIN:?built by toolchain/fe-browser.sh}"
: "${SVAVYOM_HELPER_SIM_BIN:?built by toolchain/fe-browser.sh}"
: "${SVAVYOM_CONSOLE_SIM_BIN:?built by toolchain/fe-browser.sh}"
mode=${1:?open|closed|storage}
case $mode in open) port=4176 ;; closed) port=4177 ;; storage) port=4178 ;; *) exit 2 ;; esac
dir=/tmp/svavyom-e2e-create-$mode
rm -rf "$dir" && mkdir -p "$dir/images" "$dir/state"
umask 077
chmod 700 "$dir" "$dir/state"; chmod 750 "$dir/images"
# Operator-side source files (outside the catalog): minimal valid qcow2 v3 headers (no backing file, no encryption) + a body.
qcow2() { printf 'QFI\373\000\000\000\003\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\020\000\000\000\000\004\000\000\000\000\000\000\000'; head -c 36 /dev/zero; printf '%s' "$1"; }
mkdir "$dir/src"
qcow2 e2e-image-body > "$dir/src/debian.qcow2"
qcow2 e2e-registered-only-body > "$dir/src/raw.qcow2"
printf '%s\n' "e2e-only-passphrase-not-a-real-credential" > "$dir/pw"
"$SVAVYOM_API_BIN" bootstrap-admin --db "$dir/svavyom.db" --username admin < "$dir/pw"
rm -f "$dir/pw"
"$SVAVYOM_API_BIN" register-image --insecure-dev-single-identity --catalog-dir "$dir/images" --id debian-13 --display-name "Debian 13" --distribution Debian \
  --version 13 --source "$dir/src/debian.qcow2" --login-user debian --min-disk-gib 3 --cloud-init
# A second image that is only registered (cloud-init support not confirmed): listed by the API, never selectable.
"$SVAVYOM_API_BIN" register-image --insecure-dev-single-identity --catalog-dir "$dir/images" --id raw-1 --display-name "Raw 1" --distribution Other \
  --version 1 --source "$dir/src/raw.qcow2" --login-user admin --min-disk-gib 3
backup=""
if [ "$mode" = storage ]; then
  mkdir -p "$dir/backups" && chmod 700 "$dir/backups"
  backup=",\"backup_dir\":\"$dir/backups\""
  qcow2 e2e-qualified-body > "$dir/src/qualified.qcow2"
  "$SVAVYOM_API_BIN" register-image --insecure-dev-single-identity --catalog-dir "$dir/images" --id ubuntu-q --display-name "Ubuntu Q" --distribution Ubuntu \
    --version 24.04 --source "$dir/src/qualified.qcow2" --login-user ubuntu --min-disk-gib 3 --cloud-init
  "$SVAVYOM_API_BIN" image-state --insecure-dev-single-identity --catalog-dir "$dir/images" --id ubuntu-q --state qualified --evidence qr-20261011-5e5e5e
fi
cat > "$dir/provision.json" <<EOF
{"catalog_dir":"$dir/images","pool":"svavyom","network":"svavyom-nat","domain_type":"test","libvirt_uri":"test:///default","state_dir":"$dir/state"$backup}
EOF
SVAVYOM_FIXTURE_AGENT=1 "$SVAVYOM_FIXTURE_BIN" --socket "$dir/ro.sock" --sim-dir "$dir/state/sim" &
agent=$!
# The supervisor gives the helper a fixed environment, so a wrapper sets the test-only simulation guard.
printf '#!/bin/sh\nSVAVYOM_SIM_HOST=1 exec "%s" "$@"\n' "$SVAVYOM_HELPER_SIM_BIN" > "$dir/helper-sim.sh"
chmod 700 "$dir/helper-sim.sh"
"$SVAVYOM_SUPERVISOR_BIN" --socket "$dir/mut.sock" --allow-uid "$(id -u)" --helper "$dir/helper-sim.sh" \
  --helper-config "$dir/provision.json" --deadline 4s --insecure-dev-single-identity &
sup=$!
# The real console broker over the SIMULATED hypervisor (scripted boot log and a toy login prompt), watching the same simulated host.
SVAVYOM_FIXTURE_CONSOLE=1 "$SVAVYOM_CONSOLE_SIM_BIN" --socket "$dir/console.sock" --allow-uid "$(id -u)" --sim-dir "$dir/state/sim" &
con=$!
trap 'kill $agent $sup $con 2>/dev/null || true' EXIT INT TERM
i=0
while [ ! -S "$dir/ro.sock" ] || [ ! -S "$dir/mut.sock" ] || [ ! -S "$dir/console.sock" ]; do i=$((i+1)); [ $i -lt 100 ] || { echo "agents did not start"; exit 1; }; sleep 0.1; done
extra=""
[ "$mode" != closed ] && extra="--experimental-mutation --insecure-dev-single-identity --experimental-console"
# shellcheck disable=SC2086
"$SVAVYOM_API_BIN" serve --db "$dir/svavyom.db" --listen 127.0.0.1:$port --static-dir dist --host-name e2e-host --agent-socket "$dir/ro.sock" \
  --provision-config "$dir/provision.json" --mutation-socket "$dir/mut.sock" --console-socket "$dir/console.sock" --usage-interval 1s $extra
