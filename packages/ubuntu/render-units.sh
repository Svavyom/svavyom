#!/bin/sh
# Renders the unit and configuration templates into a NEW directory. Read-only with respect to the system: it only calls `id` and
# writes under OUT. It installs nothing and starts nothing. Usage:  render-units.sh OUT_DIR
# For tests the identities can be supplied instead of looked up:  SVAVYOM_TEST_IDS="api_uid api_gid ro_uid ro_gid mut_uid mut_gid libvirt_gid con_uid con_gid"
set -eu
out=${1:?usage: render-units.sh OUT_DIR}
here=$(cd "$(dirname "$0")" && pwd)
[ ! -e "$out" ] || { echo "ERROR $out already exists; refusing to overwrite" >&2; exit 2; }
if [ -n "${SVAVYOM_TEST_IDS:-}" ]; then
  # shellcheck disable=SC2086
  set -- $SVAVYOM_TEST_IDS
  api_uid=$1 api_gid=$2 ro_uid=$3 ro_gid=$4 mut_uid=$5 mut_gid=$6 lv_gid=$7 con_uid=$8 con_gid=$9
else
  api_uid=$(id -u svavyom-api) api_gid=$(id -g svavyom-api)
  ro_uid=$(id -u svavyom-ro)   ro_gid=$(id -g svavyom-ro)
  mut_uid=$(id -u svavyom-mut) mut_gid=$(id -g svavyom-mut)
  lv_gid=$(getent group libvirt | cut -d: -f3)
  con_uid=$(id -u svavyom-con) con_gid=$(id -g svavyom-con)
fi
for v in "$api_uid" "$api_gid" "$ro_uid" "$ro_gid" "$mut_uid" "$mut_gid" "$lv_gid" "$con_uid" "$con_gid"; do
  case "$v" in ''|*[!0-9]*) echo "ERROR a service identity is missing (create the users first; see UBUNTU-DEPLOYMENT.md)" >&2; exit 2;; esac
  [ "$v" -ne 0 ] || { echo "ERROR a service identity resolves to uid/gid 0; refusing" >&2; exit 2; }
done
mkdir -p "$out/systemd/svavyom-api.service.d" "$out/etc"
sub() {
  sed -e "s/@SVAVYOM_API_UID@/$api_uid/g" -e "s/@SVAVYOM_API_GID@/$api_gid/g" -e "s/@SVAVYOM_RO_UID@/$ro_uid/g" -e "s/@SVAVYOM_RO_GID@/$ro_gid/g" \
      -e "s/@SVAVYOM_MUT_UID@/$mut_uid/g" -e "s/@SVAVYOM_MUT_GID@/$mut_gid/g" -e "s/@LIBVIRT_GID@/$lv_gid/g" -e "s/@SVAVYOM_CON_UID@/$con_uid/g" -e "s/@SVAVYOM_CON_GID@/$con_gid/g" "$1"
}
for u in svavyom-api svavyom-agent svavyom-mutation svavyom-offsite svavyom-console; do sub "$here/systemd/$u.service.in" > "$out/systemd/$u.service"; done
cp "$here/systemd/svavyom-api.service.d/experimental-mutation.conf.example" "$out/systemd/svavyom-api.service.d/"
sub "$here/etc/provision.json.in" > "$out/etc/provision.json"
grep -q '@[A-Z_]*@' "$out"/systemd/*.service "$out/etc/provision.json" && { echo "ERROR unreplaced placeholder" >&2; exit 2; }
echo "rendered into $out (nothing installed)"
