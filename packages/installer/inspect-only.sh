#!/bin/sh
set -eu
printf '%s\n' 'Dedicated Cloud installer placeholder: SAFE INSPECTION ONLY.'
printf '%s\n' 'No packages, networking, disks or system services will be changed.'
uname -srm
if [ -r /etc/os-release ]; then . /etc/os-release; printf 'OS: %s\n' "${PRETTY_NAME:-unknown}"; fi
printf '%s\n' 'The supported installer is svavyom-ctl (INSTALLING.md): preflight, plan-then---apply, upgrade, rollback.'
