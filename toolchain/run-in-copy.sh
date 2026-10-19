#!/bin/sh
# Run a command on a container-local copy of the read-only checkout (story
# M0-E02-S02, review cycle 2 N4). Gates may write node_modules, dist and
# caches; none of that can reach files the host later executes.
# The archive goes through a file, not a pipe, so a failing source tar is not
# masked (cycle 3 N12); the copy starts empty each time (N13).
set -eu
src=/workspace/cloud-platform
dst=/tmp/workspace-copy/cloud-platform
archive=/tmp/workspace-copy.tar
rm -rf -- /tmp/workspace-copy
mkdir -p "$dst"
tar -C "$src" --exclude=./frontend/node_modules --exclude=./frontend/dist -cf "$archive" .
tar -C "$dst" -xf "$archive"
rm -f -- "$archive"
cd "$dst"
exec "$@"
