#!/bin/sh
# Builds the seven release binaries on the Ubuntu 24.04 builder into /out/bin. The checkout is mounted read-only; the build runs on a copy.
set -eu
src=/workspace/cloud-platform
dst=/tmp/build
rm -rf "$dst" && mkdir -p "$dst" /out/bin
tar -C "$src" --exclude=./frontend --exclude=./.git -cf - . | tar -C "$dst" -xf -
cd "$dst/backend"
v=$(cat ../VERSION)
build() { # name package cgo tags
  CGO_ENABLED=$3 go build -trimpath -buildvcs=false -tags "$4" -ldflags "-s -w" -o "/out/bin/$1" "./cmd/$2"
}
build api api 0 ""
build mutation-supervisor mutation-supervisor 0 ""
build offsite offsite 0 ""
build agent agent 1 libvirt
build mutation-helper mutation-helper 1 libvirt
build console-broker console-broker 1 libvirt
CGO_ENABLED=0 go build -trimpath -buildvcs=false -ldflags "-s -w -X main.Version=$v" -o /out/bin/svavyom-ctl ./cmd/svavyom-ctl
chmod 0755 /out/bin/*
{
  echo "# Dynamic linkage of the release binaries (built on $(. /etc/os-release && echo "$PRETTY_NAME"), $(go version))."
  echo "# A binary that lists no shared library is statically linked."
  for b in /out/bin/*; do
    echo "== $(basename "$b")"
    readelf -d "$b" 2>/dev/null | sed -n 's/.*(NEEDED).*\[\(.*\)\]/NEEDED \1/p' || true
  done
} > /out/BUILD-LINKAGE.txt
cp /usr/local/share/apt-versions.txt /out/BUILDER-PACKAGES.txt
