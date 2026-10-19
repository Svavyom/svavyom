# Release builder (M4-S11). The libvirt-linked binaries (agent, mutation-helper, console-broker) link libvirt dynamically, so they must be built on the
# SUPPORTED TARGET (Ubuntu 24.04 LTS), not on the Debian development image, or they would need a newer libc than the host has. The Go toolchain and the
# module cache are the development image's (same pinned toolchain, no network); only the C toolchain and libvirt-dev come from Ubuntu.
ARG UBUNTU_IMAGE=ubuntu:24.04@sha256:534baea6a22c03a63003dbc8dbe78fe34bc0d7e595d9a9dc9834884ff530eb55
FROM dedicatedcloud-dev:local AS dev
FROM ${UBUNTU_IMAGE}
RUN apt-get update \
 && apt-get install -y --no-install-recommends gcc libc6-dev libvirt-dev pkg-config ca-certificates binutils \
 && rm -rf /var/lib/apt/lists/* \
 && dpkg-query -W -f '${Package}=${Version}\n' | LC_ALL=C sort > /usr/local/share/apt-versions.txt
COPY --from=dev /usr/local/go /usr/local/go
COPY --from=dev /opt/go-mod-cache /opt/go-mod-cache
ENV PATH=/usr/local/go/bin:/usr/local/bin:/usr/bin:/bin GOTOOLCHAIN=local GOFLAGS=-mod=readonly GOTELEMETRY=off GOPROXY=off \
    GOMODCACHE=/opt/go-mod-cache HOME=/tmp GOCACHE=/tmp/go-cache
USER 65534:65534
WORKDIR /workspace/cloud-platform
