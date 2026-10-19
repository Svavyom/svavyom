#!/bin/sh
# Builds the production web bundle offline from the image's npm cache into /out/web (run via toolchain/run-in-copy.sh on a copy of the checkout).
set -eu
rm -rf /tmp/npm-cache && cp -a /opt/npm-cache /tmp/npm-cache
cd frontend
npm ci --offline --ignore-scripts --no-audit --cache /tmp/npm-cache
npx vite build
mkdir -p /out/web
cp -R dist/. /out/web/
