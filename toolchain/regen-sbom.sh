#!/bin/sh
# Host-side helper: regenerates the SBOM, the licence inventory and THIRD-PARTY-NOTICES.md in the pinned container and copies them back.
# Run it after changing VERSION, a dependency or the licence policy (docs/BUILD.md, "Changing the version"). The checkout is mounted read-only in the
# container, so the generator writes into a scratch directory and this script copies the four files into the tree. Never run as root.
set -eu
[ "$(id -u)" -ne 0 ] || { echo "do not run as root"; exit 1; }
root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"
scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT INT TERM
cat > "$scratch/inner.sh" <<'EOF'
set -eu
cd frontend && npm ci --ignore-scripts --no-audit --no-fund >/dev/null 2>&1; cd ..
python3 tools/gen_sbom.py --write
mkdir -p /out
cp docs/sbom/sbom.cdx.json docs/sbom/licenses.json docs/sbom/go-modules.txt THIRD-PARTY-NOTICES.md /out/
EOF
mkdir -p "$scratch/out"
HOST_UID=$(id -u) HOST_GID=$(id -g) docker compose --env-file toolchain/versions.env run --rm \
  -v "$scratch/inner.sh:/s/inner.sh:ro" -v "$scratch/out:/out" dev toolchain/run-in-copy.sh sh /s/inner.sh
cp "$scratch/out/sbom.cdx.json" "$scratch/out/licenses.json" "$scratch/out/go-modules.txt" docs/sbom/
cp "$scratch/out/THIRD-PARTY-NOTICES.md" THIRD-PARTY-NOTICES.md
echo "regenerated: docs/sbom/{sbom.cdx.json,licenses.json,go-modules.txt} and THIRD-PARTY-NOTICES.md"
