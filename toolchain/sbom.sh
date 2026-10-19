#!/bin/sh
# Regenerates docs/sbom/go-modules.txt (run inside the pinned dev image, cwd = backend/).
set -eu
go list -deps -f '{{with .Module}}{{if not .Main}}{{.Path}} {{.Version}}{{end}}{{end}}' ./... | sort -u > ../docs/sbom/go-modules.txt
