#!/usr/bin/env bash
# Renders every docs/diagrams/*.mmd source to an .svg file alongside it
# (same path, same name, .svg extension). Invoked by `make diagrams`.
set -euo pipefail

for src in docs/diagrams/*.mmd; do
	out="${src%.mmd}.svg"
	echo "==> $src -> $out"
	npx --yes --package=@mermaid-js/mermaid-cli mmdc -i "$src" -o "$out"
done
