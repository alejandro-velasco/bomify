# Builds and tagging

`bomify build` pulls every component, then records the SBOM as the
build's manifest (`build.RecordManifest`; building the same SBOM again
is a no-op) and points any `--tag`s at its hash
(`build.UpdateRepositories`). `bomify tag` points a new tag at what an
existing one resolves to. `repositories.json` follows Docker's layout,
and a tag without `:version` means `latest`. With `--provenance`, the
build's provenance is recorded too (see [Build provenance](provenance.md)).

## Pruning

`bomify package prune` (and `package remove`, which prunes after
untagging) mirrors `docker image prune`. Every tag keeps its SBOM
manifest and the purl hash of every component it describes; anything
else under `manifests/`, `layers/`, and `vulnerabilities/` is removed,
along with the provenance of any build removed,
except items with a live `.pid` file, which are reported as skipped.

A tagged manifest that exists but won't parse is different from a
missing one: its components exist but can't be identified, so they
would be deleted as unreachable. `Prune` reports such manifests in
`PruneResult.Unprotected` instead, and both commands warn about them.

![Pruning reachability walk](../diagrams/prune.svg)

*Source: [`docs/diagrams/prune.mmd`](https://github.com/alejandro-velasco/bomify/blob/main/docs/diagrams/prune.mmd)*
