---
icon: lucide/package
title: bomify
---

# bomify

`bomify` is a CLI that builds packages from [CycloneDX](https://cyclonedx.org/)
Software Bills of Materials (SBOMs).

Give it an SBOM and `bomify build` walks its components, delegating each one
to an external plugin binary that knows how to pull it. `bomify distribute`
later republishes an already-built package the same way, one component at a
time — to a different registry, a mirror, or wherever the component's own
plugin knows how to send it.

bomify's design deliberately mirrors Docker's: a **package** is built from a
CycloneDX SBOM the way an image is built from a Dockerfile, a **tag** points a
human-readable name at one, and `packages`/`tag`/`package rm`/`save`/`load`
all have a direct Docker analogue. What Docker calls "layers" are here the
individual **components** an SBOM describes — each pulled independently,
cached independently, and reused across builds by content hash.

!!! warning "Pre-alpha"

    bomify is under active early development. Its CLI flags, data directory
    layout, and plugin contract can all still change without notice, and
    there is currently no guarantee of stability or backward compatibility
    between versions.

<div class="grid cards" markdown>

- :material-rocket-launch:{ .lg .middle } **New here?**

    ---

    Install bomify and its first-party plugins, then build your first
    package.

    [:octicons-arrow-right-24: Getting started](getting-started/index.md)

- :material-console:{ .lg .middle } **Looking for a flag?**

    ---

    Full reference for every command, generated straight from the CLI
    itself.

    [:octicons-arrow-right-24: Usage](usage/index.md)

- :material-puzzle-outline:{ .lg .middle } **Building a plugin?**

    ---

    bomify doesn't know how to fetch anything itself — every purl type is
    handled by an external plugin binary.

    [:octicons-arrow-right-24: Building a plugin](development/building-a-plugin.md)

</div>
