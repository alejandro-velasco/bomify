---
icon: lucide/rocket
---

# Getting started

This section walks through installing bomify and its first-party plugins,
and building your first package. If you just want the flags for a specific
command, skip ahead to [Usage](../usage/index.md).

bomify itself never fetches or publishes anything — it only reads a
CycloneDX SBOM and delegates each component to an external
`bomify-plugin-<kind>` binary that knows how to handle that component's purl
type. That's why installing bomify alone isn't enough to build anything real:
you also need the plugin for whatever kinds of components your SBOMs
describe. See [Installing plugins](installing-plugins.md).

1. [Install bomify and the plugins you need](installation.md)
2. [Install the first-party plugins](installing-plugins.md)
3. [Build, tag, and push your first package](quickstart.md)
