---
icon: lucide/package
title: bomify
---

# Overview

## What is Bomify?

`bomify` is a CLI that builds OCI packages from [CycloneDX](https://cyclonedx.org/)
Software Bills of Materials (SBOMs).

Bomify works as an orchestrator, by delegating component specific actions
to an external plugin binary (i.e. `bomify-plugin-<component-type>`) that knows how to interect with
that component type's api.

bomify's design deliberately mirrors many OCI container management tools (i.e. Docker, Podman, etc.): 

- A **package** is built from a CycloneDX SBOM the way an **image** is built from a Dockerfile, 
- A **tag** is a human readable reference to an SBOM Package
- The `package` subcommand subcommand works fairly similarly to the docker `image` subcommand
- What Docker/Podman calls **layers** are here the individual **components** an SBOM describes — each pulled independently,
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

    Full reference for every command

    [:octicons-arrow-right-24: Usage](usage/index.md)

- :material-puzzle-outline:{ .lg .middle } **Building a plugin?**

    ---

    Build a plugin to extend bomify's functionality.

    [:octicons-arrow-right-24: Building a plugin](development/building-a-plugin.md)

</div>
