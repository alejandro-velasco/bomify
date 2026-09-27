---
icon: lucide/list-checks
---

# How-to guides

Task-focused walkthroughs for specific bomify workflows. These assume
you already have bomify (and whichever plugins you need) installed —
see [Getting started](../getting-started/index.md) first if you don't.
Each guide links out to the full flag reference for the commands it
uses; it doesn't repeat it.

- [Building a package](building-a-package.md) — pull every component
  an SBOM describes into a locally tagged package.
- [Distributing a package](distributing-a-package.md) — publish a
  built package's components to one or more remote endpoints.
- [Building an SBOM from a Helm chart](building-an-sbom-from-a-helm-chart.md) —
  generate a CycloneDX SBOM from a chart's rendered templates, no
  cluster required.
- [Scanning an SBOM's components with grype](scanning-with-grype.md) —
  populate an SBOM's `vulnerabilities` using `bomify-plugin-grype`.
- [Saving packages for airgapped environments](saving-packages-for-airgapped-environments.md) —
  move packages to a machine with no registry access via a tarball.
