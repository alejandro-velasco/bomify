---
icon: lucide/send
---

# Distributing a package

`bomify distribute` takes a package `bomify build` (or `bomify pull`)
already recorded locally and publishes each of its components to a
remote endpoint — unlike `bomify push`, which publishes a whole
package as one OCI artifact, `distribute` resolves an endpoint
per-component, so components of different kinds (or from different
origins) can land at different destinations in one call. See
[bomify distribute](../usage/reference/bomify_distribute.md) for the
full flag reference.

## 1. One-off remotes with `--remote`

```sh
bomify distribute myapp:latest \
  --remote oci=registry.example.com \
  --remote helm=charts.example.com/helm
```

Each `--remote` is a `kind=endpoint` pair; a component whose plugin
kind isn't given a matching `--remote` falls back to the rules below.

## 2. Reusable rules with `bomify distribution create`

For rules you don't want to retype on every distribute, record them
once in the data directory instead:

```sh
# Fall back to this registry for any OCI component
bomify distribution create registry.example.com --type oci

# Mirror docker.io/myorg/* under a new registry, keeping each
# repository's own path: docker.io/myorg/app -> mirror.example.com/myorg/app
bomify distribution create mirror.example.com/myorg --type oci --match docker.io/myorg
```

A rule with `--match` acts as a mirror: whatever of the component's
origin comes after the matched prefix is carried over onto the
endpoint, so distinct repositories under that prefix still land at
distinct destinations. When more than one rule matches a component,
the one with the longer `--match` wins, and `--type` breaks a tie
between two equally specific matches.

```sh
# See every configured rule, most specific first
bomify distribution list

# Drop a rule
bomify distribution remove --type oci --match docker.io/myorg
```

With rules in place, distributing is just:

```sh
bomify distribute myapp:latest
```

## 3. Check permissions first, without publishing

```sh
bomify distribute myapp:latest --check
```

## 4. Distribute concurrently

```sh
bomify distribute myapp:latest --concurrency 4
```

## Next steps

- [Building a package](building-a-package.md) if you haven't got one
  tagged locally yet.
- [Scanning an SBOM's components with grype](scanning-with-grype.md)
  before you distribute, if you want vulnerability data recorded
  alongside it.
