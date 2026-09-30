---
icon: lucide/send
---

# Distributing a package

`bomify distribute` publishes each component of a local package to its
own endpoint (images to an image registry, charts to a chart
repository), unlike `bomify push`, which publishes the package as one
artifact.

## 1. One-off remotes

```sh
bomify distribute myapp:latest \
  --remote oci=registry.example.com \
  --remote helm=charts.example.com/helm
```

Each `--remote` is a `kind=endpoint` pair. Kinds without one fall back to
rules.

## 2. Reusable rules

```sh
# Any OCI component goes here
bomify distribution create registry.example.com --type oci

# Mirror docker.io/myorg/*, keeping paths: docker.io/myorg/app -> mirror.example.com/myorg/app
bomify distribution create mirror.example.com/myorg --type oci --match docker.io/myorg

bomify distribution list
bomify distribution remove --type oci --match docker.io/myorg
```

A rule with `--match` keeps whatever follows the matched prefix of the
component's origin. The longest `--match` wins, and `--type` breaks
ties. With rules in place:

```sh
bomify distribute myapp:latest --concurrency 4
bomify distribute myapp:latest --check   # permissions only, publishes nothing
```
