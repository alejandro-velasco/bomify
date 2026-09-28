---
icon: lucide/lock
---

# Saving packages for airgapped environments

`bomify save`/`bomify load` move one or more built packages between
machines as a single tarball — an OCI image-layout archive containing
each package's manifest and components, plus any local vulnerability
report a component has from a prior `bomify security scan` — with no
registry involved on either end. Useful for an airgapped target, or
anywhere a registry just isn't reachable. See
[bomify save](../usage/reference/bomify_save.md) and
[bomify load](../usage/reference/bomify_load.md) for the full flag
reference.

## 1. Build the packages you need first

`save` only archives packages already recorded locally, so
[build](building-a-package.md) (or `bomify pull`) whatever you need
before saving:

```sh
bomify build sbom.json --tag myapp:1.0
```

## 2. Save one or more tagged packages to a tarball

```sh
bomify save myapp:1.0 --output myapp.tar
```

Save several packages into one tarball — a component shared by more
than one of the given tags is stored once, not duplicated:

```sh
bomify save myapp:v1 myapp:v2 --output packages.tar
```

Archive layers concurrently for a faster save:

```sh
bomify save myapp:1.0 --output myapp.tar --concurrency 6
```

`--output` can be omitted to write to stdout instead, e.g. for
piping straight onto removable media:

```sh
bomify save myapp:1.0 > myapp.tar
```

## 3. Move the tarball across the airgap

However that transfer happens for your environment — removable media,
a one-way file drop, etc. — `myapp.tar` is the only artifact you need
to carry across.

## 4. Load it back on the other side

```sh
bomify load --input myapp.tar
```

`load` restores every package the tarball contains — vulnerability
reports included — exactly as `bomify pull` would have, and records
each of their tags — so `bomify packages`, `bomify push`, and `bomify
distribute` all work immediately on the far side, with no registry
ever contacted.

```sh
# Reading from stdin instead of --input works too
cat myapp.tar | bomify load
```

## Next steps

- [Distributing a package](distributing-a-package.md) once it's
  loaded, if the airgapped environment has its own internal registry.
- [Scanning a package's components with grype](scanning-with-grype.md)
  before you save — any report a scan already produced travels with
  the package automatically, so there's no need for network access on
  the far side to fetch it later.
