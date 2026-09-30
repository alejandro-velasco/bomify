---
icon: lucide/lock
---

# Saving packages for airgapped environments

`bomify save` writes built packages to one tarball, with their
components, vulnerability reports, and signatures; `bomify load`
restores them on another machine. No registry is involved.

## 1. Save

Packages must exist locally (built or pulled). Components shared between
packages are stored once.

```sh
bomify save myapp:v1 myapp:v2 --output packages.tar --concurrency 6
bomify save myapp:1.0 > myapp.tar   # stdout
```

## 2. Carry the tarball across

Removable media, a one-way file drop, whatever your environment allows.

## 3. Load

```sh
bomify load --input packages.tar
cat packages.tar | bomify load   # stdin
```

Every package is restored, reports included, and its tags recorded, just
as `bomify pull` would. `packages`, `push`, and `distribute` then work
offline.

To verify signatures without network access, sign with a key pair (see
[Signing and verifying packages](signing-and-verifying-packages.md#5-offline-tarballs)).
Scan before saving, since scanning needs network access.
