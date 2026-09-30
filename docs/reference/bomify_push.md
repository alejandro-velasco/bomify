## bomify push

Publish a bomify package to an OCI registry

### Synopsis

Push packages the SBOM manifest a prior "bomify build" recorded for
<tag> (and each component it describes) as an OCI artifact, and
publishes it under <tag>. <tag> is both the local bookkeeping key
(see "bomify tag" / "bomify packages") and the destination reference.

Every local vulnerability report from a prior "bomify security scan" of
the package's components is attached to it as a single OCI referrer,
rather than as part of the package itself: re-scanning and pushing
again leaves the package's digest, and so any signature over it,
unchanged, and just attaches a newer report referrer. Pushing again
with unchanged reports attaches nothing new. Once attached, all but the
newest --keep-reports report referrers (default 1; 0 keeps them all)
are deleted from the registry, each with its own signature. Deletion
is best-effort: a registry that refuses it (e.g. ghcr.io) only logs a
warning, and "bomify security prune" can retry it later.

--sign signs the pushed package with a signing plugin before <tag> is
updated to point at it, attaching the signature to it as an OCI
referrer. One signature covers the SBOM and every component; the
report referrer is signed separately, the same way. See "bomify pull
--verify" and "bomify trust" for checking them.

--quiet prints only the pushed package's pinned reference,
<repository>@<digest>, on stdout — no progress bars, and no logging but
warnings and errors — for scripts that go on to publish or pin it.

```
bomify push <tag> [flags]
```

### Examples

```
  # Push the package tagged myapp:latest to its own registry reference
  bomify push myapp:latest

  # Push using a fully qualified registry reference as the tag
  bomify push registry.example.com/myapp:latest

  # Upload up to 6 layers concurrently
  bomify push myapp:latest --concurrency 6

  # Sign the package with a cosign key while pushing it
  bomify push registry.example.com/myapp:latest --sign sigstore --sign-option key=cosign.key

  # Print just the pinned reference, e.g. to publish it
  pinned=$(bomify push registry.example.com/myapp:latest --quiet)
```

### Options

```
  -c, --concurrency int           number of layers to upload concurrently (default 3)
  -h, --help                      help for push
      --keep-reports int          number of newest vulnerability report referrers to keep on the registry after pushing; older ones are deleted (0 keeps them all) (default 1)
  -q, --quiet                     print only the pushed package's pinned reference (<repository>@<digest>), with no progress or informational logging
      --sign string               sign the package with this signing plugin (bomify-plugin-<kind>, e.g. sigstore), attaching the signature as an OCI referrer
      --sign-option stringArray   a key=value option passed through to the signing plugin (repeatable; e.g. key=cosign.key)
```

### Options inherited from parent commands

```
      --data-dir string   directory to store bomify data (e.g., built packages). default is $HOME/.bomify or the value of the BOMIFY_DATA_DIR environment variable
      --docs-dir string   directory to write documentation to (if empty, no docs are generated)
      --verbose           enable verbose (debug) logging
```

### SEE ALSO

* [bomify](bomify.md)	 - bomify builds packages from CycloneDX SBOMs

