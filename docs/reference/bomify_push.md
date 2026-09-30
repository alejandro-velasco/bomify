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

--scan <type> scans the package's components fresh before anything is
uploaded — the reports it writes are the ones the package then carries
— and --fail-on <severity> (with --ignore and --vex) refuses to push it
if anything at or above it is found; --fail-on needs --scan, since a
push always scans fresh. A "bomify security policy" rule listing "push"
in its --on does the same for a matching <tag> without flags;
--skip-scan ignores it.

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
      --fail-on string            fail if any vulnerability is at or above this severity (info, low, medium, high, critical); overrides a matching "bomify security policy" rule's
  -h, --help                      help for push
      --ignore stringArray        a vulnerability ID not to fail on, for this command only (repeatable); requires --fail-on
      --keep-reports int          number of newest vulnerability report referrers to keep on the registry after pushing; older ones are deleted (0 keeps them all) (default 1)
  -q, --quiet                     print only the pushed package's pinned reference (<repository>@<digest>), with no progress or informational logging
      --scan string               scan the package's components with the bomify-plugin-<type> scanner first (e.g. grype); overrides a matching "bomify security policy" rule's scanner
      --sign string               sign the package with this signing plugin (bomify-plugin-<kind>, e.g. sigstore), attaching the signature as an OCI referrer
      --sign-option stringArray   a key=value option passed through to the signing plugin (repeatable; e.g. key=cosign.key)
      --skip-scan                 don't scan or gate at all, even if a "bomify security policy" rule matching the package says to
      --vex stringArray           an OpenVEX, CSAF, or CycloneDX VEX document whose not-affected/fixed statements exempt vulnerabilities from failing (repeatable); added to a matching rule's
```

### Options inherited from parent commands

```
      --data-dir string   directory to store bomify data (e.g., built packages). default is $HOME/.bomify or the value of the BOMIFY_DATA_DIR environment variable
      --docs-dir string   directory to write documentation to (if empty, no docs are generated)
      --verbose           enable verbose (debug) logging
```

### SEE ALSO

* [bomify](bomify.md)	 - bomify builds packages from CycloneDX SBOMs

