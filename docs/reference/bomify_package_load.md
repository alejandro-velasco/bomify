## bomify package load

Load packages from a tarball

### Synopsis

Load restores every package in a "bomify save" tarball, as "bomify
pull" would, and records their tags. It reads stdin unless --input is
given.

--verify, --verify-provenance, --scan, --fail-on, their policy rules,
and --quiet work as for "bomify pull", applied to each package before
anything of it is restored. Scanning may need network access; on an air-gapped machine,
scan before saving instead.

```
bomify package load [flags]
```

### Examples

```
  # Load a tarball piped in from stdin
  cat packages.tar | bomify load

  # Load a tarball from a file
  bomify load --input packages.tar

  # Restore up to 6 layers concurrently
  bomify load --input packages.tar --concurrency 6

  # Require every package to carry a signature made with a cosign key
  bomify load --input packages.tar --verify sigstore --verify-option key=cosign.pub

  # Print just the pinned reference of each package loaded
  bomify load --input packages.tar --quiet
```

### Options

```
  -c, --concurrency int             number of layers to restore concurrently (default 3)
      --fail-on conditions          fail on these comma-separated conditions: a severity (info, low, medium, high, critical) that any vulnerability at or above fails, and/or "unscanned", failing if the scanner skipped any component; replaces a matching "bomify security policy" rule's
  -h, --help                        help for load
  -i, --input string                read the tarball from here instead of stdin
      --insecure-skip-verify        restore the package without verifying its signature or provenance, even if a "bomify trust" rule requires it
  -q, --quiet                       print only each restored package's pinned reference (<repository>@<digest>), with no progress or informational logging
      --scan string                 scan the package with this scanner (e.g. grype) before anything is written, refusing it if --fail-on is met; overrides a matching "bomify security policy" rule's
      --skip-scan                   don't scan or gate at all, even if a "bomify security policy" rule matching the package says to
      --verify string               require a signature this signing plugin (bomify-plugin-<kind>, e.g. sigstore) verifies, overriding any "bomify trust" rule
      --verify-option stringArray   a key=value option passed through to the --verify plugin (repeatable; e.g. key=cosign.pub)
      --verify-provenance           also require the package's build provenance, attested by a signer the verifying plugin trusts
```

### Options inherited from parent commands

```
      --data-dir string   directory to store bomify data (e.g., built packages). default is $HOME/.bomify or the value of the BOMIFY_DATA_DIR environment variable
      --docs-dir string   directory to write documentation to (if empty, no docs are generated)
      --verbose           enable verbose (debug) logging
```

### SEE ALSO

* [bomify package](bomify_package.md)	 - Manage individual bomify packages

