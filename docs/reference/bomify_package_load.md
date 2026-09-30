## bomify package load

Load packages from a tarball

### Synopsis

Load restores every package a "bomify save" tarball contains into the
data directory, exactly as "bomify pull" would have for each, and
records each of their tags. Reads from stdin if --input isn't given.

Signature verification works exactly as for "bomify pull": --verify,
else any "bomify trust" rule matching each tag, checked before
anything of that package is restored. --insecure-skip-verify bypasses
a matching trust rule.

--scan, --fail-on, and --skip-scan gate each tag before anything of it
is restored, exactly as "bomify pull" does, as does a "bomify security
policy" rule listing "pull" in its --on.
Scanning may need network access, so on an air-gapped machine leave it
off, or scan before saving instead.

--quiet prints only each restored package's pinned reference,
<repository>@<digest>, one per tag on stdout — no progress bars, and no
logging but warnings and errors.

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
      --fail-on string              fail if any vulnerability is at or above this severity (info, low, medium, high, critical); overrides a matching "bomify security policy" rule's
  -h, --help                        help for load
  -i, --input string                read the tarball from here instead of stdin
      --insecure-skip-verify        restore the package without verifying its signature, even if a "bomify trust" rule requires it
  -q, --quiet                       print only each restored package's pinned reference (<repository>@<digest>), with no progress or informational logging
      --scan string                 scan the package's components with the bomify-plugin-<type> scanner before anything is written (e.g. grype), refusing it if --fail-on is met; overrides a matching "bomify security policy" rule's scanner
      --skip-scan                   don't scan or gate at all, even if a "bomify security policy" rule matching the package says to
      --verify string               require a signature this signing plugin (bomify-plugin-<kind>, e.g. sigstore) verifies, overriding any "bomify trust" rule
      --verify-option stringArray   a key=value option passed through to the --verify plugin (repeatable; e.g. key=cosign.pub)
```

### Options inherited from parent commands

```
      --data-dir string   directory to store bomify data (e.g., built packages). default is $HOME/.bomify or the value of the BOMIFY_DATA_DIR environment variable
      --docs-dir string   directory to write documentation to (if empty, no docs are generated)
      --verbose           enable verbose (debug) logging
```

### SEE ALSO

* [bomify package](bomify_package.md)	 - Manage individual bomify packages

