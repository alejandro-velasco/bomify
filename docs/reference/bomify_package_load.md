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
```

### Options

```
  -c, --concurrency int             number of layers to restore concurrently (default 3)
  -h, --help                        help for load
  -i, --input string                read the tarball from here instead of stdin
      --insecure-skip-verify        restore the package without verifying its signature, even if a "bomify trust" rule requires it
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

