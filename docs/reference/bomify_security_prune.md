## bomify security prune

Delete stale vulnerability report referrers of a package in a registry

### Synopsis

Prune deletes all but the newest --keep vulnerability report referrers
of the package <ref> in its registry, each with its signature. Nothing
else attached to the package is touched.

"bomify push" already prunes; use this to retry when the registry
refused, or to clean up without pushing. Unlike push, prune fails if
any deletion fails.

```
bomify security prune <ref> [flags]
```

### Examples

```
  # Keep only the newest vulnerability reports of a pushed package
  bomify security prune registry.example.com/myapp:latest

  # Keep the three newest
  bomify security prune registry.example.com/myapp:latest --keep 3
```

### Options

```
  -h, --help       help for prune
      --keep int   number of newest vulnerability report referrers to keep (default 1)
```

### Options inherited from parent commands

```
      --data-dir string   directory to store bomify data (e.g., built packages). default is $HOME/.bomify or the value of the BOMIFY_DATA_DIR environment variable
      --docs-dir string   directory to write documentation to (if empty, no docs are generated)
      --verbose           enable verbose (debug) logging
```

### SEE ALSO

* [bomify security](bomify_security.md)	 - Security scanning commands

