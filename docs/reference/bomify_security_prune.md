## bomify security prune

Delete stale vulnerability report referrers of a package in a registry

### Synopsis

Prune deletes all but the newest --keep vulnerability report referrers
attached to the package <ref> resolves to in its registry, each along
with anything referring to it in turn (typically its signature). The
package itself, its own signatures, and anything else attached to it are
left alone.

"bomify push" already does this after attaching new reports (see its
--keep-reports); prune is for retrying that when it couldn't, or for
cleaning up a package without pushing it again. Unlike push, prune fails
if any stale referrer couldn't be deleted — e.g. because the registry
refuses manifest deletes altogether.

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

