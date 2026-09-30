## bomify packages

List built packages

### Synopsis

Packages lists local packages, one row per repository:tag. SIZE is the
on-disk size of the package's components (0 for any not pulled).

```
bomify packages [flags]
```

### Examples

```
  # List every locally recorded package
  bomify packages
```

### Options

```
  -h, --help   help for packages
```

### Options inherited from parent commands

```
      --data-dir string   directory to store bomify data (e.g., built packages). default is $HOME/.bomify or the value of the BOMIFY_DATA_DIR environment variable
      --docs-dir string   directory to write documentation to (if empty, no docs are generated)
      --verbose           enable verbose (debug) logging
```

### SEE ALSO

* [bomify](bomify.md)	 - bomify builds packages from CycloneDX SBOMs

