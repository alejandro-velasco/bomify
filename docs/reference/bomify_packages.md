## bomify packages

List built packages

### Synopsis

Packages lists the packages recorded in
<data-dir>/package/repositories.json, one row per repository:tag. SIZE
is the total on-disk size of every component the package's SBOM
describes (0 for any not pulled yet).

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

