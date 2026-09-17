## bomify package build

Build builds the package described by a CycloneDX SBOM

### Synopsis

Build reads a CycloneDX SBOM and builds a containing each component it describes.

```
bomify package build <sbom-file> [flags]
```

### Options

```
  -c, --concurrency int   number of components to pull concurrently (default 1)
      --hash string       hash algorithm to verify pulled components against their SBOM-declared hash (default "sha-256")
  -h, --help              help for build
  -t, --tag stringArray   tag this build as name[:version] (repeatable); defaults version to "latest"
```

### Options inherited from parent commands

```
      --data-dir string   directory to store bomify data (e.g., built packages). default is $HOME/.bomify or the value of the BOMIFY_DATA_DIR environment variable
      --docs-dir string   directory to write documentation to (if empty, no docs are generated)
      --verbose           enable verbose (debug) logging
```

### SEE ALSO

* [bomify package](bomify_package.md)	 - Manage individual bomify packages

