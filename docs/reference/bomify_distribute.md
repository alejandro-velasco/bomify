## bomify distribute

Distribute publishes the packages described by a CycloneDX SBOM to a remote endpoint

### Synopsis

Distribute reads a CycloneDX SBOM and publishes each component it describes to a remote endpoint.

```
bomify distribute <sbom-file> [flags]
```

### Options

```
  -c, --concurrency int   number of components to push concurrently (default 1)
  -h, --help              help for distribute
  -r, --remote string     remote endpoint to distribute components to
```

### Options inherited from parent commands

```
      --data-dir string   directory to store bomify data (e.g., built packages). default is $HOME/.bomify or the value of the BOMIFY_DATA_DIR environment variable
      --docs-dir string   directory to write documentation to (if empty, no docs are generated)
      --verbose           enable verbose (debug) logging
```

### SEE ALSO

* [bomify](bomify.md)	 - bomify builds packages from CycloneDX SBOMs

