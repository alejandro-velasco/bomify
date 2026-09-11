## bomify pull

Pull downloads a bomify package from an OCI registry

### Synopsis

Pull downloads a bomify package artifact from an OCI registry: its config (the aggregate SBOM manifest) and each of its layers (the components that SBOM describes), laying them out in the data directory exactly as `bomify build` would have. Layers download concurrently, each with its own progress bar.

```
bomify pull <reference> [flags]
```

### Options

```
  -c, --concurrency int   number of layers to download concurrently (default 3)
  -h, --help              help for pull
```

### Options inherited from parent commands

```
      --data-dir string   directory to store bomify data (e.g., built packages) (default "C:\\Users\\aleja\\.bomify")
      --docs-dir string   directory to write documentation to (if empty, no docs are generated)
      --verbose           enable verbose (debug) logging
```

### SEE ALSO

* [bomify](bomify.md)	 - bomify builds packages from CycloneDX SBOMs

