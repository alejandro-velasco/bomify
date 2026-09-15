## bomify package manifest

Print a package's CycloneDX manifest

### Synopsis

Manifest resolves <tag> to the build recorded for it (see `bomify build`) and writes its aggregate CycloneDX SBOM manifest verbatim to stdout.

```
bomify package manifest <tag> [flags]
```

### Options

```
  -h, --help   help for manifest
```

### Options inherited from parent commands

```
      --data-dir string   directory to store bomify data (e.g., built packages) (default "C:\\Users\\aleja\\.bomify")
      --docs-dir string   directory to write documentation to (if empty, no docs are generated)
      --verbose           enable verbose (debug) logging
```

### SEE ALSO

* [bomify package](bomify_package.md)	 - Manage individual bomify packages

