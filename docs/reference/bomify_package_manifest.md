## bomify package manifest

Print a remote package's CycloneDX manifest

### Synopsis

Manifest fetches <reference> from an OCI registry and writes its
aggregate CycloneDX SBOM manifest (the artifact's config blob)
verbatim to stdout, without pulling any of its layers or writing
anything to the data directory.

```
bomify package manifest <reference> [flags]
```

### Examples

```
  # Print the manifest for a tagged reference
  bomify package manifest registry.example.com/myapp:latest

  # Print the manifest for a digest reference
  bomify package manifest registry.example.com/myapp@sha256:abcdef...
```

### Options

```
  -h, --help   help for manifest
```

### Options inherited from parent commands

```
      --data-dir string   directory to store bomify data (e.g., built packages). default is $HOME/.bomify or the value of the BOMIFY_DATA_DIR environment variable
      --docs-dir string   directory to write documentation to (if empty, no docs are generated)
      --verbose           enable verbose (debug) logging
```

### SEE ALSO

* [bomify package](bomify_package.md)	 - Manage individual bomify packages

