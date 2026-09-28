## bomify pull

Download a bomify package from an OCI registry

### Synopsis

Pull downloads a bomify package artifact from an OCI registry: its
config (the aggregate SBOM manifest) and each of its layers (the
components that SBOM describes), laying them out in the data
directory exactly as "bomify build" would have. Layers download
concurrently, each with its own progress bar.

Any component the package carries a vulnerability report for is
restored to "<data-dir>/vulnerabilities/<purl-hash>.json", the same
path "bomify security scan" itself would have written it to.

--verify requires the package to carry a signature the named signing
plugin verifies (see "bomify push --sign"); without it, any "bomify
trust" rule matching <reference> applies instead. Either way, the
signature is checked before anything is written to the data
directory, so a package that fails verification leaves no trace.
--insecure-skip-verify bypasses a matching trust rule.

```
bomify pull <reference> [flags]
```

### Examples

```
  # Pull a tagged reference
  bomify pull registry.example.com/myapp:latest

  # Pull by digest
  bomify pull registry.example.com/myapp@sha256:abcdef...

  # Download up to 6 layers concurrently
  bomify pull registry.example.com/myapp:latest --concurrency 6

  # Require a signature made with a specific cosign key
  bomify pull registry.example.com/myapp:latest --verify cosign --verify-option key=cosign.pub
```

### Options

```
  -c, --concurrency int             number of layers to download concurrently (default 3)
  -h, --help                        help for pull
      --insecure-skip-verify        restore the package without verifying its signature, even if a "bomify trust" rule requires it
      --verify string               require a signature this signing plugin (bomify-plugin-<kind>, e.g. cosign) verifies, overriding any "bomify trust" rule
      --verify-option stringArray   a key=value option passed through to the --verify plugin (repeatable; e.g. key=cosign.pub)
```

### Options inherited from parent commands

```
      --data-dir string   directory to store bomify data (e.g., built packages). default is $HOME/.bomify or the value of the BOMIFY_DATA_DIR environment variable
      --docs-dir string   directory to write documentation to (if empty, no docs are generated)
      --verbose           enable verbose (debug) logging
```

### SEE ALSO

* [bomify](bomify.md)	 - bomify builds packages from CycloneDX SBOMs

