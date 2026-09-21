## bomify package build

Build the package described by a CycloneDX SBOM

### Synopsis

Build reads a CycloneDX SBOM and builds a package containing each
component it describes. Each component is resolved to a plugin by its
kind and pulled through it, and the SBOM is then recorded as this
build's manifest so later commands (push, distribute, tag, packages)
can find it.

--check verifies every component is pullable and authorized — an
inexpensive existence/auth check each plugin performs itself, without
downloading anything — and skips recording a build, since nothing was
actually pulled.

```
bomify package build <sbom-file> [flags]
```

### Examples

```
  # Build the package described by sbom.json
  bomify build sbom.json

  # Build and tag the result as myapp:latest
  bomify build sbom.json --tag myapp:latest

  # Pull up to 4 components concurrently, verifying against sha-512
  bomify build sbom.json --concurrency 4 --hash sha-512

  # Verify every component is pullable, without downloading anything
  bomify build sbom.json --check
```

### Options

```
      --check             verify every component is pullable and authorized, without downloading any of them or recording a build
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

