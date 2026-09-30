## bomify build

Build the package described by a CycloneDX SBOM

### Synopsis

Build pulls every component a CycloneDX SBOM describes, each through
the plugin for its purl type, and records the SBOM as the build so
push, distribute, tag, and packages can find it.

A "pkg:bomify-plugin/..." component is a plugin binary: bomify copies it
from the path or file:// URL in its "distribution" external reference
(relative to the SBOM). Packages built this way are what "bomify plugin
install" installs.

--check asks each plugin to confirm its component is reachable and
authorized, without downloading anything or recording a build.

```
bomify build <sbom-file> [flags]
```

### Examples

```
  # Build the package described by sbom.json
  bomify build sbom.json

  # Build and tag the result as myapp:latest
  bomify build sbom.json --tag myapp:latest

  # Pull up to 4 components concurrently
  bomify build sbom.json --concurrency 4

  # Verify every component is pullable, without downloading anything
  bomify build sbom.json --check
```

### Options

```
      --check             verify every component is pullable and authorized, without downloading any of them or recording a build
  -c, --concurrency int   number of components to pull concurrently (default 1)
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

* [bomify](bomify.md)	 - bomify builds packages from CycloneDX SBOMs

