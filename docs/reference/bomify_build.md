## bomify build

Build the package described by a CycloneDX SBOM

### Synopsis

Build reads a CycloneDX SBOM and builds a package containing each
component it describes. Each component is resolved to a plugin by its
kind and pulled through it, and the SBOM is then recorded as this
build's manifest so later commands (push, distribute, tag, packages)
can find it.

A component whose purl type is "bomify-plugin" (e.g.
"pkg:bomify-plugin/oci@v1.2.0?os=linux&arch=amd64") is a plugin binary
rather than something a plugin fetches: bomify copies it itself from
the local path (or file:// URL) its "distribution" external reference
names, resolved against the SBOM's own directory. Packages built this
way are what "bomify plugin install" installs.

--check verifies every component is pullable and authorized — an
inexpensive existence/auth check each plugin performs itself, without
downloading anything — and skips recording a build, since nothing was
actually pulled.

--scan <type> scans the recorded build's components with a scanning
plugin afterwards, writing each component's report as "bomify security
scan" would, and --fail-on <severity> (with --ignore and --vex) fails
the command if anything at or above it is found. A "bomify security
policy" rule listing "build" in its --on does the same for any matching
--tag without flags; --skip-scan ignores it. A failing scan leaves the
build recorded, reports included, to inspect with "bomify package
vulnerabilities".

```
bomify build <sbom-file> [flags]
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
      --check                verify every component is pullable and authorized, without downloading any of them or recording a build
  -c, --concurrency int      number of components to pull concurrently (default 1)
      --fail-on string       fail if any vulnerability is at or above this severity (info, low, medium, high, critical); overrides a matching "bomify security policy" rule's
      --hash string          hash algorithm to verify pulled components against their SBOM-declared hash (default "sha-256")
  -h, --help                 help for build
      --ignore stringArray   a vulnerability ID not to fail on, for this command only (repeatable); requires --fail-on
      --scan string          scan the package's components with the bomify-plugin-<type> scanner first (e.g. grype); overrides a matching "bomify security policy" rule's scanner
      --skip-scan            don't scan or gate at all, even if a "bomify security policy" rule matching the package says to
  -t, --tag stringArray      tag this build as name[:version] (repeatable); defaults version to "latest"
      --vex stringArray      an OpenVEX, CSAF, or CycloneDX VEX document whose not-affected/fixed statements exempt vulnerabilities from failing (repeatable); added to a matching rule's
```

### Options inherited from parent commands

```
      --data-dir string   directory to store bomify data (e.g., built packages). default is $HOME/.bomify or the value of the BOMIFY_DATA_DIR environment variable
      --docs-dir string   directory to write documentation to (if empty, no docs are generated)
      --verbose           enable verbose (debug) logging
```

### SEE ALSO

* [bomify](bomify.md)	 - bomify builds packages from CycloneDX SBOMs

