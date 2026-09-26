## bomify security scan

Scan an SBOM's components for vulnerabilities via a security scanning plugin

### Synopsis

Scan resolves a single "bomify-plugin-<type>" binary — <type> names the
scanning tool itself (e.g. "grype"), not a purl type or deployment
medium, since any scanner can in principle scan any component — and
first asks it, once, which component purl types and scan categories it
supports ("security supported-components"). Any component whose purl
type isn't in that list is skipped; every other component is scanned
via "security scan --purl <purl>", once per component, up to
--concurrency at a time: the same per-component, concurrent dispatch
"bomify build"/"bomify distribute" use, just for scanning instead of
pulling/pushing.

Each scan call reports the vulnerabilities that component's purl is
affected by, and sets each one's "affects" itself — to the purl it was
given, or, if it had to unpack that purl into smaller pieces to scan it
at all (e.g. cataloging a container image's contents), to the specific
piece(s) actually affected. bomify only merges results across every
component: two separate scans reporting a vulnerability with the same
"bom-ref" are folded into one entry combining both "affects", rather
than duplicated; any pieces a plugin reports unpacking a component into
are embedded as that component's own nested components. See
plugins/SECURITY-CONTRACT.md for the full contract.

The scanned SBOM, with its "vulnerabilities" populated, is printed to
stdout by default; --output redirects it to a file instead.

```
bomify security scan <type> <sbom-file> [flags]
```

### Examples

```
  # Scan an SBOM for vulnerabilities with grype
  bomify security scan grype sbom.cdx.json

  # Scan up to 4 components concurrently, writing the result to a file
  bomify security scan grype sbom.cdx.json --concurrency 4 --output scanned.cdx.json
```

### Options

```
  -c, --concurrency int   number of components to scan concurrently (default 1)
  -h, --help              help for scan
  -o, --output string     file to write the scanned SBOM to (defaults to stdout)
```

### Options inherited from parent commands

```
      --data-dir string   directory to store bomify data (e.g., built packages). default is $HOME/.bomify or the value of the BOMIFY_DATA_DIR environment variable
      --docs-dir string   directory to write documentation to (if empty, no docs are generated)
      --verbose           enable verbose (debug) logging
```

### SEE ALSO

* [bomify security](bomify_security.md)	 - Security scanning commands

