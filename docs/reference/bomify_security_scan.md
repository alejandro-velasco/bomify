## bomify security scan

Scan a built package's components for vulnerabilities via a security scanning plugin

### Synopsis

Scan scans every component of the local package <tag> with each of
<scanners>, comma-separated (bomify-plugin-<scanner>, e.g. grype), and
writes one CycloneDX vulnerability report per component and scanner to
<data-dir>/vulnerabilities/, shared by every package containing that
component. Each component goes to every scanner that supports it, and a
scanner's report replaces only its own earlier one. Components no
scanner supports are skipped, and listed on stderr.

--fail-on takes comma-separated conditions that exit non-zero, printing
what failed to stderr. Reports are written either way.
  - A severity (info, low, medium, high, critical): any vulnerability at
    or above it.
  - "unscanned": any component no scanner scanned, so nothing passes
    unchecked. Skipped components are listed on stderr either way.
  Every scanner's reports are gated together: a vulnerability several
  scanners report fails at the highest severity any gives it.
  --ignore (repeatable) exempts vulnerability IDs for this scan only.
  --vex (repeatable) reads an OpenVEX, CSAF, or CycloneDX VEX file; a
  vulnerability it marks not affected or fixed doesn't fail the scan.
  For an image, every affected package in it must be exempted.

Without --fail-on, the most specific matching "bomify security policy"
rule's conditions apply; --fail-on replaces them all. The rule's stored
VEX always applies alongside --vex. --skip-gate ignores the rule's
conditions.

```
bomify security scan <scanners> <tag> [flags]
```

### Examples

```
  # Scan the package tagged myapp:latest for vulnerabilities with grype
  bomify security scan grype myapp:latest

  # Scan up to 4 components concurrently
  bomify security scan grype myapp:latest --concurrency 4

  # Fail on anything high or critical, except one accepted CVE
  bomify security scan grype myapp:latest --fail-on high --ignore CVE-2024-1234

  # Also fail if grype skipped any component
  bomify security scan grype myapp:latest --fail-on high,unscanned

  # Scan with two scanners, failing unless one of them scanned every component
  bomify security scan grype,trivy myapp:latest --fail-on high,unscanned
```

### Options

```
  -c, --concurrency int      number of components to scan concurrently (default 1)
      --fail-on conditions   fail on these comma-separated conditions: a severity (info, low, medium, high, critical) that any vulnerability at or above fails, and/or "unscanned", failing if any component no scanner scanned; replaces a matching "bomify security policy" rule's
  -h, --help                 help for scan
      --ignore stringArray   a vulnerability ID not to fail on, for this command only (repeatable); requires --fail-on
      --skip-gate            never fail on vulnerabilities, even if a "bomify security policy" rule matching the package says to
      --vex stringArray      a VEX document (OpenVEX, CSAF, or CycloneDX) exempting what it marks not affected or fixed (repeatable); applied with a matching rule's
```

### Options inherited from parent commands

```
      --data-dir string   directory to store bomify data (e.g., built packages). default is $HOME/.bomify or the value of the BOMIFY_DATA_DIR environment variable
      --docs-dir string   directory to write documentation to (if empty, no docs are generated)
      --verbose           enable verbose (debug) logging
```

### SEE ALSO

* [bomify security](bomify_security.md)	 - Security scanning commands

