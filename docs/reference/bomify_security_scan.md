## bomify security scan

Scan a built package's components for vulnerabilities via a security scanning plugin

### Synopsis

Scan resolves <tag> to a package a prior "bomify build" (or "bomify
pull"/"bomify load") recorded locally, then scans every component that
package's SBOM describes through a single "bomify-plugin-<type>" binary —
<type> names the scanning tool itself (e.g. "grype"), not a purl type or
deployment medium, since any scanner can in principle scan any component.

bomify first asks the plugin, once, which component purl types and scan
categories it supports ("security supported-components"). Any component
whose purl type isn't in that list is skipped; every other component is
scanned via "security scan --purl <purl>", once per component, up to
--concurrency at a time: the same per-component, concurrent dispatch
"bomify build"/"bomify distribute" use, just for scanning instead of
pulling/pushing.

Each component's result is written as its own CycloneDX vulnerability
report, <data-dir>/vulnerabilities/<purl-hash>.json — keyed by the same
purl hash as that component's pull manifest and layer, so a component
shared by two packages shares one report too, and scanning either
package refreshes it for both. A report's metadata component is the
scanned component itself; for a component the plugin had to unpack to
scan at all (e.g. cataloging an OCI image's contents), the pieces it
found are the report's top-level components, and each vulnerability's
"affects" names the specific piece(s) affected. See
plugins/SECURITY-CONTRACT.md for the full contract.

--fail-on makes the scan exit non-zero if any vulnerability found is at
or above the given severity (info, low, medium, high, or critical),
printing a table of them to stderr; a vulnerability's severity is the
highest any of its ratings gives it, and one rated only "none" or
"unknown" never fails. --ignore (repeatable) exempts specific
vulnerability IDs for this scan only. --vex (repeatable) names an
OpenVEX, CSAF, or CycloneDX VEX document: a vulnerability it says doesn't
affect the component it was found in ("not_affected", "false_positive")
or was fixed there ("fixed", "resolved") doesn't fail the scan, and is
logged as exempted instead. For a vulnerability found in an image, every
package it affects there must be exempted. Without --fail-on, the most
specific "bomify security policy" rule matching <tag> decides the
threshold instead, if any does, and that rule's stored VEX documents
always apply alongside --vex, which reads the given file as it is now;
--skip-gate ignores the rule. Reports
are written either way.

```
bomify security scan <type> <tag> [flags]
```

### Examples

```
  # Scan the package tagged myapp:latest for vulnerabilities with grype
  bomify security scan grype myapp:latest

  # Scan up to 4 components concurrently
  bomify security scan grype myapp:latest --concurrency 4

  # Fail on anything high or critical, except one accepted CVE
  bomify security scan grype myapp:latest --fail-on high --ignore CVE-2024-1234
```

### Options

```
  -c, --concurrency int      number of components to scan concurrently (default 1)
      --fail-on string       fail if any vulnerability is at or above this severity (info, low, medium, high, critical); overrides a matching "bomify security policy" rule's
  -h, --help                 help for scan
      --ignore stringArray   a vulnerability ID not to fail on, for this command only (repeatable); requires --fail-on
      --skip-gate            never fail on vulnerabilities, even if a "bomify security policy" rule matching the package says to
      --vex stringArray      an OpenVEX, CSAF, or CycloneDX VEX document whose not-affected/fixed statements exempt vulnerabilities from failing (repeatable); added to a matching rule's
```

### Options inherited from parent commands

```
      --data-dir string   directory to store bomify data (e.g., built packages). default is $HOME/.bomify or the value of the BOMIFY_DATA_DIR environment variable
      --docs-dir string   directory to write documentation to (if empty, no docs are generated)
      --verbose           enable verbose (debug) logging
```

### SEE ALSO

* [bomify security](bomify_security.md)	 - Security scanning commands

