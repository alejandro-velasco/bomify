## bomify package vulnerabilities

Print a package's component vulnerability reports

### Synopsis

Vulnerabilities resolves <tag> to a package a prior "bomify build" (or
"bomify pull"/"bomify load") recorded locally, then writes a JSON array
to stdout — parsable straight through "jq", unlike the single raw
document "bomify package manifest" writes — with one element per
component: its vulnerability report exactly as it sits at
"<data-dir>/vulnerabilities/<purl-hash>.json" (see "bomify security
scan"), in the SBOM's own component order. A component with no report
(never scanned, or scanned by a plugin that doesn't support its purl
type) is silently skipped, and a purl the SBOM lists more than once is
only included once.

--purl narrows this down to specific components; pass it more than
once for more than one. Without it, every component the SBOM describes
is considered.

Nothing but that JSON array is ever written to stdout — no log lines,
so a "--purl" that matches nothing in the SBOM is reported as a
warning on stderr rather than printed inline.

```
bomify package vulnerabilities <tag> [flags]
```

### Examples

```
  # Print every component's vulnerability report for a package
  bomify package vulnerabilities myapp:latest

  # Print only specific components' reports
  bomify package vulnerabilities myapp:latest --purl pkg:oci/nginx@1.27 --purl pkg:npm/lodash@4.17.15

  # Pipe into jq, e.g. to list every reported vulnerability ID
  bomify package vulnerabilities myapp:latest | jq '.[].vulnerabilities[].id'
```

### Options

```
  -h, --help               help for vulnerabilities
      --purl stringArray   only show the report for this purl (repeatable); shows every component's report if omitted
```

### Options inherited from parent commands

```
      --data-dir string   directory to store bomify data (e.g., built packages). default is $HOME/.bomify or the value of the BOMIFY_DATA_DIR environment variable
      --docs-dir string   directory to write documentation to (if empty, no docs are generated)
      --verbose           enable verbose (debug) logging
```

### SEE ALSO

* [bomify package](bomify_package.md)	 - Manage individual bomify packages

