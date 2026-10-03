## bomify package vulnerabilities

Print a package's component vulnerability reports

### Synopsis

Vulnerabilities prints the vulnerability reports of the local package
<tag>'s components (from "bomify security scan") as one JSON array on
stdout, in SBOM order: one per component and scanner, ordered by
scanner, each naming its scanner in metadata.tools. Components without a
report are skipped.

--purl (repeatable) limits it to specific components. Nothing but the
array goes to stdout; warnings, such as a --purl matching nothing, go
to stderr.

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

