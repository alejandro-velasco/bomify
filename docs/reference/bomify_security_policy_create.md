## bomify security policy create

Create or update a vulnerability scanning policy rule

### Synopsis

Create adds a rule to <data-dir>/conf/scan.json setting the scanning
policy for every package whose reference matches --match: the scanning
plugin (bomify-plugin-<scanner>) that scans it, and — with --fail-on —
the severity at or above which its vulnerabilities fail the scan.
--match is a
"/"-separated prefix of the package's repository — its reference
without a tag or digest, e.g. "registry.example.com",
"registry.example.com/team", or "registry.example.com/team/app" —
matched at segment boundaries; omitting it makes the rule apply to
every package. When more than one rule matches, the one with the
longer --match wins. Running create again for the same --match
replaces that rule.

"bomify security scan" applies a matching rule's --fail-on when given
no --fail-on of its own, and ignores rules entirely with --skip-gate.
Rules have no list of vulnerabilities to ignore: exempt a one-off with
"bomify security scan --ignore" instead.

```
bomify security policy create <scanner> [flags]
```

### Examples

```
  # Fail any scan of a team's packages on high or critical vulnerabilities
  bomify security policy create grype --match registry.example.com/team --fail-on high

  # Scan every other package with grype, never failing
  bomify security policy create grype
```

### Options

```
      --fail-on string   fail on any vulnerability at or above this severity (info, low, medium, high, critical); default never fails
  -h, --help             help for create
      --match string     apply to packages whose repository starts with this "/"-separated prefix; default applies to every package
```

### Options inherited from parent commands

```
      --data-dir string   directory to store bomify data (e.g., built packages). default is $HOME/.bomify or the value of the BOMIFY_DATA_DIR environment variable
      --docs-dir string   directory to write documentation to (if empty, no docs are generated)
      --verbose           enable verbose (debug) logging
```

### SEE ALSO

* [bomify security policy](bomify_security_policy.md)	 - Manage vulnerability scanning policy rules

