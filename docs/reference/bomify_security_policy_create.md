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

--vex (repeatable) names a VEX document in the data directory's managed
store (see "bomify security vex add") whose "not affected"/"fixed"
statements exempt a matching package's vulnerabilities from --fail-on.
Rules refer to documents by name, never by path, so a rule keeps
working however the files it was built from move, and re-adding a
document under the same name updates every rule using it. Rules have
no list of bare vulnerability IDs to ignore: a standing exemption
belongs in a VEX document, which says which component it applies to
and why. For a one-off, use "bomify security scan --ignore".

"bomify security scan" applies a matching rule's --fail-on when given
no --fail-on of its own, always applies its VEX documents alongside any
--vex of its own, and ignores rules entirely with --skip-scan.

--on (comma-separated or repeatable) also makes a matching package get
scanned with <scanner> and gated automatically at those lifecycle hooks:
"push" (before "bomify push" or "bomify save" sends it anywhere) and
"pull" (before "bomify pull" or "bomify load" writes anything of it). Without --on, the rule only
applies to "bomify security scan". Each of those commands' --scan and
--fail-on override the rule, and --skip-scan ignores it.

```
bomify security policy create <scanner> [flags]
```

### Examples

```
  # Fail any scan of a team's packages on high or critical vulnerabilities
  bomify security policy create grype --match registry.example.com/team --fail-on high

  # ...exempting whatever the team's VEX document shows doesn't affect it
  bomify security vex add team team.openvex.json
  bomify security policy create grype --match registry.example.com/team --fail-on high --vex team

  # ...and scan and gate them automatically before they're pushed or pulled
  bomify security policy create grype --match registry.example.com/team --fail-on high --on push,pull

  # Scan every other package with grype, never failing
  bomify security policy create grype
```

### Options

```
      --fail-on string    fail on any vulnerability at or above this severity (info, low, medium, high, critical); default never fails
  -h, --help              help for create
      --match string      apply to packages whose repository starts with this "/"-separated prefix; default applies to every package
      --on strings        lifecycle hooks to scan and gate matching packages at automatically: push (and save), pull (and load); default none
      --vex stringArray   the name of a stored VEX document (see "bomify security vex add") exempting vulnerabilities it shows don't affect the package (repeatable)
```

### Options inherited from parent commands

```
      --data-dir string   directory to store bomify data (e.g., built packages). default is $HOME/.bomify or the value of the BOMIFY_DATA_DIR environment variable
      --docs-dir string   directory to write documentation to (if empty, no docs are generated)
      --verbose           enable verbose (debug) logging
```

### SEE ALSO

* [bomify security policy](bomify_security_policy.md)	 - Manage vulnerability scanning policy rules

