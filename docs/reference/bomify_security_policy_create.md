## bomify security policy create

Create or update a vulnerability scanning policy rule

### Synopsis

Create adds a scan policy rule for packages whose repository starts with
--match (a "/"-separated prefix; omit it to match every package): the
scanner to use and, with --fail-on, the severity that fails. The longest
matching --match wins, and creating a rule for the same --match replaces
it.

--vex (repeatable) names documents from "bomify security vex add" that
exempt vulnerabilities. Rules have no ignore list on purpose: a standing
exemption belongs in VEX, which says which component and why. Use
"bomify security scan --ignore" for one-offs.

"bomify security scan" uses a matching rule's --fail-on when given none,
and always applies its VEX.

--on pull also scans and gates matching packages in "bomify pull" and
"bomify load" before anything is written. It requires --fail-on. Without
--on, the rule only applies to "bomify security scan".

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

  # ...and scan and gate them automatically before they're pulled or loaded
  bomify security policy create grype --match registry.example.com/team --fail-on high --on pull

  # Scan every other package with grype, never failing
  bomify security policy create grype
```

### Options

```
      --fail-on string    fail on any vulnerability at or above this severity (info, low, medium, high, critical); default never fails
  -h, --help              help for create
      --match string      apply to packages whose repository starts with this "/"-separated prefix; default applies to every package
      --on strings        lifecycle hooks to scan and gate matching packages at automatically: pull (which covers load too); default none
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

