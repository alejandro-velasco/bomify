## bomify trust create

Create or update a signature verification rule

### Synopsis

Create adds a rule to <data-dir>/conf/trust.json requiring every
package whose reference matches --match to carry a signature the
<verifier> signing plugin (bomify-plugin-<verifier>) verifies before
"bomify pull" or "bomify load" restore it. --match is a "/"-separated
prefix of the package's repository — its reference without a tag or
digest, e.g. "registry.example.com", "registry.example.com/team", or
"registry.example.com/team/app" — matched at segment boundaries;
omitting it makes the rule apply to every package. When more than one
rule matches, the one with the longer --match wins. Running create
again for the same --match replaces that rule.

Each --option (key=value) is passed through, unparsed, to the plugin's
"signature verify" — typically naming which key or identity it should
trust for packages matching this rule.

An explicit "--verify" on pull/load takes precedence over every rule,
and "--insecure-skip-verify" bypasses them.

```
bomify trust create <verifier> [flags]
```

### Examples

```
  # Require packages from a team's repositories to be signed with its cosign key
  bomify trust create sigstore --match registry.example.com/team --option key=team.pub

  # Require every package to be signed with the organization's key
  bomify trust create sigstore --option key=org.pub
```

### Options

```
  -h, --help                 help for create
      --match string         apply to packages whose repository starts with this "/"-separated prefix; default applies to every package
      --option stringArray   a key=value option passed through to the verifier plugin (repeatable)
```

### Options inherited from parent commands

```
      --data-dir string   directory to store bomify data (e.g., built packages). default is $HOME/.bomify or the value of the BOMIFY_DATA_DIR environment variable
      --docs-dir string   directory to write documentation to (if empty, no docs are generated)
      --verbose           enable verbose (debug) logging
```

### SEE ALSO

* [bomify trust](bomify_trust.md)	 - Manage signature verification rules for bomify pull and load

