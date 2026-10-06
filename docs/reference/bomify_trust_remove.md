## bomify trust remove

Remove a signature verification rule

### Synopsis

Remove drops the rule matching --match exactly (as "bomify trust
list" prints it) from <data-dir>/conf/trust.json, or with --signer just
that signer, and the rule along with its last one. --signer '' removes
the rule's unnamed signer ("-" in "bomify trust list").

After --signer removes one, a rule with "--require all" requires every
signer left. A rule with a number refuses to drop below it: removing a
signer from a rule requiring 2 of 2 fails until its --require is
lowered.

```
bomify trust remove [flags]
```

### Examples

```
  # Remove the rule for a team's repositories
  bomify trust remove --match registry.example.com/team

  # Remove the rule applying to every package (no --match)
  bomify trust remove

  # Stop requiring the security team's signature
  bomify trust remove --match registry.example.com/prod --signer security

  # Drop the unnamed signer a rule kept after named ones were added
  bomify trust remove --match registry.example.com/prod --signer ''
```

### Options

```
  -h, --help            help for remove
      --match string    the rule's match prefix, exactly as "bomify trust list" prints it (empty for a rule with no --match)
      --signer string   remove only this signer from the rule ('' for its unnamed signer)
```

### Options inherited from parent commands

```
      --data-dir string   directory to store bomify data (e.g., built packages). default is $HOME/.bomify or the value of the BOMIFY_DATA_DIR environment variable
      --docs-dir string   directory to write documentation to (if empty, no docs are generated)
      --verbose           enable verbose (debug) logging
```

### SEE ALSO

* [bomify trust](bomify_trust.md)	 - Manage signature verification rules for bomify pull and load

