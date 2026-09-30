## bomify security policy remove

Remove a vulnerability scanning policy rule

### Synopsis

Remove drops the rule matching --match exactly (as "bomify security
policy list" prints it) from <data-dir>/conf/scan.json.

```
bomify security policy remove [flags]
```

### Examples

```
  # Remove the rule for a team's repositories
  bomify security policy remove --match registry.example.com/team

  # Remove the rule applying to every package (no --match)
  bomify security policy remove
```

### Options

```
  -h, --help           help for remove
      --match string   the rule's match prefix, exactly as "bomify security policy list" prints it (empty for a rule with no --match)
```

### Options inherited from parent commands

```
      --data-dir string   directory to store bomify data (e.g., built packages). default is $HOME/.bomify or the value of the BOMIFY_DATA_DIR environment variable
      --docs-dir string   directory to write documentation to (if empty, no docs are generated)
      --verbose           enable verbose (debug) logging
```

### SEE ALSO

* [bomify security policy](bomify_security_policy.md)	 - Manage vulnerability scanning policy rules

