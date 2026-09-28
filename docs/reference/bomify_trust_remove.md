## bomify trust remove

Remove a signature verification rule

### Synopsis

Remove drops the rule matching --match exactly (as "bomify trust
list" prints it) from <data-dir>/conf/trust.json.

```
bomify trust remove [flags]
```

### Examples

```
  # Remove the rule for a team's repositories
  bomify trust remove --match registry.example.com/team

  # Remove the rule applying to every package (no --match)
  bomify trust remove
```

### Options

```
  -h, --help           help for remove
      --match string   the rule's match prefix, exactly as "bomify trust list" prints it (empty for a rule with no --match)
```

### Options inherited from parent commands

```
      --data-dir string   directory to store bomify data (e.g., built packages). default is $HOME/.bomify or the value of the BOMIFY_DATA_DIR environment variable
      --docs-dir string   directory to write documentation to (if empty, no docs are generated)
      --verbose           enable verbose (debug) logging
```

### SEE ALSO

* [bomify trust](bomify_trust.md)	 - Manage signature verification rules for bomify pull and load

