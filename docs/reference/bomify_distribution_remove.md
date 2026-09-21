## bomify distribution remove

Remove a remote-endpoint rule

### Synopsis

Remove drops the rule matching --type/--match exactly (as
"bomify distribution list" prints them) from
<data-dir>/conf/distribution.json.

```
bomify distribution remove [flags]
```

### Examples

```
  # Remove the docker.io/myorg-specific oci rule
  bomify distribution remove --type oci --match docker.io/myorg

  # Remove the catch-all rule (no --type, no --match)
  bomify distribution remove
```

### Options

```
  -h, --help           help for remove
      --match string   the rule's match prefix, exactly as "bomify distribution list" prints it (empty for a rule with no --match)
      --type string    the rule's plugin kind, exactly as "bomify distribution list" prints it (empty for a rule with no --type)
```

### Options inherited from parent commands

```
      --data-dir string   directory to store bomify data (e.g., built packages). default is $HOME/.bomify or the value of the BOMIFY_DATA_DIR environment variable
      --docs-dir string   directory to write documentation to (if empty, no docs are generated)
      --verbose           enable verbose (debug) logging
```

### SEE ALSO

* [bomify distribution](bomify_distribution.md)	 - Manage remote-endpoint rules for bomify distribute

