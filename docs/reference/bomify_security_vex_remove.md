## bomify security vex remove

Remove a VEX document from the managed store

### Synopsis

Remove drops <name> from <data-dir>/vex/, deleting its stored copy
unless another name refers to the same content. It refuses while any
"bomify security policy" rule still lists <name>, so no rule is left
referring to a document that no longer exists.

```
bomify security vex remove <name> [flags]
```

### Examples

```
  # Remove the document stored as "team"
  bomify security vex remove team
```

### Options

```
  -h, --help   help for remove
```

### Options inherited from parent commands

```
      --data-dir string   directory to store bomify data (e.g., built packages). default is $HOME/.bomify or the value of the BOMIFY_DATA_DIR environment variable
      --docs-dir string   directory to write documentation to (if empty, no docs are generated)
      --verbose           enable verbose (debug) logging
```

### SEE ALSO

* [bomify security vex](bomify_security_vex.md)	 - Manage the VEX documents scan policy rules refer to

