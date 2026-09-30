## bomify security vex list

List the VEX documents in the managed store

### Synopsis

List prints every stored VEX document: its name, content hash, when it
was added, and the file it was copied from.

```
bomify security vex list [flags]
```

### Examples

```
  # See every stored VEX document
  bomify security vex list
```

### Options

```
  -h, --help   help for list
```

### Options inherited from parent commands

```
      --data-dir string   directory to store bomify data (e.g., built packages). default is $HOME/.bomify or the value of the BOMIFY_DATA_DIR environment variable
      --docs-dir string   directory to write documentation to (if empty, no docs are generated)
      --verbose           enable verbose (debug) logging
```

### SEE ALSO

* [bomify security vex](bomify_security_vex.md)	 - Manage the VEX documents scan policy rules refer to

