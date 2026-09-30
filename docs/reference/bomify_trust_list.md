## bomify trust list

List signature verification rules

### Synopsis

List prints every trust rule. "*" in MATCH means every package, and
KEY-OPTIONS lists each option=name pair naming a stored key.

```
bomify trust list [flags]
```

### Examples

```
  # See every configured rule
  bomify trust list
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

* [bomify trust](bomify_trust.md)	 - Manage signature verification rules for bomify pull and load

