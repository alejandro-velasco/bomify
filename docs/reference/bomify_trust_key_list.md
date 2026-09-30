## bomify trust key list

List the public keys in the managed key store

### Synopsis

List prints every stored key: its name, content hash, when it was
added, and the file it was copied from.

```
bomify trust key list [flags]
```

### Examples

```
  # See every stored key
  bomify trust key list
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

* [bomify trust key](bomify_trust_key.md)	 - Manage the public keys trust rules refer to

