## bomify trust key remove

Remove a public key from the managed key store

### Synopsis

Remove drops <name> from <data-dir>/keys/, deleting its stored copy
unless another name refers to the same content. It refuses while any
"bomify trust" rule still refers to <name>, so no rule is left
referring to a key that no longer exists.

```
bomify trust key remove <name> [flags]
```

### Examples

```
  # Remove the key stored as "team"
  bomify trust key remove team
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

* [bomify trust key](bomify_trust_key.md)	 - Manage the public keys trust rules refer to

