## bomify signer remove

Remove a named signer

### Synopsis

Remove deletes <name> from the stored signers. Signatures it already
made are unaffected.

```
bomify signer remove <name> [flags]
```

### Examples

```
  # Remove the "security" signer
  bomify signer remove security
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

* [bomify signer](bomify_signer.md)	 - Manage named signers for bomify push and save

