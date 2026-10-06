## bomify signer list

List named signers

### Synopsis

List prints every stored signer: its name, signing plugin, and options.

```
bomify signer list [flags]
```

### Examples

```
  # See every stored signer
  bomify signer list
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

* [bomify signer](bomify_signer.md)	 - Manage named signers for bomify push and save

