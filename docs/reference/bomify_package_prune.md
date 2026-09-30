## bomify package prune

Remove packages not associated with any tag

### Synopsis

Prune removes every manifest, layer, and vulnerability report that no
current tag reaches. A component used by any tagged package is kept.

```
bomify package prune [flags]
```

### Examples

```
  # Remove every untagged manifest, layer, and vulnerability report
  bomify package prune
```

### Options

```
  -h, --help   help for prune
```

### Options inherited from parent commands

```
      --data-dir string   directory to store bomify data (e.g., built packages). default is $HOME/.bomify or the value of the BOMIFY_DATA_DIR environment variable
      --docs-dir string   directory to write documentation to (if empty, no docs are generated)
      --verbose           enable verbose (debug) logging
```

### SEE ALSO

* [bomify package](bomify_package.md)	 - Manage individual bomify packages

