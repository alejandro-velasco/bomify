## bomify package prune

Remove packages not associated with any tag

### Synopsis

Prune removes every manifest and layer in the data directory that isn't reachable from a tag currently recorded in repositories.json — mirroring `docker image prune`. A component still used by any tagged package, even one also used by an otherwise-unreferenced package, is left alone.

```
bomify package prune [flags]
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

