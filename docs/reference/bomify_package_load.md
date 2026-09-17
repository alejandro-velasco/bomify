## bomify package load

Load packages from a tarball

### Synopsis

Load restores every package a `bomify save` tarball contains into the data directory, exactly as `bomify pull` would have for each, and records each of their tags. Reads from stdin if --input isn't given, mirroring `docker load`.

```
bomify package load [flags]
```

### Options

```
  -c, --concurrency int   number of layers to restore concurrently (default 3)
  -h, --help              help for load
  -i, --input string      read the tarball from here instead of stdin
```

### Options inherited from parent commands

```
      --data-dir string   directory to store bomify data (e.g., built packages). default is $HOME/.bomify or the value of the BOMIFY_DATA_DIR environment variable
      --docs-dir string   directory to write documentation to (if empty, no docs are generated)
      --verbose           enable verbose (debug) logging
```

### SEE ALSO

* [bomify package](bomify_package.md)	 - Manage individual bomify packages

