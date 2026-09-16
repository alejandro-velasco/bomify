## bomify distribution create

Create or update the default remote endpoint for a plugin kind

### Synopsis

Create sets <kind>'s default remote endpoint in <data-dir>/conf/distribution.json, the file `bomify distribute` falls back to for any kind not given a `--remote kind=endpoint`. Running it again for the same <kind> overwrites its endpoint.

```
bomify distribution create <kind> <endpoint> [flags]
```

### Options

```
  -h, --help   help for create
```

### Options inherited from parent commands

```
      --data-dir string   directory to store bomify data (e.g., built packages). default is $HOME/.bomify or the value of the BOMIFY_DATA_DIR environment variable
      --docs-dir string   directory to write documentation to (if empty, no docs are generated)
      --verbose           enable verbose (debug) logging
```

### SEE ALSO

* [bomify distribution](bomify_distribution.md)	 - Manage default remote endpoints for `bomify distribute`

