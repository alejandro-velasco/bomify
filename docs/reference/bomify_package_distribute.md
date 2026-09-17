## bomify package distribute

Distribute publishes a locally available bomify package to a remote endpoint

### Synopsis

Distribute resolves <tag> to the SBOM manifest a prior `bomify build`/`bomify pull` recorded for it (see `bomify tag`/`bomify packages`) and publishes each component that SBOM describes to a remote endpoint. The endpoint used is chosen per component by its plugin kind: pass one or more `--remote kind=endpoint` (e.g. --remote oci=registry.example.com --remote helm=charts.example.com/helm). A kind with no matching --remote falls back to the data directory's conf/distribution.json.

```
bomify package distribute <tag> [flags]
```

### Options

```
  -c, --concurrency int         number of components to push concurrently (default 1)
  -h, --help                    help for distribute
  -r, --remote stringToString   kind=endpoint remote mapping (repeatable); kinds not given fall back to <data-dir>/conf/distribution.json (default [])
```

### Options inherited from parent commands

```
      --data-dir string   directory to store bomify data (e.g., built packages). default is $HOME/.bomify or the value of the BOMIFY_DATA_DIR environment variable
      --docs-dir string   directory to write documentation to (if empty, no docs are generated)
      --verbose           enable verbose (debug) logging
```

### SEE ALSO

* [bomify package](bomify_package.md)	 - Manage individual bomify packages

