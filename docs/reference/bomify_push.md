## bomify push

Push publishes a bomify package to an OCI registry

### Synopsis

Push packages the SBOM manifest a prior `bomify build` recorded for <tag> (and each component it describes) as an OCI artifact, and publishes it under <tag>. <tag> is both the local bookkeeping key (see `bomify tag`/`bomify packages`) and the destination reference, exactly like `docker push`.

```
bomify push <tag> [flags]
```

### Options

```
  -c, --concurrency int   number of layers to upload concurrently (default 3)
  -h, --help              help for push
```

### Options inherited from parent commands

```
      --data-dir string   directory to store bomify data (e.g., built packages). default is $HOME/.bomify or the value of the BOMIFY_DATA_DIR environment variable
      --docs-dir string   directory to write documentation to (if empty, no docs are generated)
      --verbose           enable verbose (debug) logging
```

### SEE ALSO

* [bomify](bomify.md)	 - bomify builds packages from CycloneDX SBOMs

