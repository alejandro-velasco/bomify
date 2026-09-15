## bomify save

Save packages to a tarball

### Synopsis

Save packages one or more tagged packages into a single tarball — an OCI image-layout archive containing each package's manifest and components — that `bomify load` can restore on any machine, with no registry involved. A component shared by more than one given tag is stored once. Writes to stdout if --output isn't given, mirroring `docker save`.

```
bomify save <tag>... [flags]
```

### Options

```
  -c, --concurrency int   number of layers to archive concurrently (default 3)
  -h, --help              help for save
  -o, --output string     write the tarball here instead of stdout
```

### Options inherited from parent commands

```
      --data-dir string   directory to store bomify data (e.g., built packages). default is $HOME/.bomify or the value of the BOMIFY_DATA_DIR environment variable
      --docs-dir string   directory to write documentation to (if empty, no docs are generated)
      --verbose           enable verbose (debug) logging
```

### SEE ALSO

* [bomify](bomify.md)	 - bomify builds packages from CycloneDX SBOMs

