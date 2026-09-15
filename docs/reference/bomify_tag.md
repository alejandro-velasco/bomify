## bomify tag

Tag creates a new tag pointing at an existing package

### Synopsis

Tag creates <destination-tag> as an alias for the package that <source-tag> currently resolves to, similar to `docker tag`.

```
bomify tag <source-tag> <destination-tag> [flags]
```

### Options

```
  -h, --help   help for tag
```

### Options inherited from parent commands

```
      --data-dir string   directory to store bomify data (e.g., built packages). default is $HOME/.bomify or the value of the BOMIFY_DATA_DIR environment variable
      --docs-dir string   directory to write documentation to (if empty, no docs are generated)
      --verbose           enable verbose (debug) logging
```

### SEE ALSO

* [bomify](bomify.md)	 - bomify builds packages from CycloneDX SBOMs

