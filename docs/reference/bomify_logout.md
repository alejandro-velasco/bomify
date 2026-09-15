## bomify logout

Log out from an OCI registry

### Synopsis

Logout removes stored credentials for an OCI registry (default: docker.io) from the same credential store `docker logout` uses.

```
bomify logout [server] [flags]
```

### Options

```
  -h, --help   help for logout
```

### Options inherited from parent commands

```
      --data-dir string   directory to store bomify data (e.g., built packages). default is $HOME/.bomify or the value of the BOMIFY_DATA_DIR environment variable
      --docs-dir string   directory to write documentation to (if empty, no docs are generated)
      --verbose           enable verbose (debug) logging
```

### SEE ALSO

* [bomify](bomify.md)	 - bomify builds packages from CycloneDX SBOMs

