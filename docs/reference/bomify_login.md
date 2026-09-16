## bomify login

Log in to an OCI registry

### Synopsis

Login authenticates against an OCI registry (default: docker.io) and stores the credentials for later build/distribute/pull/push operations to reuse — using the same credential store `docker login` itself reads and writes, so credentials from either tool work for both.

```
bomify login [server] [flags]
```

### Options

```
  -h, --help              help for login
  -p, --password string   password (insecure: prefer --password-stdin, or the interactive prompt)
      --password-stdin    read the password from stdin
  -u, --username string   username
```

### Options inherited from parent commands

```
      --data-dir string   directory to store bomify data (e.g., built packages). default is $HOME/.bomify or the value of the BOMIFY_DATA_DIR environment variable
      --docs-dir string   directory to write documentation to (if empty, no docs are generated)
      --verbose           enable verbose (debug) logging
```

### SEE ALSO

* [bomify](bomify.md)	 - bomify builds packages from CycloneDX SBOMs

