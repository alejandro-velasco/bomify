## bomify login

Log in to an OCI registry

### Synopsis

Login authenticates against an OCI registry (default: docker.io) and
stores the credentials for later build/distribute/pull/push
operations to reuse.

```
bomify login [server] [flags]
```

### Examples

```
  # Log in to docker.io, prompting for username and password
  bomify login

  # Log in to a specific registry
  bomify login registry.example.com

  # Log in non-interactively, e.g. from a script or CI pipeline
  echo "$PASSWORD" | bomify login registry.example.com -u myuser --password-stdin
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

