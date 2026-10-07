## bomify login

Log in to an OCI registry, or store credentials for another host

### Synopsis

Login authenticates against an OCI registry (default: docker.io) and
stores the credentials for later build/distribute/pull/push
operations to reuse.

Credentials are stored through <data-dir>/conf/auth.json, in the OS
credential store when one is available. Registries with nothing stored
there fall back to docker login's credentials.

--verify=false stores the credentials without checking them, for a host
that isn't an OCI registry, so plugins can use them there: a Hugging Face
hub (the password is an access token), or an HTTPS server
bomify-plugin-generic downloads from.

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

  # Store a Hugging Face access token for bomify-plugin-huggingface
  echo "$HF_TOKEN" | bomify login huggingface.co -u myuser --password-stdin --verify=false
```

### Options

```
  -h, --help              help for login
  -p, --password string   password (insecure: prefer --password-stdin, or the interactive prompt)
      --password-stdin    read the password from stdin
  -u, --username string   username
      --verify            check the credentials against the server as an OCI registry before storing them; false stores them unchecked, for a host that isn't a registry (default true)
```

### Options inherited from parent commands

```
      --data-dir string   directory to store bomify data (e.g., built packages). default is $HOME/.bomify or the value of the BOMIFY_DATA_DIR environment variable
      --docs-dir string   directory to write documentation to (if empty, no docs are generated)
      --verbose           enable verbose (debug) logging
```

### SEE ALSO

* [bomify](bomify.md)	 - bomify builds packages from CycloneDX SBOMs

