## bomify package save

Save packages to a tarball

### Synopsis

Save writes one or more local packages, with their vulnerability
reports and signatures, to a single tarball (an OCI image layout) that
"bomify load" can restore anywhere without a registry. Shared components
are stored once. It writes to stdout unless --output is given.

--sign and --vex work as for "bomify push", and provenance is attached
the same way; all of it travels inside the tarball.

```
bomify package save <tag>... [flags]
```

### Examples

```
  # Save one package to stdout, redirected to a file
  bomify save myapp:latest > packages.tar

  # Save several packages to a file
  bomify save myapp:v1 myapp:v2 --output packages.tar

  # Archive up to 6 layers concurrently
  bomify save myapp:latest --output packages.tar --concurrency 6

  # Sign each saved package with a cosign key
  bomify save myapp:latest --output packages.tar --sign sigstore --sign-option key=cosign.key
```

### Options

```
  -c, --concurrency int           number of layers to archive concurrently (default 3)
  -h, --help                      help for save
  -o, --output string             write the tarball here instead of stdout
      --sign string               sign the package with this signing plugin (bomify-plugin-<kind>, e.g. sigstore), attaching the signature as an OCI referrer
      --sign-option stringArray   a key=value option passed through to the signing plugin (repeatable; e.g. key=cosign.key)
      --vex stringArray           attach this VEX document to the package: a name from "bomify security vex add", or a file (repeatable)
```

### Options inherited from parent commands

```
      --data-dir string   directory to store bomify data (e.g., built packages). default is $HOME/.bomify or the value of the BOMIFY_DATA_DIR environment variable
      --docs-dir string   directory to write documentation to (if empty, no docs are generated)
      --verbose           enable verbose (debug) logging
```

### SEE ALSO

* [bomify package](bomify_package.md)	 - Manage individual bomify packages

