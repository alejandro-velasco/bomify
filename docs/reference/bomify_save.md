## bomify save

Save packages to a tarball

### Synopsis

Save packages one or more tagged packages into a single tarball — an
OCI image-layout archive containing each package's manifest and
components, plus any local vulnerability report a component has — that
"bomify load" can restore on any machine, with no registry involved. A
component shared by more than one given tag is stored once. Writes to
stdout if --output isn't given.

--sign signs each saved package with a signing plugin, exactly as
"bomify push --sign" would, the signature travelling inside the
tarball for "bomify load --verify" to check.

```
bomify save <tag>... [flags]
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
  bomify save myapp:latest --output packages.tar --sign cosign --sign-option key=cosign.key
```

### Options

```
  -c, --concurrency int           number of layers to archive concurrently (default 3)
  -h, --help                      help for save
  -o, --output string             write the tarball here instead of stdout
      --sign string               sign the package with this signing plugin (bomify-plugin-<kind>, e.g. cosign), attaching the signature as an OCI referrer
      --sign-option stringArray   a key=value option passed through to the signing plugin (repeatable; e.g. key=cosign.key)
```

### Options inherited from parent commands

```
      --data-dir string   directory to store bomify data (e.g., built packages). default is $HOME/.bomify or the value of the BOMIFY_DATA_DIR environment variable
      --docs-dir string   directory to write documentation to (if empty, no docs are generated)
      --verbose           enable verbose (debug) logging
```

### SEE ALSO

* [bomify](bomify.md)	 - bomify builds packages from CycloneDX SBOMs

