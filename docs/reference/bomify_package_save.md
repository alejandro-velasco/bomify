## bomify package save

Save packages to a tarball

### Synopsis

Save packages one or more tagged packages into a single tarball — an
OCI image-layout archive containing each package's manifest and
components, plus a referrer carrying any local vulnerability reports of
its components (see "bomify push") — that
"bomify load" can restore on any machine, with no registry involved. A
component shared by more than one given tag is stored once. Writes to
stdout if --output isn't given.

--sign signs each saved package with a signing plugin, exactly as
"bomify push --sign" would, the signature travelling inside the
tarball for "bomify load --verify" to check.

--scan, --fail-on, --ignore, --vex, and --skip-scan gate each tag
before anything is written, exactly as "bomify push" does, as does a
"bomify security policy" rule listing "push" in its --on.

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
      --fail-on string            fail if any vulnerability is at or above this severity (info, low, medium, high, critical); overrides a matching "bomify security policy" rule's
  -h, --help                      help for save
      --ignore stringArray        a vulnerability ID not to fail on, for this command only (repeatable); requires --fail-on
  -o, --output string             write the tarball here instead of stdout
      --scan string               scan the package's components with the bomify-plugin-<type> scanner first (e.g. grype); overrides a matching "bomify security policy" rule's scanner
      --sign string               sign the package with this signing plugin (bomify-plugin-<kind>, e.g. sigstore), attaching the signature as an OCI referrer
      --sign-option stringArray   a key=value option passed through to the signing plugin (repeatable; e.g. key=cosign.key)
      --skip-scan                 don't scan or gate at all, even if a "bomify security policy" rule matching the package says to
      --vex stringArray           an OpenVEX, CSAF, or CycloneDX VEX document whose not-affected/fixed statements exempt vulnerabilities from failing (repeatable); added to a matching rule's
```

### Options inherited from parent commands

```
      --data-dir string   directory to store bomify data (e.g., built packages). default is $HOME/.bomify or the value of the BOMIFY_DATA_DIR environment variable
      --docs-dir string   directory to write documentation to (if empty, no docs are generated)
      --verbose           enable verbose (debug) logging
```

### SEE ALSO

* [bomify package](bomify_package.md)	 - Manage individual bomify packages

