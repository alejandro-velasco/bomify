## bomify package push

Publish a bomify package to an OCI registry

### Synopsis

Push packages the SBOM manifest a prior "bomify build" recorded for
<tag> (and each component it describes) as an OCI artifact, and
publishes it under <tag>. <tag> is both the local bookkeeping key
(see "bomify tag" / "bomify packages") and the destination reference.

Any component with a local vulnerability report from a prior "bomify
security scan" is pushed an extra layer carrying it; a component never
scanned carries none.

--sign signs the pushed package with a signing plugin before <tag> is
updated to point at it, attaching the signature to it as an OCI
referrer. One signature covers the whole package: the SBOM, every
component, and every vulnerability report. See "bomify pull --verify"
and "bomify trust" for checking it.

```
bomify package push <tag> [flags]
```

### Examples

```
  # Push the package tagged myapp:latest to its own registry reference
  bomify push myapp:latest

  # Push using a fully qualified registry reference as the tag
  bomify push registry.example.com/myapp:latest

  # Upload up to 6 layers concurrently
  bomify push myapp:latest --concurrency 6

  # Sign the package with a cosign key while pushing it
  bomify push registry.example.com/myapp:latest --sign sigstore --sign-option key=cosign.key
```

### Options

```
  -c, --concurrency int           number of layers to upload concurrently (default 3)
  -h, --help                      help for push
      --sign string               sign the package with this signing plugin (bomify-plugin-<kind>, e.g. sigstore), attaching the signature as an OCI referrer
      --sign-option stringArray   a key=value option passed through to the signing plugin (repeatable; e.g. key=cosign.key)
```

### Options inherited from parent commands

```
      --data-dir string   directory to store bomify data (e.g., built packages). default is $HOME/.bomify or the value of the BOMIFY_DATA_DIR environment variable
      --docs-dir string   directory to write documentation to (if empty, no docs are generated)
      --verbose           enable verbose (debug) logging
```

### SEE ALSO

* [bomify package](bomify_package.md)	 - Manage individual bomify packages

