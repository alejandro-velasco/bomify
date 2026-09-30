## bomify package push

Publish a bomify package to an OCI registry

### Synopsis

Push publishes the local package <tag> as an OCI artifact under <tag>,
which must be a full registry reference.

Local vulnerability reports are attached as a separate OCI referrer, so
re-scanning and pushing again refreshes them without changing the
package's digest. Afterwards, all but the newest --keep-reports report
referrers are deleted (best-effort: "bomify security prune" retries if
the registry refuses).

--sign signs the package, and its reports separately, before the tag
moves, so the tag never points at an unsigned package.

--quiet prints only the pinned reference, <repository>@<digest>, with no
progress or info logging.

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

  # Print just the pinned reference, e.g. to publish it
  pinned=$(bomify push registry.example.com/myapp:latest --quiet)
```

### Options

```
  -c, --concurrency int           number of layers to upload concurrently (default 3)
  -h, --help                      help for push
      --keep-reports int          number of newest vulnerability report referrers to keep on the registry after pushing; older ones are deleted (0 keeps them all) (default 1)
  -q, --quiet                     print only the pushed package's pinned reference (<repository>@<digest>), with no progress or informational logging
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

