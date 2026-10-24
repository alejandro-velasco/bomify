## bomify deploy list

List the deployments of a package in an OCI registry

### Synopsis

List reads the package <reference> from its registry, verified as
"bomify pull" would, and prints each of its deployments, as "bomify
build --deployments" packaged them, one row each: its name, its type,
whose plugin generates it, its options, its config and overlays, and the
deployments to apply before it, its templates named by their paths in
the package. A disabled one is marked so. These are the names a
deployment file given to "bomify deploy generate --file" overrides.
Nothing is written.

```
bomify deploy list <reference> [flags]
```

### Examples

```
  # See how a package deploys
  bomify deploy list registry.example.com/team/app:1.0
```

### Options

```
  -h, --help                        help for list
      --insecure-skip-verify        restore the package without verifying its signature or provenance, even if a "bomify trust" rule requires it
      --verify string               require a signature this signing plugin (bomify-plugin-<kind>, e.g. sigstore) verifies, overriding any "bomify trust" rule
      --verify-option stringArray   a key=value option passed through to the --verify plugin (repeatable; e.g. key=cosign.pub)
      --verify-provenance           also require the package's build provenance, attested by a signer the verifying plugin trusts
```

### Options inherited from parent commands

```
      --data-dir string   directory to store bomify data (e.g., built packages). default is $HOME/.bomify or the value of the BOMIFY_DATA_DIR environment variable
      --docs-dir string   directory to write documentation to (if empty, no docs are generated)
      --verbose           enable verbose (debug) logging
```

### SEE ALSO

* [bomify deploy](bomify_deploy.md)	 - Generate deployments of a package in an OCI registry

