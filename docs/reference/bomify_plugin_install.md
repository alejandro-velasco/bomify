## bomify plugin install

Install a plugin from an OCI registry

### Synopsis

Install downloads the plugin package "<registry>/<name>:<version>"
(version defaulting to "latest"; "<name>@sha256:..." pins a digest) and
installs the plugin binaries it carries into <data-dir>/plugins, the
only place bomify looks for plugins.

A plugin package is an ordinary bomify package whose SBOM describes
"pkg:bomify-plugin/<kind>" components, typically one per platform
(distinguished by "os"/"arch" purl qualifiers). Install walks those
components and installs, as bomify-plugin-<kind>, each one built for
this machine — replacing any earlier install of the same kind. The
package itself isn't kept as a local package the way "bomify pull"
would keep it.

By default (--verify), every plugin binary must match the SHA-256 its
component declares in the package's SBOM, on top of the digest checks
every pull performs. The package's signature is verified too:
  - by the most specific "bomify trust" rule matching the package, if
    any;
  - otherwise by bomify-plugin-sigstore with --verify-option (e.g.
    key=<public key>), which requires sigstore to be installed already.
Without either, only checksums are verified, with a warning — which is
also how bomify-plugin-sigstore itself gets installed the first time.
--verify=false skips signature verification and no longer requires a
declared checksum (a declared one that doesn't match still fails).

```
bomify plugin install <name>[:<version>|@<digest>] [flags]
```

### Examples

```
  # Install the latest bomify-plugin-oci
  bomify plugin install oci

  # Install a specific version
  bomify plugin install grype:1.12.0

  # Install from another registry, verifying its signature with a cosign key
  bomify plugin install myplugin --registry registry.example.com/plugins --verify-option key=cosign.pub

  # Install without verifying anything beyond the pull's own digest checks
  bomify plugin install oci --verify=false
```

### Options

```
  -c, --concurrency int             number of layers to download concurrently (default 3)
  -h, --help                        help for install
      --registry string             repository prefix plugin packages are pulled from, as <registry>/<name>:<version> (default "ghcr.io/alejandro-velasco/bomify/plugins")
      --verify                      verify plugin binaries' checksums and, when possible, the package's signature (default true)
      --verify-option stringArray   a key=value option passed to bomify-plugin-sigstore to verify the package's signature (repeatable; e.g. key=cosign.pub)
```

### Options inherited from parent commands

```
      --data-dir string   directory to store bomify data (e.g., built packages). default is $HOME/.bomify or the value of the BOMIFY_DATA_DIR environment variable
      --docs-dir string   directory to write documentation to (if empty, no docs are generated)
      --verbose           enable verbose (debug) logging
```

### SEE ALSO

* [bomify plugin](bomify_plugin.md)	 - Install and list bomify plugins

