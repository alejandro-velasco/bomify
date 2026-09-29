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

By default (--verify), a plugin is only installed if something vouches
for it, checked before anything is downloaded:
  - its signature, verified by bomify-plugin-sigstore against the signer
    named by --verify-option (e.g. key=<public key>, or
    certificate-identity and certificate-oidc-issuer for a keyless
    signature), else by the most specific "bomify trust" rule matching
    it; or
  - a reference pinned by digest (<name>@sha256:...), which names
    exactly the content to install — how bomify-plugin-sigstore itself
    gets installed the first time, from the digest published with each
    bomify release.
Anything else is refused. Every plugin binary must also match the
SHA-256 its component declares in the package's SBOM — an integrity
check, not proof of who published it. --verify=false installs without
any of this (a declared checksum that doesn't match still fails).

```
bomify plugin install <name>[:<version>|@<digest>] [flags]
```

### Examples

```
  # Bootstrap: install bomify-plugin-sigstore pinned to the digest a
  # bomify release published for it
  bomify plugin install sigstore@sha256:<digest>

  # Install the latest bomify-plugin-oci (needs a signer configured, e.g.
  # a "bomify trust" rule for its registry)
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

