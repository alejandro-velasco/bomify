## bomify plugin install

Install a plugin from an OCI registry

### Synopsis

Install downloads the plugin package "<registry>/<name>[:<version>]"
("latest" by default; "<name>@sha256:..." pins a digest) and installs
the binary built for this machine into <data-dir>/plugins as
bomify-plugin-<name>, replacing any earlier install.

A plugin is installed only if something vouches for it, checked before
downloading:
  - its signature, verified by bomify-plugin-sigstore against
    --verify-option (e.g. key=<public key>, or certificate-identity
    and certificate-oidc-issuer) or else the matching "bomify trust"
    rule; or
  - a digest pin, which is how bomify-plugin-sigstore itself is
    installed first, from the digests each release publishes.

Each binary must also match the SHA-256 its SBOM declares, and speak the
plugin contract versions bomify does, as its SBOM records. --verify=false
skips the signature requirement, but not these checks.

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

