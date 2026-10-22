## bomify

bomify packages, verifies, and ships whole platforms as one OCI artifact

### Synopsis

bomify packages an entire platform (container images, Helm charts,
models, and files) as one signed, scanned OCI artifact, and delivers it
through any registry or air gap to the tools that deploy it.

A package starts from a CycloneDX SBOM, the platform's bill of
materials, and pins every part by digest. Signatures, vulnerability
reports, and build provenance travel with it, and are checked before a
pull writes anything.

```
bomify [flags]
```

### Examples

```
  # Build a package from an SBOM, then publish it
  bomify build sbom.json --tag myapp:latest
  bomify push myapp:latest

  # See what's built locally
  bomify packages
```

### Options

```
      --data-dir string   directory to store bomify data (e.g., built packages). default is $HOME/.bomify or the value of the BOMIFY_DATA_DIR environment variable
      --docs-dir string   directory to write documentation to (if empty, no docs are generated)
  -h, --help              help for bomify
      --verbose           enable verbose (debug) logging
```

### SEE ALSO

* [bomify build](bomify_build.md)	 - Build the package described by a CycloneDX SBOM
* [bomify completion](bomify_completion.md)	 - Generate the autocompletion script for the specified shell
* [bomify component](bomify_component.md)	 - List and pull the components of a package in an OCI registry
* [bomify load](bomify_load.md)	 - Load packages from a tarball
* [bomify login](bomify_login.md)	 - Log in to an OCI registry, or store credentials for another host
* [bomify logout](bomify_logout.md)	 - Log out from an OCI registry
* [bomify package](bomify_package.md)	 - Manage individual bomify packages
* [bomify packages](bomify_packages.md)	 - List built packages
* [bomify plugin](bomify_plugin.md)	 - Install and list bomify plugins
* [bomify pull](bomify_pull.md)	 - Download a bomify package from an OCI registry
* [bomify push](bomify_push.md)	 - Publish a bomify package to an OCI registry
* [bomify rmp](bomify_rmp.md)	 - Remove packages by tag (shorthand for "bomify package remove")
* [bomify save](bomify_save.md)	 - Save packages to a tarball
* [bomify sbom](bomify_sbom.md)	 - Compose SBOMs from deployment mediums
* [bomify security](bomify_security.md)	 - Security scanning commands
* [bomify sign](bomify_sign.md)	 - Add signatures to a published package
* [bomify signer](bomify_signer.md)	 - Manage named signers for bomify push and save
* [bomify tag](bomify_tag.md)	 - Create a new tag pointing at an existing package
* [bomify trust](bomify_trust.md)	 - Manage signature verification rules for bomify pull and load
* [bomify version](bomify_version.md)	 - Print version, commit, and build date information

