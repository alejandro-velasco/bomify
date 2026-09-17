## bomify package

Manage individual bomify packages

### Options

```
  -h, --help   help for package
```

### Options inherited from parent commands

```
      --data-dir string   directory to store bomify data (e.g., built packages). default is $HOME/.bomify or the value of the BOMIFY_DATA_DIR environment variable
      --docs-dir string   directory to write documentation to (if empty, no docs are generated)
      --verbose           enable verbose (debug) logging
```

### SEE ALSO

* [bomify](bomify.md)	 - bomify builds packages from CycloneDX SBOMs
* [bomify package build](bomify_package_build.md)	 - Build builds the package described by a CycloneDX SBOM
* [bomify package distribute](bomify_package_distribute.md)	 - Distribute publishes a locally available bomify package to a remote endpoint
* [bomify package load](bomify_package_load.md)	 - Load packages from a tarball
* [bomify package manifest](bomify_package_manifest.md)	 - Print a remote package's CycloneDX manifest
* [bomify package prune](bomify_package_prune.md)	 - Remove packages not associated with any tag
* [bomify package pull](bomify_package_pull.md)	 - Pull downloads a bomify package from an OCI registry
* [bomify package push](bomify_package_push.md)	 - Push publishes a bomify package to an OCI registry
* [bomify package remove](bomify_package_remove.md)	 - Remove packages by tag
* [bomify package save](bomify_package_save.md)	 - Save packages to a tarball
* [bomify package tag](bomify_package_tag.md)	 - Tag creates a new tag pointing at an existing package

