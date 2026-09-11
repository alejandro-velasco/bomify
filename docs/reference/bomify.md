## bomify

bomify builds packages from CycloneDX SBOMs

### Synopsis

bomify is a CLI that consumes a CycloneDX Software Bill of Materials (SBOM)
and builds packages from the components it describes.

```
bomify [flags]
```

### Options

```
      --data-dir string   directory to store bomify data (e.g., built packages) (default "C:\\Users\\aleja\\.bomify")
      --docs-dir string   directory to write documentation to (if empty, no docs are generated)
  -h, --help              help for bomify
      --verbose           enable verbose (debug) logging
```

### SEE ALSO

* [bomify build](bomify_build.md)	 - Build builds the package described by a CycloneDX SBOM
* [bomify completion](bomify_completion.md)	 - Generate the autocompletion script for the specified shell
* [bomify load](bomify_load.md)	 - Load packages from a tarball
* [bomify login](bomify_login.md)	 - Log in to an OCI registry
* [bomify logout](bomify_logout.md)	 - Log out from an OCI registry
* [bomify mirror](bomify_mirror.md)	 - Mirror publishes the packages described by a CycloneDX SBOM to a remote endpoint
* [bomify package](bomify_package.md)	 - Manage individual bomify packages
* [bomify packages](bomify_packages.md)	 - List built packages
* [bomify pull](bomify_pull.md)	 - Pull downloads a bomify package from an OCI registry
* [bomify push](bomify_push.md)	 - Push publishes a bomify package to an OCI registry
* [bomify rmp](bomify_rmp.md)	 - Remove packages by tag (shorthand for `bomify package remove`)
* [bomify save](bomify_save.md)	 - Save packages to a tarball
* [bomify tag](bomify_tag.md)	 - Tag creates a new tag pointing at an existing package
* [bomify version](bomify_version.md)	 - Print version, commit, and build date information

