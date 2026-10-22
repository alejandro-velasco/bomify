## bomify component

List and pull the components of a package in an OCI registry

### Synopsis

A package's components are the ones its SBOM describes: each a model, an
image, a chart, or a set of files. These commands work on one package in
a registry without pulling the rest of it.

### Options

```
  -h, --help   help for component
```

### Options inherited from parent commands

```
      --data-dir string   directory to store bomify data (e.g., built packages). default is $HOME/.bomify or the value of the BOMIFY_DATA_DIR environment variable
      --docs-dir string   directory to write documentation to (if empty, no docs are generated)
      --verbose           enable verbose (debug) logging
```

### SEE ALSO

* [bomify](bomify.md)	 - bomify packages, verifies, and ships whole platforms as one OCI artifact
* [bomify component list](bomify_component_list.md)	 - List the components of a package in an OCI registry
* [bomify component pull](bomify_component_pull.md)	 - Pull one component of a package from an OCI registry into a directory

