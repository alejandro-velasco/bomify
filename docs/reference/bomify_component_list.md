## bomify component list

List the components of a package in an OCI registry

### Synopsis

List prints each component of the package <reference>: its name, type,
size in the registry, and purl, which "bomify component pull" takes to
name it.

It reads only the package's manifest, without downloading a layer or
touching the data directory, and verifies nothing: "bomify component
pull" does.

```
bomify component list <reference> [flags]
```

### Examples

```
  # List what a package holds
  bomify component list registry.example.com/llm-serving:1.0

  # List a package by digest
  bomify component list registry.example.com/llm-serving@sha256:abcdef...
```

### Options

```
  -h, --help   help for list
```

### Options inherited from parent commands

```
      --data-dir string   directory to store bomify data (e.g., built packages). default is $HOME/.bomify or the value of the BOMIFY_DATA_DIR environment variable
      --docs-dir string   directory to write documentation to (if empty, no docs are generated)
      --verbose           enable verbose (debug) logging
```

### SEE ALSO

* [bomify component](bomify_component.md)	 - List and pull the components of a package in an OCI registry

