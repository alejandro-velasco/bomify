## bomify package tag

Create a new tag pointing at an existing package

### Synopsis

Tag creates <destination-tag> as an alias for the package that
<source-tag> currently resolves to.

```
bomify package tag <source-tag> <destination-tag> [flags]
```

### Examples

```
  # Point a new tag at an existing package
  bomify tag myapp:v1 myapp:latest

  # Re-tag a package under a different repository name
  bomify tag myapp:latest registry.example.com/myapp:latest
```

### Options

```
  -h, --help   help for tag
```

### Options inherited from parent commands

```
      --data-dir string   directory to store bomify data (e.g., built packages). default is $HOME/.bomify or the value of the BOMIFY_DATA_DIR environment variable
      --docs-dir string   directory to write documentation to (if empty, no docs are generated)
      --verbose           enable verbose (debug) logging
```

### SEE ALSO

* [bomify package](bomify_package.md)	 - Manage individual bomify packages

