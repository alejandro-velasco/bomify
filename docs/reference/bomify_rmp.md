## bomify rmp

Remove packages by tag (shorthand for "bomify package remove")

```
bomify rmp <tag>... [flags]
```

### Examples

```
  # Remove a single tagged package
  bomify rmp myapp:latest

  # Remove several at once
  bomify rmp myapp:v1 myapp:v2
```

### Options

```
  -h, --help   help for rmp
```

### Options inherited from parent commands

```
      --data-dir string   directory to store bomify data (e.g., built packages). default is $HOME/.bomify or the value of the BOMIFY_DATA_DIR environment variable
      --docs-dir string   directory to write documentation to (if empty, no docs are generated)
      --verbose           enable verbose (debug) logging
```

### SEE ALSO

* [bomify](bomify.md)	 - bomify builds packages from CycloneDX SBOMs

