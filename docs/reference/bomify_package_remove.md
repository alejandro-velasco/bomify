## bomify package remove

Remove packages by tag

### Synopsis

Remove untags each given <tag> and reclaims any manifest or component
no longer used by a remaining tag. Also available as the top-level
shorthand "bomify rmp".

```
bomify package remove <tag>... [flags]
```

### Examples

```
  # Remove a single tagged package
  bomify package remove myapp:latest

  # Remove several at once
  bomify package remove myapp:v1 myapp:v2
```

### Options

```
  -h, --help   help for remove
```

### Options inherited from parent commands

```
      --data-dir string   directory to store bomify data (e.g., built packages). default is $HOME/.bomify or the value of the BOMIFY_DATA_DIR environment variable
      --docs-dir string   directory to write documentation to (if empty, no docs are generated)
      --verbose           enable verbose (debug) logging
```

### SEE ALSO

* [bomify package](bomify_package.md)	 - Manage individual bomify packages

