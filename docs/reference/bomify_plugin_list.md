## bomify plugin list

List installed plugins

### Synopsis

List prints every plugin installed in <data-dir>/plugins. VERSION and
SOURCE show the version and package "bomify plugin install" installed
it from, or "-" for a binary placed there some other way (e.g. "make
install").

```
bomify plugin list [flags]
```

### Examples

```
  # See every installed plugin
  bomify plugin list
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

* [bomify plugin](bomify_plugin.md)	 - Install and list bomify plugins

