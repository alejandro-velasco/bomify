## bomify plugin list

List installed plugins

### Synopsis

List prints every plugin in <data-dir>/plugins, with the version and
package "bomify plugin install" installed it from, or "-" for one placed
there another way.

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

