## bomify distribution list

List remote-endpoint rules

### Synopsis

List prints every distribution rule, sorted by type and match. "*"
means the rule matches any kind or origin there; see "bomify
distribution create" for how rules are ranked.

```
bomify distribution list [flags]
```

### Examples

```
  # See every configured rule
  bomify distribution list
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

* [bomify distribution](bomify_distribution.md)	 - Manage remote-endpoint rules for bomify distribute

