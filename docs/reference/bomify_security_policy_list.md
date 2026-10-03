## bomify security policy list

List vulnerability scanning policy rules

### Synopsis

List prints every scan policy rule. "*" in MATCH means every package.
FAIL-ON lists what fails a matching package: a severity threshold, and
"unscanned" for components no scanner scanned.
"-" means nothing fails it, or no ON hooks.

```
bomify security policy list [flags]
```

### Examples

```
  # See every configured rule
  bomify security policy list
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

* [bomify security policy](bomify_security_policy.md)	 - Manage vulnerability scanning policy rules

