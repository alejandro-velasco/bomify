## bomify security policy list

List vulnerability scanning policy rules

### Synopsis

List prints every rule recorded in <data-dir>/conf/scan.json. MATCH
prints "*" for a rule that omitted it, meaning it applies to every
package, and FAIL-ON prints "-" for a rule that never fails.

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

