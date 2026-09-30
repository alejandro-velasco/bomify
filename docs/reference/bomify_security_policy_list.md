## bomify security policy list

List vulnerability scanning policy rules

### Synopsis

List prints every rule recorded in <data-dir>/conf/scan.json. MATCH
prints "*" for a rule that omitted it, meaning it applies to every
package, FAIL-ON prints "-" for a rule that never fails, VEX lists the
names of each rule's stored VEX documents, and ON the lifecycle hooks
it scans at automatically ("-" for none).

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

