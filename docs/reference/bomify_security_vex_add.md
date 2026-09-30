## bomify security vex add

Add or replace a VEX document in the managed store

### Synopsis

Add copies the VEX document at <file> — OpenVEX, CSAF, or CycloneDX
VEX — into <data-dir>/vex/ under <name>, for "bomify security policy
create --vex <name>" to refer to. The document is checked first, and
stored by its content hash: later edits to <file> have no effect until
it's added again, so a rule's exemptions only ever change when someone
re-adds its documents, and every scan decision traces back to an exact
document. Adding under an existing <name> replaces it for every rule
that uses it.

"bomify security scan --vex <file>" reads a file directly instead, as
it is at that moment, without the store.

```
bomify security vex add <name> <file> [flags]
```

### Examples

```
  # Store the team's OpenVEX document as "team"
  bomify security vex add team vex/team.openvex.json

  # After editing it, add it again to update every rule using "team"
  bomify security vex add team vex/team.openvex.json
```

### Options

```
  -h, --help   help for add
```

### Options inherited from parent commands

```
      --data-dir string   directory to store bomify data (e.g., built packages). default is $HOME/.bomify or the value of the BOMIFY_DATA_DIR environment variable
      --docs-dir string   directory to write documentation to (if empty, no docs are generated)
      --verbose           enable verbose (debug) logging
```

### SEE ALSO

* [bomify security vex](bomify_security_vex.md)	 - Manage the VEX documents scan policy rules refer to

