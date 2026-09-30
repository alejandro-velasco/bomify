## bomify trust key add

Add or replace a public key in the managed key store

### Synopsis

Add stores a copy of the public key or certificate <file> under <name>,
for "bomify trust create --key-option <option>=<name>". Every PEM block
must be a CERTIFICATE, PUBLIC KEY, or RSA PUBLIC KEY that parses, so
private keys and corrupt files are refused. For other formats (e.g. SSH
keys), use --option with a path instead.

Later edits to <file> have no effect until it's added again. Adding an
existing <name> replaces it for every rule using it, which is how to
rotate a key.

```
bomify trust key add <name> <file> [flags]
```

### Examples

```
  # Store the team's cosign public key as "team"
  bomify trust key add team keys/team.pub

  # Rotate it: every rule using "team" now trusts the new key
  bomify trust key add team keys/team-2026.pub
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

* [bomify trust key](bomify_trust_key.md)	 - Manage the public keys trust rules refer to

