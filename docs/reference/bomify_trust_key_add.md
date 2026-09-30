## bomify trust key add

Add or replace a public key in the managed key store

### Synopsis

Add copies the PEM file at <file> into <data-dir>/keys/ under <name>,
for "bomify trust create --key-option <option>=<name>" to refer to. Only
public material is accepted: every PEM block must be a CERTIFICATE,
PUBLIC KEY, or RSA PUBLIC KEY that actually parses. A private key is
refused, so a signing key is never copied into the data directory by
mistake (sign with --sign-option instead), and a corrupt or wrong file
fails here rather than on a later pull. Formats other than X.509-style
PEM (e.g. an SSH or minisign public key) can't be stored; pass those
with --option instead.

The key is stored by its content hash: later edits to <file> have no
effect until it's added again, so a rule's trust only changes when
someone re-adds its keys. Adding under an existing <name> replaces it
for every rule that uses it — e.g. to rotate a key.

"--option key=<path>", on "bomify trust create" and as --verify-option,
still reads a key file directly, without the store.

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

