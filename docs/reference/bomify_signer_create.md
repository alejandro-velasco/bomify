## bomify signer create

Create or update a named signer

### Synopsis

Create stores <name> as a way to sign: bomify-plugin-<plugin> with
--option (key=value) passed to its sign unparsed, e.g. the key to sign
with. "bomify push" and "bomify save" sign as it with --signer <name>,
and repeating --signer signs as several signers at once, for a trust
rule requiring more than one. Creating an existing <name> replaces it.

Only options are stored, such as a private key's path, never key
material.

```
bomify signer create <name> <plugin> [flags]
```

### Examples

```
  # Sign as "release" with a cosign key
  bomify signer create release sigstore --option key=release.key

  # A second signer, for a rule requiring both
  bomify signer create security sigstore --option key=security.key

  # Sign a package as both while pushing it
  bomify push registry.example.com/myapp:1.0 --signer release --signer security
```

### Options

```
  -h, --help                 help for create
      --option stringArray   a key=value option passed through to the signing plugin (repeatable)
```

### Options inherited from parent commands

```
      --data-dir string   directory to store bomify data (e.g., built packages). default is $HOME/.bomify or the value of the BOMIFY_DATA_DIR environment variable
      --docs-dir string   directory to write documentation to (if empty, no docs are generated)
      --verbose           enable verbose (debug) logging
```

### SEE ALSO

* [bomify signer](bomify_signer.md)	 - Manage named signers for bomify push and save

