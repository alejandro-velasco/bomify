## bomify trust create

Create or update a signature verification rule

### Synopsis

Create adds a rule requiring packages whose repository starts with
--match (a "/"-separated prefix; omit it to match every package) to
carry a signature that bomify-plugin-<verifier> verifies before "bomify
pull" or "bomify load" restores them. The longest matching --match wins,
and creating a rule for the same --match replaces it.

--option (key=value) is passed to the plugin's verify unparsed, e.g. the
key or identity to trust. --key-option (option=name) instead names a key
from "bomify trust key add"; the plugin receives the stored copy's path
as that option. The same option can't be given both ways.

"--verify" on pull or load overrides every rule, and
"--insecure-skip-verify" bypasses them.

```
bomify trust create <verifier> [flags]
```

### Examples

```
  # Require packages from a team's repositories to be signed with its cosign key
  bomify trust create sigstore --match registry.example.com/team --option key=team.pub

  # Require every package to be signed with the organization's key
  bomify trust create sigstore --option key=org.pub

  # The same, with the key kept in the managed key store
  bomify trust key add org org.pub
  bomify trust create sigstore --key-option key=org
```

### Options

```
  -h, --help                     help for create
      --key-option stringArray   an option=name pair: pass the verifier plugin option=<path of the stored key name> (see "bomify trust key add"; repeatable)
      --match string             apply to packages whose repository starts with this "/"-separated prefix; default applies to every package
      --option stringArray       a key=value option passed through to the verifier plugin (repeatable)
```

### Options inherited from parent commands

```
      --data-dir string   directory to store bomify data (e.g., built packages). default is $HOME/.bomify or the value of the BOMIFY_DATA_DIR environment variable
      --docs-dir string   directory to write documentation to (if empty, no docs are generated)
      --verbose           enable verbose (debug) logging
```

### SEE ALSO

* [bomify trust](bomify_trust.md)	 - Manage signature verification rules for bomify pull and load

