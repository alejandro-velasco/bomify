## bomify trust create

Create or update a signature verification rule

### Synopsis

Create adds a signer to the rule for --match (a "/"-separated prefix
of a package's repository; omit it to match every package), creating the
rule if needed. "bomify pull" and "bomify load" restore a matching
package only if, for each of the rule's signers, one of its signatures
verifies with bomify-plugin-<plugin>. The longest matching --match
wins.

--signer names the signer to add, or to replace if the rule already has
one by that name. Without it, the signer is unnamed ("-" in "bomify
trust list"), so repeating a plain "trust create" replaces the rule's
one signer. Add signers under different names to require several
signatures, e.g. from a release team and a security team, and --require
<k> to accept any k of them instead of all.

An unnamed signer stays when named ones are added: a rule first created
without --signer and then given "--signer security" requires both.
Remove it with "bomify trust remove --signer ''", or create the rule
with names from the start.

--option (key=value) is passed to the plugin's verify unparsed, e.g. the
key or identity to trust. --key-option (option=name) instead names a key
from "bomify trust key add"; the plugin receives the stored copy's path
as that option. The same option can't be given both ways.

--require-provenance also requires the package's build provenance (see
"bomify build --provenance"), attested by someone one of the rule's
signers trusts. --require and --require-provenance apply to the whole
rule, and change only when given.

"--verify" on pull or load overrides every rule, and
"--insecure-skip-verify" bypasses them.

```
bomify trust create <plugin> [flags]
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

  # Also require build provenance attested with that key
  bomify trust create sigstore --key-option key=org --require-provenance

  # Require signatures from both the release and security teams
  bomify trust create sigstore --match registry.example.com/prod --signer release --key-option key=release
  bomify trust create sigstore --match registry.example.com/prod --signer security --key-option key=security

  # Accept any two of three maintainers
  bomify trust create sigstore --match registry.example.com/oss --signer alice --key-option key=alice
  bomify trust create sigstore --match registry.example.com/oss --signer bob --key-option key=bob
  bomify trust create sigstore --match registry.example.com/oss --signer carol --key-option key=carol --require 2
```

### Options

```
  -h, --help                     help for create
      --key-option stringArray   an option=name pair: pass the plugin option=<path of the stored key name> (see "bomify trust key add"; repeatable)
      --match string             apply to packages whose repository starts with this "/"-separated prefix; default applies to every package
      --option stringArray       a key=value option passed through to the plugin (repeatable)
      --require string           how many of the rule's signers must verify: "all", or a number (default "all")
      --require-provenance       also require the package's build provenance, attested by someone one of the rule's signers trusts
      --signer string            the name of the rule's signer to add or replace; default is the rule's unnamed signer
```

### Options inherited from parent commands

```
      --data-dir string   directory to store bomify data (e.g., built packages). default is $HOME/.bomify or the value of the BOMIFY_DATA_DIR environment variable
      --docs-dir string   directory to write documentation to (if empty, no docs are generated)
      --verbose           enable verbose (debug) logging
```

### SEE ALSO

* [bomify trust](bomify_trust.md)	 - Manage signature verification rules for bomify pull and load

