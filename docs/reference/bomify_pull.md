## bomify pull

Download a bomify package from an OCI registry

### Synopsis

Pull downloads a package from an OCI registry into the data directory,
as if it had been built there, along with the newest vulnerability
reports attached to it. Reports are advisory: if they can't be fetched
or verified, the package is still restored, with a warning.

--verify requires a signature the named plugin verifies; without it, a
matching "bomify trust" rule applies. The package is verified before
anything is written. --insecure-skip-verify bypasses a trust rule.

--scan <type> --fail-on <severity> scans the package fresh, after
verification and before anything is written, and refuses it if anything
is at or above <severity>. The two go together. A matching "bomify
security policy" rule with --on pull does the same without flags, and
its stored VEX exempts what it covers; flags override the rule, and
--skip-scan ignores it. Scanning may need network access.

--quiet prints only the package's pinned reference,
<repository>@<digest>, with no progress or info logging.

```
bomify pull <reference> [flags]
```

### Examples

```
  # Pull a tagged reference
  bomify pull registry.example.com/myapp:latest

  # Pull by digest
  bomify pull registry.example.com/myapp@sha256:abcdef...

  # Download up to 6 layers concurrently
  bomify pull registry.example.com/myapp:latest --concurrency 6

  # Require a signature made with a specific cosign key
  bomify pull registry.example.com/myapp:latest --verify sigstore --verify-option key=cosign.pub

  # Print just the pinned reference of what was pulled
  pinned=$(bomify pull registry.example.com/myapp:latest --quiet)
```

### Options

```
  -c, --concurrency int             number of layers to download concurrently (default 3)
      --fail-on string              fail if any vulnerability is at or above this severity (info, low, medium, high, critical); overrides a matching "bomify security policy" rule's
  -h, --help                        help for pull
      --insecure-skip-verify        restore the package without verifying its signature, even if a "bomify trust" rule requires it
  -q, --quiet                       print only the restored package's pinned reference (<repository>@<digest>), with no progress or informational logging
      --scan string                 scan the package with this scanner (e.g. grype) before anything is written, refusing it if --fail-on is met; overrides a matching "bomify security policy" rule's
      --skip-scan                   don't scan or gate at all, even if a "bomify security policy" rule matching the package says to
      --verify string               require a signature this signing plugin (bomify-plugin-<kind>, e.g. sigstore) verifies, overriding any "bomify trust" rule
      --verify-option stringArray   a key=value option passed through to the --verify plugin (repeatable; e.g. key=cosign.pub)
```

### Options inherited from parent commands

```
      --data-dir string   directory to store bomify data (e.g., built packages). default is $HOME/.bomify or the value of the BOMIFY_DATA_DIR environment variable
      --docs-dir string   directory to write documentation to (if empty, no docs are generated)
      --verbose           enable verbose (debug) logging
```

### SEE ALSO

* [bomify](bomify.md)	 - bomify builds packages from CycloneDX SBOMs

