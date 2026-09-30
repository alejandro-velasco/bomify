## bomify package pull

Download a bomify package from an OCI registry

### Synopsis

Pull downloads a bomify package artifact from an OCI registry: its
config (the aggregate SBOM manifest) and each of its layers (the
components that SBOM describes), laying them out in the data
directory exactly as "bomify build" would have. Layers download
concurrently, each with its own progress bar.

The vulnerability reports of the package's newest report referrer (see
"bomify push") are restored to
"<data-dir>/vulnerabilities/<purl-hash>.json", the same path "bomify
security scan" itself would have written them to. Reports are
advisory: if they can't be listed, fetched, or verified, the package is
still restored, and a warning says why its reports weren't.

--verify requires the package to carry a signature the named signing
plugin verifies (see "bomify push --sign"); without it, any "bomify
trust" rule matching <reference> applies instead. Either way, the
signature is checked before anything is written to the data
directory, so a package that fails verification leaves no trace. The
report referrer's own signature is checked the same way before its
reports are restored.
--insecure-skip-verify bypasses a matching trust rule.

--scan <type> scans the package's components fresh — after --verify,
before anything is written — and --fail-on <severity> (with --ignore
and --vex) refuses to restore it if anything at or above it is found,
leaving no trace, as a failed verify does. The fresh reports replace
the ones the package carries. Gating a pull always needs --scan: the
reports a pulled package carries are its publisher's, not a verdict to
trust. A "bomify security policy" rule listing "pull" in its --on does
the same for a matching <reference> without flags; --skip-scan ignores
it. Scanning may need network access (e.g. grype's database, or the
images it scans).

--quiet prints only the restored package's pinned reference,
<repository>@<digest>, on stdout — no progress bars, and no logging but
warnings and errors.

```
bomify package pull <reference> [flags]
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
      --ignore stringArray          a vulnerability ID not to fail on, for this command only (repeatable); requires --fail-on
      --insecure-skip-verify        restore the package without verifying its signature, even if a "bomify trust" rule requires it
  -q, --quiet                       print only the restored package's pinned reference (<repository>@<digest>), with no progress or informational logging
      --scan string                 scan the package's components with the bomify-plugin-<type> scanner first (e.g. grype); overrides a matching "bomify security policy" rule's scanner
      --skip-scan                   don't scan or gate at all, even if a "bomify security policy" rule matching the package says to
      --verify string               require a signature this signing plugin (bomify-plugin-<kind>, e.g. sigstore) verifies, overriding any "bomify trust" rule
      --verify-option stringArray   a key=value option passed through to the --verify plugin (repeatable; e.g. key=cosign.pub)
      --vex stringArray             an OpenVEX, CSAF, or CycloneDX VEX document whose not-affected/fixed statements exempt vulnerabilities from failing (repeatable); added to a matching rule's
```

### Options inherited from parent commands

```
      --data-dir string   directory to store bomify data (e.g., built packages). default is $HOME/.bomify or the value of the BOMIFY_DATA_DIR environment variable
      --docs-dir string   directory to write documentation to (if empty, no docs are generated)
      --verbose           enable verbose (debug) logging
```

### SEE ALSO

* [bomify package](bomify_package.md)	 - Manage individual bomify packages

