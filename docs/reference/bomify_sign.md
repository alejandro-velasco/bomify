## bomify sign

Add signatures to a published package

### Synopsis

Sign signs a package that's already published: <reference> in a
registry, or with --input every package tagged in a "bomify save"
tarball. Only manifests are fetched, never layers, so co-signers can sign
at different times, in different environments, each with only its own
key, for a trust rule requiring several signers.

It signs as --sign and --signer do for "bomify push": the package, and
each of its vulnerability report and VEX referrers, which pulls verify
separately. Signatures already there are kept. Build provenance isn't
attested again: a rule requiring it accepts one trusted attestation.

With --input, the signed tarball is written to --output, or back over
--input if --output isn't given.

```
bomify sign [<reference>] [flags]
```

### Examples

```
  # Add the security team's signature to a package CI already signed
  bomify sign registry.example.com/myapp:1.0 --signer security

  # Sign with a plugin directly
  bomify sign registry.example.com/myapp:1.0 --sign sigstore --sign-option key=security.key

  # Sign every package in a tarball, in place
  bomify sign --input myapp.tar --signer security

  # Write the signed tarball elsewhere
  bomify sign --input myapp.tar --output myapp-signed.tar --signer security
```

### Options

```
  -h, --help                      help for sign
  -i, --input string              sign every package in this "bomify save" tarball instead of a registry reference
  -o, --output string             write the signed tarball here instead of back over --input
      --sign string               sign the package with this signing plugin (bomify-plugin-<kind>, e.g. sigstore), attaching the signature as an OCI referrer
      --sign-option stringArray   a key=value option passed through to the --sign plugin (repeatable; e.g. key=cosign.key)
      --signer stringArray        also sign the package as this signer from "bomify signer create" (repeatable)
```

### Options inherited from parent commands

```
      --data-dir string   directory to store bomify data (e.g., built packages). default is $HOME/.bomify or the value of the BOMIFY_DATA_DIR environment variable
      --docs-dir string   directory to write documentation to (if empty, no docs are generated)
      --verbose           enable verbose (debug) logging
```

### SEE ALSO

* [bomify](bomify.md)	 - bomify builds packages from CycloneDX SBOMs

