# Trust model

What `--verify`, trust rules, scan gates, and published VEX protect
against, and what they don't. How each works is on its own page:
[Signing and verification](signing.md), [Build provenance](provenance.md),
and [Security scanning](security-scanning.md).

Throughout, you trust the bomify binary, the plugins you installed, your
data directory, and the identities your trust rules name. Anyone who can
push to a repository is not trusted.

## Signature verification

A reference is verified when `pull`/`load` get `--verify <plugin>`, or
when a `bomify trust` rule matches it (the most specific wins).

**Guarantees:**

- Before the package's signatures verify, bomify fetches only its
  manifest and signature referrers. If they don't, the command fails
  with nothing written.
- A rule with several signers needs a signature each of them, or its
  `--require` count of them, verifies. Each signer is checked with its
  own options, so one key can't stand in for another's signer unless
  both rules name it.
- The signature covers the manifest digest, which pins the SBOM and
  every layer. Each blob is checked against its digest as it streams,
  and everything is fetched by the verified descriptor, so re-tagging
  the reference mid-pull can't substitute content.
- Which signers count is up to the plugin's options, e.g. a key, or a
  keyless certificate's identity and issuer.

**Doesn't:**

- With no `--verify` and no matching rule, nothing is verified, and an
  unsigned package pulls like any other. `--insecure-skip-verify`
  overrides a rule, with a warning, and drops the provenance requirement
  and publisher VEX with it.
- A signature binds the manifest, not the tag or repository. Anyone who
  can push can point the tag at any other package the same signer
  signed, such as an older, vulnerable version. Pull by digest, or gate
  on a fresh scan, where that matters.
- A signature says who published a package, not that it's safe.

## Referrers

A pull trusts each kind of referrer differently:

| Referrer | Trusted when | Otherwise |
| --- | --- | --- |
| Signatures | One verifies for each signer the reference needs (see above). | Ignored. |
| Provenance | Required by `--verify-provenance` or the rule, signed, and passes the checks in [Build provenance](provenance.md#verifying). Unsigned provenance never counts. | Not read. |
| Vulnerability reports | Restored after the newest one verifies, or unverified when the pull verifies nothing. | Skipped with a warning. |
| VEX | The pull verifies, and the document's own signature does too. | Ignored with a warning. |

Restored reports are only information: nothing gates on them (see
[Pull and load gates](#pull-and-load-gates)). Only the newest reports
referrer is considered, so anyone who can push can stop a verified pull
from restoring reports, but not forge them.

## Publisher VEX

VEX only ever exempts findings, so a publisher's documents count only
on a verified pull, and only each one that's signed by a trusted
signer. Push access alone can't silence a finding.

The consumer's own VEX, from the matching scan policy rule, is applied
after the publisher's, so it wins where they disagree. Publisher VEX
applies to that pull's gate only and is never stored.

**Doesn't:** trusting a signer means trusting its VEX. A trusted
publisher can exempt any finding in its own packages, unless the
consumer's VEX says otherwise.

## Pull and load gates

`--scan <scanners> --fail-on <conditions>`, or a scan policy rule with
`--on pull`, scans the package fresh, once its layers are written and
before it's tagged. A refused package fails the command untagged, and
`bomify package prune` removes it.

**Guarantees:**

- The gate never trusts the reports a package carries: `--fail-on`
  without a scanner is an error.
- Signatures, and provenance if required, are verified before anything
  else is fetched.
- A component a scanner scans from its files is scanned from the bytes
  bomify pulled and verified.

**Doesn't:**

- A component a scanner scans by purl is looked up, or fetched by the
  scanner itself (e.g. grype pulls an image), not scanned from what
  bomify pulled.
- A scanner finds only what its database knows. A component no scanner
  scanned passes unless the gate includes `unscanned`.

## Provenance

`--verify-provenance`, or a rule's `--require-provenance`, requires a
signed SLSA provenance attestation that bomify built the package's SBOM
(see [Build provenance](provenance.md#verifying)).

**Guarantees:** the attestation is signed by someone one of the
package's trusted signers trusts, names the package manifest, records
bomify as the builder, and matches the package's SBOM. One such
attestation is enough, even where the rule requires several signatures
on the package.

**Doesn't:**

- The builder's identity is the signer's: there's no separate builder
  identity. A keyless signature from CI names the workflow; a key names
  only its holder.
- `resolvedDependencies` isn't checked; the signature already pins every
  component.

## Plugin installation

`bomify plugin install` fails closed: a plugin package installs only if
its signature verifies, or it's named by digest; `--verify=false`
waives that. Each binary must match
the SHA-256 its SBOM declares, and speak the contract versions bomify
needs (see [Plugin installation](plugin-installation.md)).

## Out of scope

- A compromised signing key or OIDC identity, or a trust rule naming the
  wrong signer.
- A malicious plugin you installed: plugins run with your privileges,
  so they can read anything you can, registry credentials included.
- Anyone who can write to your data directory, which holds trust rules,
  stored keys and VEX, reports, and installed plugins.
- Freshness: a registry, or anyone who can push, can serve an older
  signed package (see [Signature verification](#signature-verification)),
  or withhold referrers. A withheld signature or provenance fails the
  pull; withheld VEX only makes a gate stricter.
- What a component contains beyond its digest: bomify checks the bytes
  match what was built, and signs a compromised upstream faithfully.
