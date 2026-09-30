---
icon: lucide/shield-alert
---

# Scanning a package's components with grype

`bomify security scan` resolves a security scanning plugin by name
(not by purl type, since any scanner can in principle scan any
component), asks it which purl types it supports, and calls it once
per supported component of a built package, storing each result as
that component's own vulnerability report. `bomify-plugin-grype` is
bomify's first-party scanner, backed by
[Anchore's grype](https://github.com/anchore/grype).
See [bomify security scan](../usage/reference/bomify_security_scan.md)
for the full flag reference,
[ARCHITECTURE.md](https://github.com/alejandro-velasco/bomify/blob/main/ARCHITECTURE.md#security-scanning)
for how reports are laid out, and
[plugins/README.md](https://github.com/alejandro-velasco/bomify/blob/main/plugins/README.md#bomify-plugin-grype)
for how the plugin itself works.

Requires [`bomify-plugin-grype`](../getting-started/installing-plugins.md)
to be installed (`bomify plugin install grype`).

## 1. Scan a package

The package must already exist locally — built with `bomify build`, or
fetched with `bomify pull`/`bomify load`:

```sh
bomify build sbom.cdx.json --tag myapp:1.0
bomify security scan grype myapp:1.0
```

Each scanned component gets its own CycloneDX vulnerability report at
`<data-dir>/vulnerabilities/<purl-hash>.json`, keyed by the same purl
hash as its pulled layer — so a component two packages share also
shares one report, and scanning either package refreshes it.

## 2. Read the reports back out

```sh
bomify package vulnerabilities myapp:1.0
```

Prints a single JSON array to stdout — one element per scanned
component's report, content unchanged, in the SBOM's own order —
parsable directly with `jq`. A component never scanned (or unsupported
by whatever scanned it) is silently skipped. Narrow it down to
specific components with `--purl`, repeatable:

```sh
bomify package vulnerabilities myapp:1.0 --purl pkg:oci/myapp@1.0

# Pipe straight into jq, e.g. to list every reported vulnerability ID
bomify package vulnerabilities myapp:1.0 | jq '.[].vulnerabilities[].id'
```

## 3. Scan container images, not just named packages

Most purl types (`npm`, `pypi`, `maven`, `apk`, ...) already name one
specific package, so grype matches it directly: the report's metadata
component is that package, and each vulnerability's `affects` points
back at it. An `oci`/`docker` component names a whole image instead —
for those, the plugin catalogs the image with
[Anchore's syft](https://github.com/anchore/syft) first (the same code
path `grype <image>` itself uses), then matches every package it finds
inside. The image stays the report's metadata component, and each
cataloged package grype actually found a vulnerability in becomes one
of the report's top-level components — packages syft found nothing
wrong with aren't carried into the report — with its own
`evidence.occurrences` tracing back to where syft found it (an
apk/dpkg entry, a `package.json`, a jar on disk, ...) and each
vulnerability's `affects` pointing at the specific package(s) affected.

Image pulling for these uses syft's own default source resolution: the
local Docker/Podman daemon if present, otherwise the registry directly
via whatever credentials `docker login`/`crane auth login` populated —
not bomify's own `bomify login` store.

## 4. Scan several components concurrently

```sh
bomify security scan grype myapp:1.0 --concurrency 4
```

## 5. Skip unsupported components

Any component whose purl type isn't in grype's own
`security supported-components` list (roughly: the OS/language
ecosystems grype has a dedicated matcher for, plus `oci`/`docker` —
notably not `generic`, since there's no image or package to look up
for it) is skipped automatically, and gets no report; you don't need to
filter the SBOM yourself first.

## 6. Fail on severe vulnerabilities

By default a scan only records reports. `--fail-on` makes it exit
non-zero — e.g. to stop a CI pipeline — if anything found is at or
above a severity (`info`, `low`, `medium`, `high`, or `critical`),
printing a table of what failed it to stderr. Reports are still
written either way:

```sh
bomify security scan grype myapp:1.0 --fail-on high

# Accept a specific vulnerability, for this scan only
bomify security scan grype myapp:1.0 --fail-on high --ignore CVE-2024-1234
```

A vulnerability counts at the highest severity any of its ratings
gives it; one grype couldn't rate (`unknown`) never fails a scan.

To set the bar once instead of on every command, record it as a policy
rule for the packages it applies to. A scan with no `--fail-on` of its
own uses the most specific matching rule's threshold (rules have no
ignore list: `--ignore` is only ever a one-off for a single command);
`--skip-scan` ignores it:

```sh
bomify security policy create grype --match registry.example.com/team --fail-on high
bomify security policy list
bomify security scan grype registry.example.com/team/myapp:1.0   # fails on high+
```

See [bomify security policy create](../usage/reference/bomify_security_policy_create.md)
for how `--match` works.

## 7. Record accepted vulnerabilities with VEX

When you've established that a vulnerability doesn't affect your
package — the vulnerable code isn't reachable, say — record that in a
VEX document rather than ignoring the ID, so the reason and the exact
component it applies to are written down. bomify reads OpenVEX,
CSAF VEX, and CycloneDX VEX. For example, an OpenVEX document (`myapp.openvex.json`):

```json
{
  "@context": "https://openvex.dev/ns/v0.2.0",
  "@id": "https://example.com/vex/myapp-1",
  "author": "Security Team",
  "timestamp": "2026-09-29T00:00:00Z",
  "version": 1,
  "statements": [
    {
      "vulnerability": { "name": "CVE-2024-1234" },
      "products": [
        {
          "@id": "pkg:oci/myapp@1.0",
          "subcomponents": [{ "@id": "pkg:apk/alpine/openssl@3.1.0-r0" }]
        }
      ],
      "status": "not_affected",
      "justification": "vulnerable_code_not_in_execute_path"
    }
  ]
}
```

Pass it straight to a scan, which reads the file as it is:

```sh
bomify security scan grype myapp:1.0 --fail-on high --vex myapp.openvex.json
```

Or, to apply it to every scan of some packages, store it under a name
and attach that name to a policy rule. The store keeps its own copy, so
the rule keeps working wherever the file goes; after editing the
document, add it again under the same name to update every rule using
it:

```sh
bomify security vex add myapp myapp.openvex.json
bomify security policy create grype --match registry.example.com/team --fail-on high --vex myapp
bomify security vex list
```

`not_affected` and `fixed` statements exempt the vulnerability for the
component (and, if given, subcomponent) they name — a purl with no
version covers every version of that package; each exemption is
logged with its justification. A vulnerability found in several
packages inside an image only stops failing once every one of them is
covered. Reports themselves are unchanged — `bomify package
vulnerabilities` still shows everything the scanner found.

## 8. Gate what you push, and what you pull

Before pushing, just run the scan with a threshold first — `&&` stops
the push if it fails, and the push carries the fresh reports:

```sh
bomify security scan grype registry.example.com/team/myapp:1.0 --fail-on high \
  && bomify push registry.example.com/team/myapp:1.0
```

Pulling is different: scanning afterwards would only gate once the
package is already on disk. `bomify pull` and `bomify load` take
`--scan` and `--fail-on` to scan a package fresh *before* anything of
it is written — a failure leaves nothing behind:

```sh
bomify pull registry.example.com/team/myapp:1.0 --scan grype --fail-on high
```

To do it for every pull without flags, add `--on pull` to a policy rule.
A rule without `--on` only applies to `bomify security scan`:

```sh
bomify security policy create grype --match registry.example.com/team --fail-on high --on pull
```

`--skip-scan` skips a rule's automatic scan for one command. Scanning
at pull or load may need network access (grype's database, or the
images it scans), so leave it off on an air-gapped machine and scan
before saving instead.

## Next steps

- [Distributing a package](distributing-a-package.md) once you're
  satisfied with what the scan turned up.
- [Publishing and pulling packages with an OCI registry](publishing-and-pulling-packages.md)
  or [saving them for an airgapped environment](saving-packages-for-airgapped-environments.md)
  — either one carries a component's scan report along with the rest
  of the package automatically. Re-scanning and pushing again refreshes
  a published package's reports without changing its digest.
- [Building an SBOM from a Helm chart](building-an-sbom-from-a-helm-chart.md)
  as one way to produce an SBOM worth building and scanning in the first
  place.
