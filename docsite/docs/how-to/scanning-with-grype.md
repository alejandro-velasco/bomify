---
icon: lucide/shield-alert
---

# Scanning a package with grype

`bomify security scan` calls a scanning plugin once per component of a
built package and stores one vulnerability report per component.
`bomify-plugin-grype` is the first-party scanner, built on
[grype](https://github.com/anchore/grype). Install it with `bomify plugin
install grype`.

See [`bomify security scan`](../usage/reference/bomify_security_scan.md)
for every flag, and
[the architecture docs](../development/architecture/security-scanning.md)
for how it works.

## 1. Scan a package

The package must exist locally (built, pulled, or loaded):

```sh
bomify build sbom.cdx.json --tag myapp:1.0
bomify security scan grype myapp:1.0 --concurrency 4
```

Each component's report goes to `<data-dir>/vulnerabilities/`, shared by
every package containing that component, alongside any other scanner's
report of it. To scan with several scanners at once, list them:
`bomify security scan grype,trivy myapp:1.0`. Each component goes to
every scanner that supports it, and a component counts as scanned if
any of them did. Components grype doesn't support are skipped, and
listed on stderr: they have no report, so nothing about them can fail a
gate. Add `unscanned` to `--fail-on` (e.g. `--fail-on high,unscanned`)
to fail the scan if any were skipped.

For `generic` components, such as a downloaded binary, grype catalogs the
file bomify pulled with [syft](https://github.com/anchore/syft): a Go or
Rust binary's embedded module list, a Java archive's manifest, or a
well-known binary's version string. A file syft finds nothing in counts
as not scanned, not as clean.

For `oci`/`docker` components, grype catalogs the image with
[syft](https://github.com/anchore/syft) and scans every package inside;
the report lists the affected packages. Images are fetched from the local
Docker/Podman daemon if present, otherwise with `docker login`
credentials, not `bomify login`'s.

## 2. Read the reports

```sh
bomify package vulnerabilities myapp:1.0
bomify package vulnerabilities myapp:1.0 --purl pkg:oci/myapp@1.0
bomify package vulnerabilities myapp:1.0 | jq '.[].vulnerabilities[].id'
```

This prints one JSON array of reports, in SBOM order.

## 3. Fail on severe vulnerabilities

`--fail-on` exits non-zero if anything is at or above a severity (`info`,
`low`, `medium`, `high`, `critical`) and prints what failed. Reports are
written either way.

```sh
bomify security scan grype myapp:1.0 --fail-on high
bomify security scan grype myapp:1.0 --fail-on high --ignore CVE-2024-1234   # this run only
```

To set the bar once, add a policy rule. A scan without `--fail-on` uses
the most specific matching rule; `--skip-gate` ignores it.

```sh
bomify security policy create grype --match registry.example.com/team --fail-on high
bomify security scan grype registry.example.com/team/myapp:1.0   # fails on high and above
```

## 4. Record accepted vulnerabilities with VEX

To accept a vulnerability that doesn't affect your package, record why
in a VEX document (OpenVEX, CSAF, or CycloneDX VEX) rather than ignoring
the ID:

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

Use it for one scan, or store it and attach it to a rule so every scan
uses it. The store keeps its own copy, so re-add the name after editing
the file.

```sh
bomify security scan grype myapp:1.0 --fail-on high --vex myapp.openvex.json

bomify security vex add myapp myapp.openvex.json
bomify security policy create grype --match registry.example.com/team --fail-on high --vex myapp
```

`not_affected` and `fixed` statements exempt the named component (and
subcomponent); a purl without a version covers every version. Each
exemption is logged, and reports still show everything found.

## 5. Gate pushes and pulls

Before a push, scan first:

```sh
bomify security scan grype registry.example.com/team/myapp:1.0 --fail-on high \
  && bomify push registry.example.com/team/myapp:1.0
```

`pull` and `load` can scan a package before tagging it, so a failing
package is never tagged (`bomify package prune` removes what it
downloaded):

```sh
bomify pull registry.example.com/team/myapp:1.0 --scan grype --fail-on high
```

To do this for every pull, add `--on pull` to a rule; `--skip-scan`
skips it for one command. Scanning needs network access (grype's
database, and images), so on an air-gapped machine, scan before saving
instead.

```sh
bomify security policy create grype --match registry.example.com/team --fail-on high --on pull
```

Reports travel with pushed and saved packages. Re-scanning and pushing
again refreshes them without changing the package's digest.

## 6. Publish VEX with a package

Attach your VEX documents (a stored name or a file) when you publish, so
the statements travel with the package:

```sh
bomify push registry.example.com/team/myapp:1.0 --sign sigstore --sign-option key=cosign.key --vex myapp
```

A consumer's `--scan --fail-on` pull honors them only if the pull
verifies signatures and each document's own signature verifies, so sign
them. The consumer's own VEX wins where the two disagree.
