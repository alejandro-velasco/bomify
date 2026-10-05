## bomify sbom compose

Compose one SBOM from several deployment mediums

### Synopsis

Compose merges the SBOMs a composition file lists into one, for
"bomify build" to build as one package. Each source is either a medium,
whose plugin generates an SBOM from the source's options, or an existing
CycloneDX JSON file. The file's own "components" are added too.

Every medium's plugin is found before any runs. Plugins run in the
composition file's directory, so relative paths in options resolve
against it, as "sbom" paths do; each plugin checks its own options.
Each SBOM must follow the SBOM generation contract's output rules, with
no field cyclonedx-go doesn't know.

Components are merged by purl, each recording the sources it came from
in its "land.bomify.compose.sources" property; two sources disagreeing
on the same purl's type, name, version, or hashes is an error. The
result describes the composition itself, by its "name" and "version",
depending on each source's root. The same sources always compose the
same SBOM, so rebuilding it builds the same package.

```
bomify sbom compose <file> [flags]
```

### Examples

```
  # Compose bomify.yaml and build the result
  bomify sbom compose bomify.yaml -o app.cdx.json
  bomify build app.cdx.json --tag myapp:1.4.0

  # bomify.yaml: two charts and a vendored SBOM
  name: myapp
  version: 1.4.0
  sources:
    - name: web
      medium: helm
      options:
        chart: web
        repo: oci://registry.example.com/charts
        version: 2.1.0
        values:
          - values/web.yaml
    - name: db
      medium: helm
      options:
        chart: postgresql
        repo: oci://registry-1.docker.io/bitnamicharts
        version: 15.6.0
    - name: tools
      sbom: vendor/tools.cdx.json
```

### Options

```
  -h, --help            help for compose
  -o, --output string   write the SBOM to this file instead of stdout
```

### Options inherited from parent commands

```
      --data-dir string   directory to store bomify data (e.g., built packages). default is $HOME/.bomify or the value of the BOMIFY_DATA_DIR environment variable
      --docs-dir string   directory to write documentation to (if empty, no docs are generated)
      --verbose           enable verbose (debug) logging
```

### SEE ALSO

* [bomify sbom](bomify_sbom.md)	 - Compose SBOMs from deployment mediums

