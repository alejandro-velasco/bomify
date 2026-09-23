## bomify sbom generate

Generate an SBOM for a deployment medium via its plugin

### Synopsis

Generate delegates entirely to a "bomify-plugin-<medium>" binary's own
"sbom generate" subcommand: bomify only locates the plugin on PATH and
execs it with every flag after <medium> passed through unchanged,
wiring stdin/stdout/stderr straight through. Unlike the component
plugin contract ("bomify build"/"bomify distribute"), bomify neither
parses the plugin's output nor imposes any flags of its own here — see
plugins/SBOM-CONTRACT.md for the (deliberately minimal) contract a
plugin must implement, and the plugin's own --help for what it accepts.

Running "bomify-plugin-<medium> sbom generate <flags>" directly is
exactly equivalent to "bomify sbom generate <medium> <flags>".

```
bomify sbom generate <medium> [flags]
```

### Examples

```
  # Generate an SBOM for a Helm chart
  bomify sbom generate helm --chart postgresql --repo oci://registry-1.docker.io/bitnamicharts --version 15.6.0 --values values.yaml
```

### Options

```
  -h, --help   help for generate
```

### Options inherited from parent commands

```
      --data-dir string   directory to store bomify data (e.g., built packages). default is $HOME/.bomify or the value of the BOMIFY_DATA_DIR environment variable
      --docs-dir string   directory to write documentation to (if empty, no docs are generated)
      --verbose           enable verbose (debug) logging
```

### SEE ALSO

* [bomify sbom](bomify_sbom.md)	 - Generate SBOMs for a deployment medium

