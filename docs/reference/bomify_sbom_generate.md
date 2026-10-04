## bomify sbom generate

Generate an SBOM for a deployment medium via its plugin

### Synopsis

Generate runs "bomify-plugin-<medium> sbom generate" with every flag
after <medium> passed through unchanged and stdin, stdout, and stderr
wired straight through; running the plugin directly is equivalent. See
the plugin's --help for its flags. bomify's own flags, such as
--data-dir, must come before <medium>.

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

* [bomify sbom](bomify_sbom.md)	 - Generate and compose SBOMs for deployment mediums

