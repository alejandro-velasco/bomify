## bomify deploy generate

Generate what deployment tools deploy, from a package in an OCI registry

### Synopsis

Generate reads the package <reference> from the registry it will be
deployed from, verifies it as "bomify pull" would, and runs each
deployment in --file through its plugin, writing into --output: one
directory per deployment, named after it, and deployments.json,
recording what each wrote, what it depends on, and what to do with it.
Nothing is deployed, and nothing is written to the data directory.

Each component is pinned by digest in the package's repository, where
every copy of the package holds it, and its tag, where "bomify push"
tagged it, is passed on only if the registry has it: a package copied
another way, or pushed with --skip-component-repositories, has none. To
deploy from a mirror, name the package there.

--output must be missing or empty, unless --replace is given: then what
it holds is replaced, once every deployment has generated. A failed
deployment leaves --output as it was.

--verify, its options, and a matching "bomify trust" rule work as for
"bomify pull"; see there.

```
bomify deploy generate <reference> [flags]
```

### Examples

```
  # Generate the deployments in deploy.yaml for a package in a registry
  bomify deploy generate registry.example.com/team/app:1.0 --file deploy.yaml --output deploy/

  # Regenerate them over what was generated before
  bomify deploy generate registry.example.com/team/app:1.1 --file deploy.yaml --output deploy/ --replace
```

### Options

```
  -f, --file string                 the deployment file: the deployments to generate (required)
  -h, --help                        help for generate
      --insecure-skip-verify        restore the package without verifying its signature or provenance, even if a "bomify trust" rule requires it
  -o, --output string               directory to write into (must be missing or empty, unless --replace)
      --replace                     replace what --output holds, once every deployment has generated
      --verify string               require a signature this signing plugin (bomify-plugin-<kind>, e.g. sigstore) verifies, overriding any "bomify trust" rule
      --verify-option stringArray   a key=value option passed through to the --verify plugin (repeatable; e.g. key=cosign.pub)
      --verify-provenance           also require the package's build provenance, attested by a signer the verifying plugin trusts
```

### Options inherited from parent commands

```
      --data-dir string   directory to store bomify data (e.g., built packages). default is $HOME/.bomify or the value of the BOMIFY_DATA_DIR environment variable
      --docs-dir string   directory to write documentation to (if empty, no docs are generated)
      --verbose           enable verbose (debug) logging
```

### SEE ALSO

* [bomify deploy](bomify_deploy.md)	 - Generate deployments of a package in an OCI registry

