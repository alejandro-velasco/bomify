## bomify deploy

Generate deployments of a package in an OCI registry

### Synopsis

A package's deployments are what deployment tools deploy it with: Helm
values that pin every image to the package's copy by digest, say. Each
deployment medium has a plugin, bomify-plugin-<type>.

### Options

```
  -h, --help   help for deploy
```

### Options inherited from parent commands

```
      --data-dir string   directory to store bomify data (e.g., built packages). default is $HOME/.bomify or the value of the BOMIFY_DATA_DIR environment variable
      --docs-dir string   directory to write documentation to (if empty, no docs are generated)
      --verbose           enable verbose (debug) logging
```

### SEE ALSO

* [bomify](bomify.md)	 - bomify packages, verifies, and ships whole platforms as one OCI artifact
* [bomify deploy generate](bomify_deploy_generate.md)	 - Generate what deployment tools deploy, from a package in an OCI registry

