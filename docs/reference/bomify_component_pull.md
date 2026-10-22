## bomify component pull

Pull one component of a package from an OCI registry into a directory

### Synopsis

Pull downloads only the files of the component <component> of the package
<reference> into --output, as they were when the package was built: for a
model, the directory a server loads it from; for an image, its OCI image
layout. --output must be missing or empty, which a volume mounted in a
container is, unless --replace is given: then what it holds is replaced,
once the component has downloaded and verified. A failed pull leaves
--output as it was, so a failed update keeps the old files. Nothing else
is written, and the package is not recorded in the data directory.

<component> is the component's purl, as "bomify component list" prints
it, or its name, alone or as <name>@<version>, when only one component
has it.

--verify requires a signature the named plugin verifies; without it, a
matching "bomify trust" rule applies. The package is verified before
anything is downloaded. --verify-provenance also requires the package's
build provenance, and --insecure-skip-verify bypasses a trust rule. See
"bomify pull" for how they work. Scanning is only available there.

--quiet prints only the package's pinned reference,
<repository>@<digest>, with no progress or info logging.

```
bomify component pull <reference> <component> [flags]
```

### Examples

```
  # See what a package holds, then pull one model into a directory
  bomify component list registry.example.com/llm-serving:1.0
  bomify component pull registry.example.com/llm-serving:1.0 \
      pkg:huggingface/org/model@2db69c1c3e91a05d2c64a3185acfbaf36f744e25 \
      --output /models/model

  # By name, when only one component has it
  bomify component pull registry.example.com/llm-serving:1.0 model --output /models/model

  # Update a directory pulled before to the package's newer version
  bomify component pull registry.example.com/llm-serving:1.1 model --output /models/model --replace

  # Require a signature made with a specific cosign key
  bomify component pull registry.example.com/llm-serving:1.0 model --output /models/model \
      --verify sigstore --verify-option key=cosign.pub
```

### Options

```
  -c, --concurrency int             number of layers to download concurrently (default 3)
  -h, --help                        help for pull
      --insecure-skip-verify        restore the package without verifying its signature or provenance, even if a "bomify trust" rule requires it
  -o, --output string               directory to write the component's files into (must be missing or empty, unless --replace)
  -q, --quiet                       print only the package's pinned reference (<repository>@<digest>), with no progress or informational logging
      --replace                     replace what --output holds, once the component has downloaded and verified
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

* [bomify component](bomify_component.md)	 - List and pull the components of a package in an OCI registry

