## bomify distribution create

Create or update a remote-endpoint rule

### Synopsis

Create adds a rule that "bomify distribute" uses for components not
given a matching --remote.

A rule matches by --type (a plugin kind, e.g. "oci"), --match (a
"/"-separated prefix of the component's origin, e.g. "docker.io/myorg"),
both, or neither (a catch-all). The longest --match wins, and a matching
--type breaks ties. Creating a rule again for the same --type and
--match replaces its endpoint.

A rule with --match mirrors: the rest of the origin after the prefix is
appended to <endpoint>, so docker.io/myorg/app resolves to
<endpoint>/app. Without --match, <endpoint> is used as given.

```
bomify distribution create <endpoint> [flags]
```

### Examples

```
  # Fall back to this OCI registry for any OCI component
  bomify distribution create registry.example.com --type oci

  # Mirror anything from docker.io/myorg under a new registry, keeping
  # the rest of each repository's path: docker.io/myorg/app becomes
  # mirror.example.com/myorg/app
  bomify distribution create mirror.example.com/myorg --type oci --match docker.io/myorg

  # Match by origin alone, regardless of plugin kind
  bomify distribution create mirror.example.com --match docker.io

  # A catch-all fallback for anything else
  bomify distribution create fallback.example.com
```

### Options

```
  -h, --help           help for create
      --match string   match components whose origin (repository_url/download_url) starts with this "/"-separated prefix; default matches any origin
      --type string    match components of this plugin kind only (e.g. oci, helm, generic); default matches any kind
```

### Options inherited from parent commands

```
      --data-dir string   directory to store bomify data (e.g., built packages). default is $HOME/.bomify or the value of the BOMIFY_DATA_DIR environment variable
      --docs-dir string   directory to write documentation to (if empty, no docs are generated)
      --verbose           enable verbose (debug) logging
```

### SEE ALSO

* [bomify distribution](bomify_distribution.md)	 - Manage remote-endpoint rules for bomify distribute

