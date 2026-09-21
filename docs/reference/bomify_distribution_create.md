## bomify distribution create

Create or update a remote-endpoint rule

### Synopsis

Create adds a rule to <data-dir>/conf/distribution.json, the file
"bomify distribute" falls back to for any component not given a
matching --remote. A rule matches a component by --type (a plugin
kind, e.g. "oci" or "helm") and/or --match (a "/"-separated prefix of
the component's origin — its plugin's own report of where it comes
from, e.g. "docker.io", "docker.io/myorg", or "docker.io/myorg/myrepo");
either or both can be omitted to widen the rule, down to a single
catch-all rule matching everything. When more than one rule matches a
component, the one with the longer --match wins, and a matching --type
breaks a tie between two equally specific matches. Running create
again for the same --type/--match pair overwrites its endpoint.

A rule with a non-empty --match acts as a mirror, not just a lookup: whatever
of the component's origin comes after the matched prefix is carried
over onto <endpoint>, so distinct repositories under that prefix still
land at distinct destinations instead of all colliding on one endpoint
(e.g. --match docker.io/myorg against origin docker.io/myorg/app
resolves to <endpoint>/app). A rule with no --match has nothing to
carry over, so <endpoint> is used exactly as given — it's up to the
component's own plugin to decide what to publish under it.

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

