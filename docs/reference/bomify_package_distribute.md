## bomify package distribute

Publish a locally available package to a remote endpoint

### Synopsis

Distribute resolves <tag> to the SBOM manifest a prior "bomify build" or
"bomify pull" recorded for it (see "bomify tag" / "bomify packages")
and publishes each component that SBOM describes to a remote
endpoint.

The endpoint used is chosen per component: pass one or more --remote
kind=endpoint flags (e.g. --remote oci=registry.example.com --remote
helm=charts.example.com/helm) for a quick one-off override by plugin
kind. A kind with no matching --remote falls back to the rules in the
data directory's conf/distribution.json (see "bomify distribution
create"). A rule scoped with --match acts as a mirror: it doesn't just
pick an endpoint, it carries over whatever of the component's origin
came after the matched prefix, so distinct repositories under that
prefix still land at distinct destinations under the mirror instead of
all colliding on one endpoint.

--check verifies push permission to every component's resolved remote —
an inexpensive check each plugin performs itself, without publishing
anything.

```
bomify package distribute <tag> [flags]
```

### Examples

```
  # Distribute myapp:latest using the rules from "bomify distribution create"
  bomify distribute myapp:latest

  # Distribute with explicit per-kind remotes, overriding any rule
  bomify distribute myapp:latest --remote oci=registry.example.com --remote helm=charts.example.com/helm

  # Distribute 4 components concurrently
  bomify distribute myapp:latest --concurrency 4

  # Verify push permission to every component's remote, without publishing anything
  bomify distribute myapp:latest --check
```

### Options

```
      --check                   verify push permission to every component's remote, without publishing anything
  -c, --concurrency int         number of components to push concurrently (default 1)
  -h, --help                    help for distribute
  -r, --remote stringToString   kind=endpoint remote mapping (repeatable); kinds not given fall back to <data-dir>/conf/distribution.json (default [])
```

### Options inherited from parent commands

```
      --data-dir string   directory to store bomify data (e.g., built packages). default is $HOME/.bomify or the value of the BOMIFY_DATA_DIR environment variable
      --docs-dir string   directory to write documentation to (if empty, no docs are generated)
      --verbose           enable verbose (debug) logging
```

### SEE ALSO

* [bomify package](bomify_package.md)	 - Manage individual bomify packages

