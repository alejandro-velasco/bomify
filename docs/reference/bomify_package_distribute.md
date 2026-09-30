## bomify package distribute

Publish a locally available package to a remote endpoint

### Synopsis

Distribute publishes each component of the package <tag> to its own
remote endpoint, as opposed to "bomify push", which publishes the
package as one artifact.

Each component's endpoint is the --remote given for its plugin kind,
else the best matching rule from "bomify distribution create".

--check verifies push permission to every resolved endpoint without
publishing anything.

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

