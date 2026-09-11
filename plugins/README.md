# bomify plugins

Plugins created and supported by the bomify project itself, as opposed to
third-party plugins a user might install separately. Each subdirectory here
is a standalone `bomify-plugin-<kind>` binary implementing the pull/push
contract described in [`internal/plugin`](../internal/plugin) and the
[README](../README.md#plugins).

| Plugin                                       | Kind     | Backing library                                                              |
|-----------------------------------------------|----------|-------------------------------------------------------------------------------|
| [`bomify-plugin-oci`](./bomify-plugin-oci)   | `oci`    | [go-containerregistry/pkg/crane](https://github.com/google/go-containerregistry) |

To add a new one, create `plugins/bomify-plugin-<kind>`, implement `pull`
and `push` per the contract, and add a row above.
