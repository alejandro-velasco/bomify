# bomify-plugin-huggingface

bomify's plugin for [Hugging Face Hub](https://huggingface.co) models. It
implements two contracts:

- **Component** (`component pull|pack`,
  [contract](../contracts/component/v1/CONTRACT.md)): fetches
  `pkg:huggingface/...` models, which bomify packages as
  [ModelPack](https://github.com/modelpack/model-spec), so `pack` gives
  nothing. `bomify build` and `bomify push` call it; you normally don't.
- **SBOM generation** (`sbom generate`,
  [contract](../contracts/sbom/v1/CONTRACT.md)): describes a model from
  the Hub's metadata. List it as a `huggingface` source in a `bomify sbom
  compose` file, or run it yourself.

## Component

`pkg:huggingface/<namespace>/<name>@<commit>` names a model repository at
a commit; a `repository_url` qualifier (or `$HF_ENDPOINT`) names another
hub. The version must be the full 40-character commit hash, so every pull
gets the same files. Datasets, Spaces, and subpaths aren't supported.

**pull** downloads every file and checks it against the hash the Hub
lists. `--check` lists the files and resolves one, without downloading.

The hash is the SHA-256 of the sorted `sha256sum` listing of every file,
so an SBOM author can compute it from a download (after `hf download
--local-dir model`, remove `model/.cache` first):

```sh
cd model && find . -type f -print0 | LC_ALL=C sort -z | xargs -0 sha256sum --text | sha256sum
```

## SBOM generation

List the model as a `medium: huggingface` source in a
[`bomify sbom compose`](../../docs/reference/bomify_sbom_compose.md) file:

```yaml
sources:
  - name: model
    medium: huggingface
    options:
      model: microsoft/phi-4   # <namespace>/<name>, required
      revision: main           # branch, tag, or commit; main by default
      # repository-url: https://hub.example.com   # another hub
```

The component is pinned to the commit the revision resolves to, with the
hash above, computed from the Hub's listing without downloading the
weights. Its `modelCard` records the task, architecture, and training
datasets, as data, since datasets aren't packaged. `sbom generate --help`
lists the options.

## Authentication

`$HF_TOKEN`, else the token `bomify login <host> --verify=false` stored,
else `hf auth login`'s:

```sh
echo "$TOKEN" | bomify login huggingface.co -u <user> --password-stdin --verify=false
```

## Developing

How plugins are built and released is in
[Plugin languages](../README.md#plugin-languages).

```sh
make plugin-huggingface   # into bin/; or: cargo build --release
make test-rust            # cargo fmt --check, clippy, and cargo test
```

## What's ours, and what's hf-hub's

[hf-hub](https://github.com/huggingface/hf-hub) lists and downloads. On
top, this crate has:

- `main.rs`: the [component](../contracts/component/v1/CONTRACT.md) and
  [SBOM generation](../contracts/sbom/v1/CONTRACT.md) contracts' commands,
  flags, and results, which a Go plugin would get from `pkg/plugin`;
- `log.rs`: logging to `--log` in bomify's format;
- `refs.rs`: purls and hub addresses;
- `token.rs`: the token, `$HF_TOKEN`, else `bomify login`'s, else
  `hf auth login`'s;
- `hub.rs`: the Hub, with the requests hf-hub can't make (see below);
- `hash.rs`: checking each file against the hash the Hub lists, and the
  tree hash;
- `transfer.rs`: pull;
- `sbom.rs`: the SBOM.

## hf-hub 1.0.0 workarounds

hf-hub 1.0.0 can't give an LFS file's SHA-256, which pull checks
downloads against and the SBOM hashes:

- its tree listing reads it from the key `sha256`, but the Hub sends
  `oid`;
- its `get_file_metadata` follows the resolve URL's redirect to the CDN,
  whose answer has no `X-Linked-ETag`.

So `Hub::lfs_sha256` asks the resolve URL itself, without following the
redirect, as `huggingface_hub` does. Drop it once hf-hub reads `oid`.
