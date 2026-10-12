# bomify-plugin-huggingface

What it does is in [plugins/README.md](../README.md#bomify-plugin-huggingface);
how plugins are built and released, in
[Plugin languages](../README.md#plugin-languages). This covers the code.

```sh
make plugin-huggingface   # into bin/; or: cargo build --release
make test-rust            # cargo fmt --check, clippy, and cargo test
```

## What's ours, and what's hf-hub's

[hf-hub](https://github.com/huggingface/hf-hub) lists, downloads, creates
repositories, and commits, sending large files through Xet. On top, this
crate has:

- `main.rs`: the [component](../contracts/component/v1/CONTRACT.md) and
  [SBOM generation](../contracts/sbom/v1/CONTRACT.md) contracts' commands,
  flags, and results, which a Go plugin would get from `pkg/plugin`;
- `log.rs`: logging to `--log` in bomify's format;
- `refs.rs`: purls, hub addresses, and `--remote`;
- `token.rs`: the token, `$HF_TOKEN`, else `bomify login`'s, else
  `hf auth login`'s;
- `hub.rs`: the Hub, with the requests hf-hub can't make (see below);
- `hash.rs`: checking each file against the hash the Hub lists, and the
  tree hash;
- `transfer.rs`: pull, and push's rules (refusing a repository holding
  other files, skipping files already there, committing on top of a
  known parent);
- `sbom.rs`: the SBOM.

## hf-hub 1.0.0 workarounds

hf-hub 1.0.0 can't give an LFS file's SHA-256, which pull checks
downloads against, push compares to skip unchanged files, and the SBOM
hashes:

- its tree listing reads it from the key `sha256`, but the Hub sends
  `oid`;
- its `get_file_metadata` follows the resolve URL's redirect to the CDN,
  whose answer has no `X-Linked-ETag`.

So `Hub::lfs_sha256` asks the resolve URL itself, without following the
redirect, as `huggingface_hub` does. Drop it once hf-hub reads `oid`.
