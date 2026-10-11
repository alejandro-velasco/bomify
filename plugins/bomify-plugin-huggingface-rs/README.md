# bomify-plugin-huggingface (Rust)

A Rust port of [`bomify-plugin-huggingface`](../bomify-plugin-huggingface),
built on Hugging Face's own Rust client,
[`hf-hub`](https://github.com/huggingface/hf-hub), so the Hub API and
Xet storage are Hugging Face's code rather than ours. It implements the
same contracts, [component](../contracts/component/v1/CONTRACT.md) and
[SBOM generation](../contracts/sbom/v1/CONTRACT.md), with the same
flags, results, and SBOM, and is an experiment in replacing the Go
plugin.

## Building and testing

```sh
cargo build --release   # target/release/bomify-plugin-huggingface
cargo test
cargo clippy --all-targets
```

Install the binary as `<data-dir>/plugins/bomify-plugin-huggingface` to
use it with bomify in place of the Go plugin.

## What's ours, and what's hf-hub's

hf-hub lists, downloads, and creates repositories, and commits, sending
large files through Xet. This plugin adds what bomify needs on top:

- the contract's commands, flags, and results (`main.rs`);
- purls, hub addresses, and `--remote` (`refs.rs`);
- the token: `$HF_TOKEN`, else `bomify login`'s, else `hf auth login`'s
  (`token.rs`);
- checking each file against the hash the Hub lists, and the tree hash
  (`hub.rs`);
- push's rules: refusing a repository holding other files, skipping
  files already there, and committing on top of a known parent
  (`transfer.rs`);
- the SBOM (`sbom.rs`).

## hf-hub 1.0.0 workarounds

hf-hub 1.0.0 can't give an LFS file's SHA-256, which pull checks
downloads against, push compares to skip unchanged files, and the SBOM
hashes:

- its tree listing reads it from the key `sha256`, but the Hub sends
  `oid`;
- its `get_file_metadata` follows the resolve URL's redirect to the CDN,
  whose answer has no `X-Linked-ETag`.

So `Hub::lfs_sha256` asks the resolve URL itself, without following the
redirect, as `huggingface_hub` does.

## Differences from the Go plugin

- Push doesn't drop files the repository's `.gitignore` excludes:
  hf-hub's commit doesn't expose the preupload's answer about them.
- Push splits large uploads into commits by its own estimate of which
  files go inline, rather than the preupload's answer.
- A commit whose response is lost is retried by hf-hub, and refused
  because the branch has moved; pushing again resumes from there.
