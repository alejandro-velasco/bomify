# Local test registry

A throwaway, TLS-enabled Docker registry (the reference [`registry:3`](https://hub.docker.com/_/registry) implementation, the [CNCF Distribution](https://github.com/distribution/distribution) project) for exercising `bomify build`/`mirror`/`pull` against a real OCI registry without needing an account anywhere. It's TLS-only, deliberately: bomify (and its `oci`/`helm` plugins) never support plain HTTP or skip-verify — see [`plugins/README.md`](../../plugins/README.md) — so this mirrors what you'd actually be pointed at in the real world, self-signed cert and all.

## Quickstart

```sh
make up     # generates ./certs on the host if needed, then `docker compose up -d`
```

This starts a `registry:3` container named `bomify-test-registry`, listening on `https://localhost:5000`, backed by `./data` (gitignored) and `./certs` (gitignored — generated fresh per checkout, never committed since it includes the private key).

Because the cert is self-signed, nothing trusts it by default — bomify, crane, oras, and `docker`/`podman push` will all reject the connection with an "unknown authority" error otherwise. `generate-certs.sh` trusts it for you as its last step, on the first (non-idempotent) run only, via `update-ca-certificates` (Debian/Ubuntu) or `update-ca-trust` (Fedora/RHEL) — the only two it supports. This runs `sudo`, so you'll see (and need to approve) a password prompt.

This script targets Linux only (that includes WSL — bomify running there only needs WSL's own trust store, not Windows'). Running it from Git Bash on native Windows will find MSYS2's own lookalike `update-ca-trust`, which trusts the cert into Git Bash's internal CA bundle only, not the real Windows store bomify.exe reads — the script has no way to tell the difference, so it'll report success without actually being trusted anywhere useful. Use WSL instead if you're on Windows.

Then point bomify at it. [`example.cdx.json`](example.cdx.json) is a minimal one-component SBOM (`alpine:3.20`) for exactly this: `bomify build` pulls it from the real Docker Hub, then `bomify mirror` re-pushes what was pulled into the test registry — `bomify-plugin-oci` names the pushed ref `<remote>/<component-name>:<version>`, so this ends up at `localhost:5000/alpine:3.20`:

```sh
bomify build  example.cdx.json --data-dir ./data-out
bomify mirror example.cdx.json --data-dir ./data-out --remote localhost:5000
```

or drive it directly with `crane`/`oras`/`docker` the same way you would any other registry — once the cert is trusted, `localhost:5000` behaves like any other TLS registry.

When you're done:

```sh
make down     # stops and removes the container; keeps certs/ and data/
make clean    # down, then also wipes certs/ and data/ (any pushed images are gone)
```

## Makefile targets

| Target | Does |
| --- | --- |
| `generate-certs` | Runs [`generate-certs.sh`](generate-certs.sh) on the host (needs bash + openssl) to create `certs/registry.{crt,key}` and trust it system-wide. Idempotent — including no re-trust attempt — unless you pass `--force` to `./generate-certs.sh` directly. |
| `up` | `generate-certs`, then `docker compose up -d`. |
| `down` | `docker compose down`. |
| `clean` | `down`, then `rm -rf certs data`. |

Override the container tool, published port, or container name with env vars: `CONTAINER_TOOL` (default `docker`, e.g. `make up CONTAINER_TOOL=podman`), `PORT` (default `5000`), `NAME` (default `bomify-test-registry`, both read by `docker-compose.yml`).

## Why not just `--insecure`?

Because bomify doesn't have one. Earlier in this project's design, plain HTTP support was deliberately removed from the Helm plugin (and never added anywhere else) so that every plugin's behavior against a real registry matches its behavior here — no separate "local dev" code path to keep in sync with the real one. If you need to test against plain HTTP specifically, that's a gap in bomify itself, not something this test registry works around.
