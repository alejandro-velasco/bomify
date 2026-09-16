# Local test registry

A throwaway, TLS-enabled Docker registry (the reference [`registry:3`](https://hub.docker.com/_/registry) implementation, the [CNCF Distribution](https://github.com/distribution/distribution) project) for exercising `bomify build`/`distribute`/`pull` against a real OCI registry without needing an account anywhere. It's TLS-only, deliberately: bomify (and its `oci`/`helm` plugins) never support plain HTTP or skip-verify — see [`plugins/README.md`](../../plugins/README.md) — so this mirrors what you'd actually be pointed at in the real world, self-signed cert and all.

## Quickstart

```sh
make up     # generates ./certs on the host if needed, then `docker compose up -d`
```

This starts a `registry:3` container named `bomify-test-registry`, listening on `https://localhost:443` (the standard HTTPS port, so it's reachable as a bare `localhost` with no port at all), backed by `./data` (gitignored) and `./certs` (gitignored — generated fresh per checkout, never committed since it includes the private key).

A bare `localhost` matters more than it might look: `bomify login`/`pull`/`push` (via `oras-go`) always assume https regardless of port, but `bomify build`/`distribute`'s OCI plugin (via `crane`) specifically treats **any** `localhost:<port>` — even `localhost:443` spelled out — as plain HTTP; only a portless `localhost` gets https from it. So if you can't bind host port 443 (it typically needs root on Linux/macOS; Docker Desktop on Windows generally doesn't need anything extra) and override it with `PORT=8443 make up`, only `bomify login`/`pull`/`push` against `localhost:8443` will still work as https — the `build`/`distribute` walkthrough below needs port 443 specifically to behave.

Because the cert is self-signed, nothing trusts it by default — bomify, crane, oras, and `docker`/`podman push` will all reject the connection with an "unknown authority" error otherwise. `generate-certs.sh` trusts it for you as its last step, on the first (non-idempotent) run only, via `update-ca-certificates` (Debian/Ubuntu) or `update-ca-trust` (Fedora/RHEL) — the only two it supports. This runs `sudo`, so you'll see (and need to approve) a password prompt.

This script targets Linux only (that includes WSL — bomify running there only needs WSL's own trust store, not Windows'). Running it from Git Bash on native Windows will find MSYS2's own lookalike `update-ca-trust`, which trusts the cert into Git Bash's internal CA bundle only, not the real Windows store bomify.exe reads — the script has no way to tell the difference, so it'll report success without actually being trusted anywhere useful. Use WSL instead if you're on Windows.

The registry also requires authentication (`generate-htpasswd.sh`, also run by `make up`, generates `auth/htpasswd` for a `testuser`/`testpassword` login — override with the `REGISTRY_USER`/`REGISTRY_PASSWORD` env vars), so `bomify login`/`push`/`pull` can be exercised against a registry that actually checks credentials, not just an anonymous one:

```sh
bomify login localhost -u testuser -p testpassword
```

Then point bomify at it. [`example.cdx.json`](example.cdx.json) is a minimal one-component SBOM (`alpine:3.20`) for exactly this: `bomify build` pulls it from the real Docker Hub, then `bomify distribute` re-pushes what was pulled into the test registry — `bomify-plugin-oci` names the pushed ref `<remote>/<component-name>:<version>`, so this ends up at `localhost/alpine:3.20`:

```sh
bomify build      example.cdx.json --data-dir ./data-out
bomify distribute example.cdx.json --data-dir ./data-out --remote localhost
```

or drive it directly with `crane`/`oras`/`docker` the same way you would any other registry — once the cert is trusted and you're logged in, `localhost` behaves like any other authenticated TLS registry.

```sh
bomify logout localhost
```

When you're done:

```sh
make down     # stops and removes the container; keeps certs/ and data/
make clean    # down, then also wipes certs/ and data/ (any pushed images are gone)
```

## Makefile targets

| Target | Does |
| --- | --- |
| `generate-certs` | Runs [`generate-certs.sh`](generate-certs.sh) on the host (needs bash + openssl) to create `certs/registry.{crt,key}` and trust it system-wide. Idempotent — including no re-trust attempt — unless you pass `--force` to `./generate-certs.sh` directly. |
| `generate-htpasswd` | Runs [`generate-htpasswd.sh`](generate-htpasswd.sh) on the host (needs `htpasswd`, from apache2-utils/httpd-tools) to create `auth/htpasswd` for `REGISTRY_USER`/`REGISTRY_PASSWORD` (default `testuser`/`testpassword`). Idempotent; pass `--force` to `./generate-htpasswd.sh` directly to regenerate. |
| `up` | `generate-certs` and `generate-htpasswd`, then `docker compose up -d`. |
| `down` | `docker compose down`. |
| `clean` | `down`, then `rm -rf certs data auth`. |

Override the container tool, published port, container name, or registry login with env vars: `CONTAINER_TOOL` (default `docker`, e.g. `make up CONTAINER_TOOL=podman`), `PORT` (default `443`), `NAME` (default `bomify-test-registry`, both read by `docker-compose.yml`), `REGISTRY_USER`/`REGISTRY_PASSWORD` (default `testuser`/`testpassword`).

## Why not just `--insecure`?

Because bomify doesn't have one. Earlier in this project's design, plain HTTP support was deliberately removed from the Helm plugin (and never added anywhere else) so that every plugin's behavior against a real registry matches its behavior here — no separate "local dev" code path to keep in sync with the real one. If you need to test against plain HTTP specifically, that's a gap in bomify itself, not something this test registry works around.
