# rama × PHP-FPM via FastCGI

Two end-to-end demos that pair rama's `gateway::fastcgi` with a real PHP-FPM
backend. Both are exercised in CI on `ubuntu-latest` via the shell scripts
checked in here.

| Demo | Transport to php-fpm | Termination | Highlight |
|---|---|---|---|
| [`gateway/`](./gateway/)     | TCP         | HTTPS (rustls self-signed) | Pure reverse-proxy: every URL is forwarded to PHP. |
| [`migration/`](./migration/) | Unix socket | plain HTTP                 | Two endpoints natively in Rust, everything else falls back to PHP. |

## Run locally

You need `php-fpm`, `jq` and `curl` on `PATH`. On Debian/Ubuntu:

```sh
apt-get install -y php-fpm jq curl
```

Each `run.sh` accepts an optional first argument selecting the mode:

| Mode | What it does |
|---|---|
| `test` (default) | Boots the stack, runs `curl` + `jq` assertions, tears it down. This is the CI path. |
| `run`            | Boots the stack and leaves it running so you can poke at it with `curl` / a browser. Ctrl-C tears it down cleanly and prints the workdir path for log inspection. |

The `just` recipes pick the right mode for the intent:

```sh
just example-fastcgi-php-gateway      # interactive (mode=run), gateway only
just example-fastcgi-php-migration    # interactive (mode=run), migration only
just test-fastcgi-php                 # CI-style assertions on both, sequentially
```

Or invoke the scripts directly:

```sh
./examples/gateway/fastcgi-php/gateway/run.sh           # test mode
./examples/gateway/fastcgi-php/gateway/run.sh run       # interactive
./examples/gateway/fastcgi-php/migration/run.sh run
./examples/gateway/fastcgi-php/test.sh                  # both, test mode
./examples/gateway/fastcgi-php/test.sh run              # both, sequentially, interactive
```

Each script exits 0 on success and `77` (POSIX skip code) if a required
dependency is missing, with a clear log line explaining what to install.

## What's being asserted

### gateway

```text
curl ──HTTPS──► rama (self-signed TLS) ──FastCGI/TCP──► php-fpm ──► app.php
```

`app.php` echoes JSON describing what php-fpm received. `run.sh` then asserts
via `jq` that `.source == "php"`, `.method`, `.https == "on"`, `.gateway ==
"CGI/1.1"`, the request URI / query string survive, and a custom request
header is forwarded as `HTTP_X_RAMA_TEST`. Body bytes are echoed back.

### migration

```text
curl ──HTTP──► rama router ─┬─► /api/health, /api/version  (handled in Rust)
                            └─► everything else: FastCGI/Unix ──► php-fpm ──► app.php
```

The PHP backend *also* implements `/api/health` and `/api/version` returning
`"source": "php"` — but the rama router preempts them and the test asserts
`.source == "rust"`. The other routes (`/api/users`, `/`, `/anything`) hit the
FastCGI fallback and the test asserts `.source == "php"`.

## Why two transports?

php-fpm supports both, and so does `rama-fastcgi` (the protocol layer is
transport-agnostic — a `Service<Req, Output = EstablishedClientConnection<IO,
Req>>` for any `IO: AsyncRead + AsyncWrite`). The demos cover both shapes:

- **TCP** (gateway) — most portable, easiest to debug with `socat`/`tcpdump`,
  what you'd use across hosts or in container networks.
- **Unix socket** (migration) — lower-latency local-only IPC, the typical
  production choice when rama and php-fpm run side-by-side.

## Configuration

Both binaries read their wiring from environment variables; see the
module-level docs in [`gateway/main.rs`](./gateway/main.rs) and
[`migration/main.rs`](./migration/main.rs) for the full list.
