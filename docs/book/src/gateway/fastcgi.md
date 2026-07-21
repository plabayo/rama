# FastCGI

> FastCGI is a binary protocol for interfacing interactive programs with a web server.
> It improves on CGI by keeping the application process running and reusing it across
> many requests over a persistent TCP or Unix-socket connection.
>
> Source: FastCGI Specification 1.0
> (vendored at `rama-fastcgi/specifications/fastcgi_spec.txt`)

`rama-fastcgi` is exposed in the `rama` meta-crate at `rama::gateway::fastcgi` when
the `fastcgi` feature is enabled. Pair it with the `http` feature for the HTTP
adaptive layers.

## Where it sits

```dot process
digraph {
    pad=0.2;
    rankdir=LR;
    "HTTP client" -> "rama gateway\n(FastCgiHttpClient)" [dir=both];
    "rama gateway\n(FastCgiHttpClient)" -> "FastCGI backend\n(php-fpm / flup / ...)" [dir=both];
    "rama gateway\n(FastCgiHttpClient)" [shape=box, style=filled, fillcolor="#eef"];
    "FastCGI backend\n(php-fpm / flup / ...)" [shape=box];
}
```

The other direction — wrapping a plain HTTP service so it can be served *as* a
FastCGI application — is symmetric:

```dot process
digraph {
    pad=0.2;
    rankdir=LR;
    "Web server\n(nginx / Apache)" -> "rama FastCgiServer\n+ FastCgiHttpService" [dir=both];
    "rama FastCgiServer\n+ FastCgiHttpService" -> "your HTTP service" [dir=both];
    "rama FastCgiServer\n+ FastCgiHttpService" [shape=box, style=filled, fillcolor="#eef"];
    "your HTTP service" [shape=box];
}
```

## Two sides, four pieces

| Piece | Direction | Description |
|---|---|---|
| `FastCgiServer<S>`        | inbound  | Accepts FastCGI connections, dispatches each request to an inner `Service<FastCgiRequest>` |
| `FastCgiHttpService<S>`   | inbound  | Wraps any HTTP `Service<Request>` so it can plug into `FastCgiServer` |
| `FastCgiClient<S>`        | outbound | Wraps a connector, runs the FastCGI exchange |
| `FastCgiHttpClient<S>`    | outbound | Same but takes an HTTP `Request` and returns an HTTP `Response` |

## Common transports

For the everyday case — point the client at a php-fpm-shaped backend over
either TCP or a Unix socket — rama ships two turnkey connectors that plug
straight into `FastCgiClient` / `FastCgiHttpClient`. No custom `Service`
impl needed.

```rust,ignore
use rama::gateway::fastcgi::{FastCgiHttpClient, FastCgiTcpConnector};

// php-fpm at 127.0.0.1:9000, front controller at /var/www/index.php
let client = FastCgiHttpClient::new(FastCgiTcpConnector::php_fpm(
    "127.0.0.1:9000".parse()?,
    "/var/www/index.php",
));
```

Same shape over a Unix socket (Unix-family targets only):

```rust,ignore
use rama::gateway::fastcgi::{FastCgiHttpClient, FastCgiUnixConnector};

let client = FastCgiHttpClient::new(FastCgiUnixConnector::php_fpm(
    "/run/php/php8.3-fpm.sock",
    "/var/www/index.php",
));
```

`php_fpm(target, script)` stages the two CGI params php-fpm needs
(`SCRIPT_FILENAME` set to `script`, `DOCUMENT_ROOT` to its parent dir).
For non-PHP backends, drop the preset and use `new(target)` plus
`.with_param(cgi::REDIRECT_STATUS, "200")` etc. as appropriate.

Both connectors live in `rama-fastcgi`'s default-on `transport` feature.
Disable it (`default-features = false`) if you want the bare protocol
layer and roll your own connector.

## Roles

FastCGI defines three roles in `FCGI_BEGIN_REQUEST`. All three are dispatched to
the inner service; inspect `req.role` to handle each:

- **Responder** — the common case. CGI environment via params, request body via
  stdin, response via stdout. Used by PHP-FPM and most others.
- **Authorizer** — params only, no stdin. A `200` response permits the request;
  any non-200 denies it. `Variable-`-prefixed response headers are forwarded
  by the web server to the downstream handler.
- **Filter** — adds an `FCGI_DATA` stream of file content to be transformed.
  Exposed as `FastCgiRequest.data`. Not surfaced through `FastCgiHttpService` —
  services that need it implement `Service<FastCgiRequest>` directly.

## Graceful by default, opt into strict

`rama-fastcgi` is **proxy-first**: it parses leniently by default (mirroring
nginx / php-fpm behaviour) and applies DoS-resistant caps. Tune via
`ServerOptions` / `ClientOptions`:

- `max_params_bytes` — caps the total `FCGI_PARAMS` size per request (default 1 MiB).
- `max_stdin_bytes` / `max_data_bytes` — optional caps on streaming body input.
- `max_stdout_bytes` / `max_stderr_bytes` (client) — caps the accumulated
  backend response and diagnostic output.
- `read_timeout` / `write_timeout` — applied at the IO layer via
  `rama_core::io::timeout::TimeoutIo`. Catches slow-loris peers.
- `strict_begin_body_size` — reject non-canonical `BEGIN_REQUEST` bodies.
- `respond_cant_mpx_conn` — reply `FCGI_CANT_MPX_CONN` to a second concurrent
  `BEGIN_REQUEST` (the server is single-request-per-connection).

## Beyond the gateway role: as a sub-service

A subtlety many users miss: rama services have the **same signature**
(`Service<Request, Output = Response>`) regardless of whether the request was
received over HTTP/1, HTTP/2, FastCGI, or anything else. Even more,
this service signature is exactly the same regardless if it is a client or a proxy!
That means `rama-fastcgi` is not only useful as the front-of-house gateway — you can also
embed it deep inside an otherwise normal HTTP service stack.

Practical cases this unlocks:

- **Hybrid server, FastCGI for one slice.** Run a regular rama HTTP server, but
  route a subset of paths (e.g. `/admin/{*}` powered by PHP-FPM, or `/legacy/{*}`
  living behind an old FastCGI authorizer) into `FastCgiHttpClient` while the
  rest is served natively. Conditional [service branches](../intro/service_branches.md)
  on path or host make this a few extra lines.

- **Step-by-step migration.** Sitting on a legacy FastCGI stack (PHP, Python
  via flup, Perl, …) that you want to replace with Rust *gradually*? Front it
  with a rama HTTP server, port one endpoint at a time, and route the
  not-yet-ported paths back through `FastCgiHttpClient` to the legacy backend.
  The cutover is gradual and reversible.

- **Re-route from a MITM proxy.** Inside a MITM flow, you can decide
  per-request that certain captured traffic should be answered by a FastCGI
  backend (for fixtures, replay, or policy enforcement) without changing the
  rest of the proxy logic.

- **FastCGI authorizer in front of any service.** `FastCgiClient` with
  `Role::Authorizer` can stand in as a pre-check layer; the inner HTTP service
  only sees requests the authorizer permitted.

In short: think of `FastCgiHttpClient` / `FastCgiHttpService` less as "the
glue at the system edge" and more as "regular rama Services that happen to
talk FastCGI on one side." They compose like any other.

## HTTP ↔ FastCGI conversion

When the `http` feature is enabled, `FastCgiHttpClient` and `FastCgiHttpService`
do the legwork of mapping between HTTP and the CGI environment that backends
expect. The emitted parameter set follows the nginx / php-fpm de-facto contract
(`SCRIPT_NAME`, `REQUEST_URI`, `HTTPS`, `REDIRECT_STATUS`, `GATEWAY_INTERFACE=CGI/1.1`,
`HTTP_*` headers, …). See
[`rama-fastcgi/specifications/nginx_fastcgi_params.md`](https://github.com/plabayo/rama/blob/main/rama-fastcgi/specifications/nginx_fastcgi_params.md)
for the full reference.

Request and response bodies stream through (no in-memory buffering) on the
request side. The response side currently buffers stdout up to
`ClientOptions::max_stdout_bytes` before parsing CGI headers.

## Specifications

Vendored under `rama-fastcgi/specifications/`:

- [`fastcgi_spec.txt`](https://github.com/plabayo/rama/blob/main/rama-fastcgi/specifications/fastcgi_spec.txt) — FastCGI 1.0 (Open Market, 1996).
- [`rfc3875.txt`](https://github.com/plabayo/rama/blob/main/rama-fastcgi/specifications/rfc3875.txt) — the semantics of the name-value pairs FastCGI carries.
- [`nginx_fastcgi_params.md`](https://github.com/plabayo/rama/blob/main/rama-fastcgi/specifications/nginx_fastcgi_params.md) — the de-facto convention guide.

## Examples

**Self-contained, rama-on-both-sides (no external services):**

[`examples/src/fastcgi_reverse_proxy.rs`](https://github.com/plabayo/rama/blob/main/examples/src/fastcgi_reverse_proxy.rs)
demonstrates both sides in one binary: an HTTP echo handler exposed as a
FastCGI backend via `FastCgiHttpService`, and an HTTP reverse proxy in front
of it using `FastCgiHttpClient`.

```sh
cargo run -p rama-examples --bin fastcgi_reverse_proxy --features=http-full,fastcgi
curl -v http://127.0.0.1:62053/hello?foo=bar
```

**Against a real PHP-FPM backend:**

[`examples/src/gateway/fastcgi-php/`](https://github.com/plabayo/rama/tree/main/examples/src/gateway/fastcgi-php)
contains two end-to-end demos exercised by CI on `ubuntu-latest`:

- [`gateway/`](https://github.com/plabayo/rama/tree/main/examples/src/gateway/fastcgi-php/gateway) —
  rama terminates HTTPS (rustls self-signed) and forwards every request to
  php-fpm over **TCP**.
- [`migration/`](https://github.com/plabayo/rama/tree/main/examples/src/gateway/fastcgi-php/migration) —
  rama serves `/api/health` and `/api/version` natively in Rust; everything
  else falls back to php-fpm over a **Unix socket**. The PHP app implements
  the Rust-served routes too, with a payload tag `"source":"php"` that the
  tests assert is never observed — proving the migration boundary.

Each demo ships with a self-contained `run.sh` that boots php-fpm, builds
and starts the rama example, and asserts the round-trip with `curl` + `jq`.

```sh
# install dependencies (Debian/Ubuntu)
apt-get install -y php-fpm jq curl

# run either or both
just example-fastcgi-php-gateway
just example-fastcgi-php-migration
just test-fastcgi-php           # both, sequentially
```

Crate docs: <https://ramaproxy.org/docs/rama/gateway/fastcgi/index.html>
