# Early data and HTTP 425

TLS early data (0-RTT) lets a resumed client send before the handshake finishes.
A peer can replay those bytes. Rama keeps three decisions separate: the transport
reports actual early use, the application decides whether to process it, and the
original client's retry policy owns recovery.

Defaults remain handshake-first. The runnable
[`http_early_data` example](https://github.com/plabayo/rama/blob/main/examples/src/http_early_data.rs)
composes an ordinary HTTP/3 client, an HTTP/3 gateway and an HTTP/1 origin:

```text
client -- early request --> gateway -- Early-Data: 1 --> origin
client <------ 425 -------- gateway <------- 425 -------- origin
client -- confirmed retry -> gateway -- unmarked ------> origin processes once
```

Run it with `cargo run -p rama-examples --bin http_early_data --features http-full,boring`,
or use `http-full,rustls,ring` for Rustls. Each terminating hop has its own keys,
tickets and early-data decision. A gateway can forward an early request over an
established or fresh ordinary upstream connection; it does not need upstream 0-RTT.
Responses use 1-RTT keys. Add `-- --incapable-origin` to demonstrate a gateway
waiting for confirmation before forwarding to an origin without Early-Data/425
support; that mode completes without a client retry.

## Original clients

Enable `h3::connection::Config::early_requests` on the existing H3 connector and
finish the ordinary client builder with
`build_client_with_early_data(application_rule, prepare_body)`. This composes one
existing `Retry` owner with `retry::early_data::with_recovery` and the early-send
permit. The connector option alone does not grant request admission.

Automatic early sending requires a safe method, a truly empty body (including no
trailers), a replayable request and no CONNECT protocol extension. At most one
request per resumed connection, normally the one that establishes it, is admitted
early; other pool users wait for authentication and ALPN verification. Responses
also wait.
`DoNotRetry` and `ForbidEarlyData` take precedence.

An actual early request receiving 425 may be retried once on a new stream after
confirmation. The connection can be reused. `EarlyDataAttempt` carries the actual
transport fact; an ordinary 425 with no evidence is returned unchanged. Forwarded
requests never get original-client 425 recovery. TLS rejection is a separate
`EarlyDataRejected` error: recovery retires that early connection and makes one
confirmed attempt. Neither a terminal 425 nor a recognized TLS early rejection
falls through to the application's generic retry rule. Other results use that
rule and its normal retry budget. Compose rules inside this owner instead of
nesting retry loops.

Payloads are allowed by the protocol, but automatic early sending currently stays
bodyless. Independently, `Policy::prepare_body` can decline replay preparation or
supply bounded `CollectOptions` for ordinary payload retries. Data and trailers
are preserved; exceeding the size/time budget streams the complete request once.
`prepare_bodyless` is the conservative convenience policy. The existing default
managed policy still collects without bounds; applications should choose limits.

## Receiving servers and gateways

A native QUIC server opting into early acceptance must set
`TlsOptions::with_early_data(true)` and bind it with
`with_early_data_context(h3_config.early_data_context()?)`. Construction fails
without a context. Both TLS providers bind stable QUIC transport parameters and
application settings to ticket compatibility. The H3 context includes every local
SETTINGS entry, including unknown entries. Any context change conservatively
rejects old early sessions; Rustls also declines ordinary resumption, whereas
Boring can retain ordinary resumption. This compatibility check is not replay
prevention across servers or connections.

Set `h3_config.early_dispatch = true` to dispatch matching, actually early
requests before the client's Finished. Otherwise dispatch waits. Missing or
mismatched contexts also wait. `EarlyDataReceived` is attached only when that
request's stream received early bytes, and remains present after confirmation;
a later ordinary stream on the same connection is unmarked. Existing header,
stream-admission, flow-control and handshake deadlines still apply. Early QPACK
sections requiring instructions may wait for the normal connection driver.

Use ordinary validation middleware for route policy:

- `ValidateRequestHeaderLayer::custom_fn(early_data::require_confirmed)` waits
  for current-hop confirmation and returns 425 for inherited exposure. Here `early_data` is the module under
  `http::layer::validate_request`.
- `EarlyDataReceived::confirmed().await` defers a current-hop decision. Routes
  requiring client authentication must wait. An inherited `Early-Data` field
  cannot be discharged by waiting on this connection.
- `early_data::forward_to(origin_supports_early_data)` returns the existing
  validation layer. Apply it after routing, before the upstream client.

| Incoming request | Origin understands Early-Data/425 | Gateway behavior |
| --- | --- | --- |
| Actual early receipt, handshake pending | Yes | Add `Early-Data: 1`; may forward before confirmation |
| Actual early receipt, already confirmed, no inherited marker | Either | Forward unmarked; forbid upstream early sending |
| Actual early receipt, no inherited marker | No/unknown | Wait, forward unmarked, forbid upstream early sending |
| Inherited marker | Yes | Preserve it and forward |
| Inherited marker | No/unknown | Return 425 without calling the origin |
| Confirmed, unmarked | Either | Forward unmarked; never gain upstream early exposure |

A capable origin must return 425 for exposed requests it cannot safely process.
The gateway passes that response back, including its body and headers. Upstream
early sending is a separate opt-in and requires the forwarding marker for ingress
requests; receipt alone never grants it. A custom gateway bypassing the helper
must add the marker itself whenever it forwards before ingress confirmation,
even if its upstream connection uses ordinary 1-RTT.

Header presence is treated conservatively, including malformed or repeated
values. Request adaptation preserves it across H1/H2/H3 and hop-by-hop cleanup.
These helpers do not sanitize unrelated response fields.

## Supported paths

| Path | Behavior |
| --- | --- |
| Native H3 with Boring or Rustls | Opt-in early send/dispatch, compatibility binding and bounded recovery |
| Composed H3 gateway with H1/H2/H3 upstream | Shared marker and 425 policy; independent upstream transport |
| H1/H2 over TCP TLS | Inherited markers and 425 pass-through; native TCP early sending/acceptance unsupported |
| Paired `Http3MitmRelay` | Handshake-first; downstream SETTINGS depend on established upstream SETTINGS |
| Opaque UDP/QUIC forwarding | Ciphertext passes through; HTTP headers and 425 cannot be inspected |

See [RFC 8470](https://www.rfc-editor.org/rfc/rfc8470.html) for the HTTP contract and
[RFC 9114 §7.2.4.2](https://www.rfc-editor.org/rfc/rfc9114.html#section-7.2.4.2)
for remembered HTTP/3 settings.
