# 🚦 Limits: concurrency, rate & bandwidth

Rama gives you three distinct kinds of limits, all composable with the
same [service stack](./service_stack.md) machinery:

1. **Concurrency**: at most _N_ inputs in flight at once;
2. **Rate**: at most _N_ inputs per period ("100 requests per second");
3. **Bandwidth**: at most _N_ bytes per second on a stream (traffic shaping),
   or pacing datagrams at a byte/packet budget.

All three are backed by first-class rama primitives — the rate and
bandwidth ones by one shared sans-IO
[token bucket](https://ramaproxy.org/docs/rama/utils/rate/struct.TokenBucket.html)
(`rama::utils::rate`), which takes time as an argument instead of reading
a clock: `no_std`, deterministic to test, and embeddable in your own
sans-IO state machines.

## Concurrency & rate: the limit layer

[`LimitLayer`](https://ramaproxy.org/docs/rama/layer/struct.LimitLayer.html)
limits any service by a
[`Policy`](https://ramaproxy.org/docs/rama/layer/limit/trait.Policy.html).
Rama ships two:
[`ConcurrentPolicy`](https://ramaproxy.org/docs/rama/layer/limit/policy/struct.ConcurrentPolicy.html)
bounds the number of in-flight inputs (optionally with a backoff), and
[`RatePolicy`](https://ramaproxy.org/docs/rama/layer/limit/policy/struct.RatePolicy.html)
bounds inputs per period. A rate policy runs in one of two modes: an
*abort* mode, where over-budget inputs fail with
[`RateLimitReached`](https://ramaproxy.org/docs/rama/layer/limit/policy/struct.RateLimitReached.html)
(it carries a `retry_after`, and `.into_response()` turns it into a
`429 Too Many Requests` with a `Retry-After` header), and a *wait* mode,
where over-budget inputs are paced instead of rejected.

Policies compose like any other rama building block: wrap one in `Option`
to toggle it, combine variants with the `Either*` combinators, and scope
them per route or per source with matcher policy maps. Limit layers also
stack. Place an aborting rate limit *outside* a concurrency limit to reject
over-budget inputs before they take a concurrency slot. Put a waiting rate
limit outside for the same reason: pacing then happens before admission,
rather than while the input occupies a concurrency slot.

### Per-client fairness

[`KeyedRatePolicy`](https://ramaproxy.org/docs/rama/net/rate/struct.KeyedRatePolicy.html)
(`rama::net::rate`) is the per-key sibling of `RatePolicy`: every key gets
its own lazily-created bucket, stored in a bounded, idle-evicting cache
(size the key bound above your expected client count, so it stays a memory
backstop rather than an availability limit). At capacity, a new key fails
closed instead of evicting a live bucket and resetting its budget. Key on the
client IP with
[`ClientIpRateKey`](https://ramaproxy.org/docs/rama/net/rate/struct.ClientIpRateKey.html)
— it honours `Forwarded` information over the socket peer address and
aggregates IPv6 clients to a `/64` by default, so a single client cannot
escape its bucket by rotating within its allocation. Size aggregation and
capacity together: one `/48` contains 65 536 `/64`s, exactly the default key
capacity. Deployments serving such allocations should use a broader prefix,
raise the key bound, or both. You can also key on anything else with a plain
closure extractor.

See [/examples/src/http_rate_limit.rs](https://github.com/plabayo/rama/tree/main/examples/src/http_rate_limit.rs)
for all of the above in action, including the matcher policy map and the
`429` + `Retry-After` mapping.

## Bandwidth: throttling streams

[`ThrottleLayer`](https://ramaproxy.org/docs/rama/net/stream/layer/struct.ThrottleLayer.html)
(`rama::net::stream::layer`) wraps a connection's IO in a
[`ThrottledIo`](https://ramaproxy.org/docs/rama/net/stream/layer/struct.ThrottledIo.html)
that paces reads and/or writes against a byte-rate bucket. Read-side
throttling back-pressures the peer through transport flow control;
write-side throttling paces your egress.

[`ThrottleMode`](https://ramaproxy.org/docs/rama/net/stream/layer/enum.ThrottleMode.html)
chooses the scope: `PerConn` gives every connection its own budget, while
`Shared` spends one aggregate cap across all connections holding the handle.
When both directions are enabled, `PerConn` gives them independent buckets;
`Shared` makes reads and writes spend that same aggregate budget. Throttling
drops into any transport stack (TCP, TLS-wrapped,
proxied bridges) exactly like the byte-tracker layers, and an
`OutgoingThrottleLayer` covers the client-connector side.

See [/examples/src/tcp_listener_layers.rs](https://github.com/plabayo/rama/tree/main/examples/src/tcp_listener_layers.rs).

## Pacing datagrams

[`PacedSink`](https://ramaproxy.org/docs/rama/stream/struct.PacedSink.html)
(`rama::stream`) paces any framed
[`Sink`](https://ramaproxy.org/docs/rama/futures/trait.Sink.html) — a
`ConnectedUdpFramed`, a `UdpFramed`, a unix datagram codec — by each
item's byte cost, or per item via a cost closure. Items are never split
or dropped: sending stays atomic and the budget is repaid before the next
item is accepted. The `Stream` half is passed through untouched, so duplex
transports stay bridgeable.

See [/examples/src/udp_codec.rs](https://github.com/plabayo/rama/tree/main/examples/src/udp_codec.rs).

## On the CLI

The `rama serve` subcommands (echo, fp, http-test, ip, fs, proxy,
discard) expose these limits as flags:

- `--rate <N>`: requests per second for http-serving commands and modes,
  new TCP/TLS connections per second for the raw transport ones
  (`0` disables it); UDP discard mode rejects this flag because its service
  is one aggregate datagram stream rather than one service call per peer;
  http rejections are `429` responses with a `Retry-After` header;
- `--throttle <BYTES_PER_SEC>`: per-connection byte-rate shaping, applied
  to each direction independently (`0` disables it). UDP discard mode has no
  connection boundary, so its read throttle is one aggregate socket budget.

For the same reason, discard mode's `--concurrent` and `--timeout` settings
apply only to TCP/TLS connections; `--concurrent` is rejected in UDP mode and
the connection timeout is ignored there.
