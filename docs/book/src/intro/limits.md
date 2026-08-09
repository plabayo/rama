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
[`Policy`](https://ramaproxy.org/docs/rama/layer/limit/trait.Policy.html):

- [`ConcurrentPolicy`](https://ramaproxy.org/docs/rama/layer/limit/policy/struct.ConcurrentPolicy.html)
  bounds in-flight inputs (optionally with a backoff);
- [`RatePolicy`](https://ramaproxy.org/docs/rama/layer/limit/policy/struct.RatePolicy.html)
  bounds inputs per second, in one of two modes:
  - `RatePolicy::abort(rate)`: over-budget inputs fail with
    [`RateLimitReached`](https://ramaproxy.org/docs/rama/layer/limit/policy/struct.RateLimitReached.html),
    which carries a `retry_after` duration — for HTTP simply
    `.into_response()` it to get a `429 Too Many Requests` with a
    `Retry-After` header;
  - `RatePolicy::wait(rate)`: over-budget inputs wait for their turn —
    pacing, no error path.

Policies compose: wrap them in `Option` to make them toggleable, combine
them with `Either*`, and scope them with matcher policy maps
(`Vec<(Matcher, Policy)>`) for per-route or per-source rules. Limit
layers also stack — putting a rate limit *outside* a concurrency limit
rejects cheap and early, without consuming a concurrency slot:

```rust,ignore
(
    // at most 100 requests per second ...
    LimitLayer::new(RatePolicy::abort(Rate::per_sec(100))),
    // ... and at most 10 in flight at any moment
    LimitLayer::new(ConcurrentPolicy::max(10)),
)
```

### Per-client fairness

[`KeyedRatePolicy`](https://ramaproxy.org/docs/rama/net/rate/struct.KeyedRatePolicy.html)
(`rama::net::rate`) is the per-key sibling of `RatePolicy`: every key gets
its own lazily-created bucket, stored in a bounded, idle-evicting cache.
Key on the client IP with
[`ClientIpRateKey`](https://ramaproxy.org/docs/rama/net/rate/struct.ClientIpRateKey.html)
(which respects `Forwarded` info over the socket peer address), or on
anything else with a plain closure extractor.

See [/examples/src/http_rate_limit.rs](https://github.com/plabayo/rama/tree/main/examples/src/http_rate_limit.rs)
for all of the above in action, including the matcher policy map and the
429 + `Retry-After` mapping.

## Bandwidth: throttling streams

[`ThrottleLayer`](https://ramaproxy.org/docs/rama/net/stream/layer/struct.ThrottleLayer.html)
(`rama::net::stream::layer`) wraps a connection's IO in a
[`ThrottledIo`](https://ramaproxy.org/docs/rama/net/stream/layer/struct.ThrottledIo.html)
that paces reads and/or writes against a byte-rate bucket:

- read-side throttling back-pressures the peer through transport flow
  control; write-side throttling paces your egress;
- [`ThrottleMode::PerConn`](https://ramaproxy.org/docs/rama/net/stream/layer/enum.ThrottleMode.html)
  gives every connection its own budget, `ThrottleMode::Shared` spends
  all connections holding the handle from one aggregate cap;
- it drops into any transport stack (TCP, TLS-wrapped, proxied bridges),
  exactly like the bytes-tracker layers; an `OutgoingThrottleLayer` covers
  the client-connector side.

```rust,ignore
// pace what we send back at 8 KiB/s per connection
ThrottleLayer::write_only(ThrottleMode::per_conn(Rate::per_sec(kib_u64(8))))
```

See [/examples/src/tcp_listener_layers.rs](https://github.com/plabayo/rama/tree/main/examples/src/tcp_listener_layers.rs).

## Pacing datagrams

[`PacedSink`](https://ramaproxy.org/docs/rama/stream/struct.PacedSink.html)
(`rama::stream`) paces any framed
[`Sink`](https://ramaproxy.org/docs/rama/futures/trait.Sink.html) — a
`ConnectedUdpFramed`, a `UdpFramed`, a unix datagram codec — by each
item's byte cost (or per item, via a cost closure). Items are never
split or dropped: sending stays atomic, the budget is repaid before the
next item is accepted. `Stream` is passed through, so duplex transports
stay bridgeable.

```rust,ignore
let framed = PacedSink::new(
    ConnectedUdpFramed::new(socket, codec),
    Rate::per_sec(mib_u64(10)),
);
```

See [/examples/src/udp_codec.rs](https://github.com/plabayo/rama/tree/main/examples/src/udp_codec.rs).

## On the CLI

The `rama serve` subcommands (echo, fp, http-test, ip, fs, proxy,
discard) expose these as flags:

- `--rate <N>`: requests per second for http-serving commands/modes,
  new connections per second for raw transport ones (0 = no limit);
  http rejections are `429` responses with a `Retry-After` header;
- `--throttle <BYTES_PER_SEC>`: per-connection byte-rate shaping
  (0 = no throttling).

```sh
rama serve echo --bind 127.0.0.1:8080 --rate 100 --throttle 65536
```
