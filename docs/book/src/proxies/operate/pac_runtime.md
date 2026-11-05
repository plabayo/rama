# PAC runtimes and performance

How to run [PAC](./pac.md) evaluation on hardened hosts, and what each engine
backend costs.

## Hardened runtimes

Enable `js-interpreter` to use PAC without dynamically executable memory:

```toml
rama = { version = "0.5", default-features = false, features = ["pac", "js-interpreter"] }
```

This selects Wasmtime's Pulley interpreter for all `rama-js` users in the
build. Direct crate users can enable `rama-pac/js-interpreter` or
`rama-js/interpreter`. iOS always uses Pulley; other targets default to Winch.

Pulley needs neither `com.apple.security.cs.allow-unsigned-executable-memory`
nor `com.apple.security.cs.allow-jit`, making it suitable for hardened macOS
hosts that cannot have these entitlements. PAC APIs, helpers, and resource
limits stay the same; execution is slower.

**`js-disk-cache` still reduces startup time.** It caches the compiled Pulley
bytecode across launches, not PAC decisions. Configure it before the first
JavaScript initialization. Native and interpreter artifacts can share a trusted
cache root; Wasmtime distinguishes them by compiler configuration and target.

Tests evaluate PAC and interrupt an infinite loop in a hardened macOS
executable signed without entitlements, with and without caching. Separate
tests reject executable-memory publication. Shipping system-extension bundles
still need their own signing and installation validation.

## Performance

On an Apple M4 Max running macOS 26.5.2, Rust 1.98.1, and Wasmtime 49.0.3
(2026-10-16):

| Metric | Winch | Pulley |
| --- | ---: | ---: |
| Engine startup, cache disabled | 172 ms | 859 ms |
| Engine startup, warm cache | 60.8 ms | 48.5 ms |
| Resolver setup + first five requests, warm cache | 15.4 ms | 148 ms |
| Mean request time, cache disabled | 1.29 ms | 12.34 ms |
| p95 request time, cache disabled | 1.80 ms | 17.22 ms |

Pulley was **9.5x slower per request**. Its warm cache made engine startup
**17.7x faster**, but did not speed up script loading or evaluation.

The synthetic enterprise fixture uses five equally weighted routes: local
hosts, intranet domains, private IPv4, a vendor wildcard, and default proxies.
Timings include worker scheduling, PAC helpers, and result parsing; they
exclude network fetching and external DNS. Each value is the median of three
runs, each with 100 warmup requests and 2,000 measured requests. The p95 is the
median of each run's p95. Benchmark your own scripts and traffic mix.

Reproduce the comparison from a checkout:

```sh
just scripts/bench/pac --runs 3 --output /tmp/pac-benchmark.json
```

The runner builds both backends before timing, alternates their order, and
measures fresh processes with disabled, empty, and warm disk caches. OS caches
are not flushed. The JSON records every measurement and the build environment;
local output under `rama-pac/benches/results/` is ignored by Git.
