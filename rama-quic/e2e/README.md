# QUIC interoperability

Rama's QUIC transport run against three independent implementations, through the public API
of the umbrella `rama` crate only. Each peer is a separate cargo project with its own
`Cargo.lock`, so an upstream implementation's dependencies never reach the workspace
resolution, and `cargo test` at the repository root does not reach these.

| directory | peer | how it runs |
| --- | --- | --- |
| `interop-common/` | — | the shared library: scenarios, identities, the deadline and the case registry |
| `quinn-interop/` | [Quinn](https://github.com/quinn-rs/quinn) | in-process, its own rustls |
| `quiche-interop/` | [quiche](https://github.com/cloudflare/quiche) | in-process, driven by hand, vendored BoringSSL |
| `aioquic-interop/` | [aioquic](https://github.com/aiortc/aioquic) | a separate Python process over a real socket |

`interop-common` holds the shared scenarios. A peer project holds its adapter — how that
implementation is configured, driven and observed — and, for now, native cases of its own. A
case that an implementation cannot express is recorded with its reason rather than skipped
silently; that line comes from a passing test, so `cargo test -- --nocapture` is what shows
it.

## Running

One sequence per peer, from the repository root. Each also works from its own directory.

```
just test-quic-interop-quinn
just test-quic-interop-quiche
just test-quic-interop-aioquic
```

`just qa-quic-interop-lint` runs formatting and Clippy across the shared library and all three
peers; `just test-quic-interop` runs everything in the order CI does.

### What each peer needs

- **Quinn**: a Rust toolchain, nothing else.
- **quiche**: `cmake` and a C++ compiler. Its default features vendor and build BoringSSL, so
  the first build is slow and a missing toolchain fails the build rather than skipping it.
- **aioquic**: [`uv`](https://docs.astral.sh/uv/) on `PATH`. `uv.lock` pins the dependency
  graph and `.python-version` pins the interpreter (CPython 3.12). `just
  test-quic-interop-aioquic` runs `uv sync --frozen` first; the harness also runs it once per
  test binary whether or not an environment exists, so one left from an older lockfile cannot
  be used, and fails with the command to fix it when `uv` is absent.

CI runs all of this in the `test-quic-interop-peers` job on Linux and macOS, on both the
stable toolchain and the pinned MSRV.

## What the shared families cover, and what they do not

The families are `scenario`, `datagram`, `names`, `trust`, `serving`, `resumption`, `keys`,
`migration` and `close`. Each runs in both roles against each peer that can express it.

Known gaps, as of this checkpoint:

- **Migration is mostly observed, not validated.** The migration cases establish that
  traffic moved and kept working, by comparing the whole endpoints the peer saw the datagrams
  come from. Only the aioquic rama-client role reads a native validation verdict for the
  moved tuple, and it has a control of its own: the same move under a server that never acts
  on a PATH_RESPONSE carries the traffic and reports the path unvalidated. Every other role
  says nothing about validation, and an address that changed is not a validated path.
- **`migration-without-an-identifier`** does not run in every role. quiche can withhold an
  identifier; Quinn and aioquic issue their own, and so does Rama, so neither side can hold
  one back in the roles where it would matter. Each is recorded with its reason, under
  `--nocapture`.
- **`migration-forbidden` is a violating client.** None of the three peers reads the server's
  `disable_active_migration`, so in the rama-server role each moves against Rama's policy.
  What the case asserts is that the peer sent from the address it moved to, that nothing came
  back there, and that the exchange it was holding completes as soon as it returns to the
  path Rama still holds — counts and traffic, not a wait that ran out.
- **Key updates**: quiche exposes none. aioquic covers both roles through the shared family.
- **TLS keying-material exporters**: neither quiche nor aioquic exposes one, so exporters are
  covered against Quinn only.
- **Native cases still exist** alongside the shared ones. Some assert what no shared case
  does yet; others already duplicate one and are waiting on an assertion mapping. None are
  removed until a shared equivalent exists.

## These are peers, not dependencies

Quinn, quiche and aioquic appear here only as independent implementations to test against.
Nothing in them ships in Rama, and nothing here is part of the published crates.
