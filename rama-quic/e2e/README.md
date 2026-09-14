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

Run one sequence per peer from the repository root:

```
just rama-quic/test-interop-quinn
just rama-quic/test-interop-quiche
just rama-quic/test-interop-aioquic
```

`just rama-quic/qa-interop-lint` runs formatting and Clippy across the shared library and all three
peers; `just rama-quic/test-interop` runs everything in the order CI does.

### What each peer needs

- **Quinn**: a Rust toolchain, nothing else.
- **quiche**: `cmake` and a C++ compiler. Its default features vendor and build BoringSSL, so
  the first build is slow and a missing toolchain fails the build rather than skipping it.
- **aioquic**: [`uv`](https://docs.astral.sh/uv/) on `PATH`. `uv.lock` pins the dependency
  graph and `.python-version` pins the interpreter (CPython 3.12). `just
  rama-quic/test-interop-aioquic` runs `uv sync --frozen` first; the harness also runs it once per
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
- **Two migration cases do not run in every role.** What runs where:

  | case | runs | recorded unsupported |
  | --- | --- | --- |
  | `migration-moves` | every peer, both roles | — |
  | `migration-forbidden` | all three rama-server roles; quiche and Quinn rama-client | aioquic rama-client: its server configuration cannot refuse a move |
  | `migration-without-an-identifier` | quiche rama-client | all three rama-server roles, since Rama issues its own identifiers; Quinn and aioquic rama-client, since each issues its own |

  Each unsupported combination is recorded with its reason, under `--nocapture`.
- **`migration-forbidden` is a violating client.** None of the three peers reads the server's
  `disable_active_migration`, so in the rama-server role each moves against Rama's policy.
  The case observes the moved socket over a bounded interval, then returns the client to the
  original socket and completes the exchange it was holding. What it establishes is an
  absence of arrivals over that interval together with success on the original path; the
  control that ties it to the policy is the run with `with_migration` overridden.
- **Key updates**: quiche exposes none. aioquic covers both roles through the shared family.
- **TLS keying-material exporters**: neither quiche nor aioquic exposes one, so exporters are
  covered against Quinn only.
- **Native cases still exist** alongside the shared ones. Some assert what no shared case
  does yet; others already duplicate one and are waiting on an assertion mapping. None are
  removed until a shared equivalent exists.

## These are peers, not dependencies

Quinn, quiche and aioquic appear here only as independent implementations to test against.
Nothing in them ships in Rama, and nothing here is part of the published crates.
