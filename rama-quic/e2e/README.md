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

`interop-common` holds the scenarios once. Each peer project owns only its adapter: how that
implementation is configured, driven and observed. A case that an implementation cannot
express is recorded with its reason rather than skipped silently, so the gaps are visible in
the run output.

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
  test-quic-interop-aioquic` runs `uv sync --frozen` first; the harness also runs it itself if
  the interpreter is missing, and fails with the command to fix it when `uv` is absent.

CI runs all of this in the `test-quic-interop-peers` job on Linux and macOS, on both the
stable toolchain and the pinned MSRV.

## What the shared families cover, and what they do not

The families are `scenario`, `datagram`, `names`, `trust`, `serving`, `resumption`, `keys`,
`migration` and `close`. Each runs in both roles against each peer that can express it.

Known gaps, as of this checkpoint:

- **Migration is observed, not validated.** The migration cases establish that traffic moved
  and kept working, by comparing where the peer saw the datagrams come from. They do not
  establish that the new path was validated. Only the aioquic rama-client role reads a native
  validation verdict for the moved tuple; the rama-server role compares ports rather than
  whole endpoints.
- **`migration-forbidden` and `migration-without-an-identifier`** do not run in every role.
  quiche can withhold an identifier and refuse a move; aioquic can do neither, and Rama's own
  server refusing a move needs an expectation of its own because a peer that moves anyway is
  not answered at its new address. Each is recorded in the run output with its reason.
- **Key updates**: quiche exposes none. aioquic covers both roles through the shared family.
- **TLS keying-material exporters**: neither quiche nor aioquic exposes one, so exporters are
  covered against Quinn only.
- **Native cases still exist** alongside the shared ones where their assertions have no shared
  equivalent yet; they are not duplicates and are not being removed until they do.

## These are peers, not dependencies

Quinn, quiche and aioquic appear here only as independent implementations to test against.
Nothing in them ships in Rama, and nothing here is part of the published crates.
