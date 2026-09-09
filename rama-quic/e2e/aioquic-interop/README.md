# aioquic interoperability

Rama's QUIC transport against [aioquic](https://github.com/aiortc/aioquic), in both roles,
through the public API of the umbrella `rama` crate only.

The project is standalone: it is not a member of the rama workspace and has its own
`Cargo.lock`, so the peer's dependencies never reach the workspace resolution. The peer is a
separate interpreter running `peer/interop_peer.py`, with its own TLS (aioquic on
`cryptography`/OpenSSL), so the only thing the two stacks share is the wire.

## What is covered

`tests/interop.rs` has the handshakes, streams, the two certificate-refusal controls and the
harness's own regressions. `tests/datagrams.rs` has DATAGRAM in both Rama roles: the peer
advertises a small `max_datagram_frame_size`, so what limits a datagram is the value it
advertised rather than the path, and the local outgoing buffer is set small so a test can fill
it deliberately.

`tests/resumption.rs` has resumption and 0-RTT: a client that asked for early data offers it
and the server accepts it, and a client that did not ask still resumes and offers none. Early
data is opt-in in this crate, so the second is the default behaviour rather than a failure.

`tests/keys.rs` has key updates, asked for from each side in turn, with the peer's key phase
read back so the counter is not the only witness, and a control where no update is asked for.
All three have Rama as the client: neither peer covers Rama as the server asking for or
following an update, and quiche exposes no key update at all. Neither peer exposes a TLS
keying-material exporter either, so exporters stay covered against Quinn.

## Prerequisites

- A Rust toolchain.
- [`uv`](https://docs.astral.sh/uv/) on `PATH`.

`uv.lock` pins the dependency graph and `.python-version` pins the interpreter uv selects
(CPython 3.12); `pyproject.toml` requires `>=3.12,<3.13`. uv keeps its download cache and its
managed interpreters outside this directory, so what is project-local is the environment and
the resolution, not everything uv touches.

## Running

Cold, on a new checkout:

```
uv sync --frozen
cargo test --locked
```

Warm, once `.venv` exists:

```
cargo test --locked
```

The test harness runs `uv sync --frozen` itself, once per test binary and under a five-minute
bound of its own, so the second form works either way; running it explicitly only keeps a cold
install out of the test run. It then asks the interpreter for its own version and aioquic's and
requires them to be the pinned ones, so an environment left from an older lockfile fails with
what it actually is. Nothing is skipped when a prerequisite is absent: a missing `uv` fails the
run with the command to fix it.

These are the commands CI should invoke from this directory. No CI job is wired up yet. The
project is not part of the workspace, so `cargo test` at the repository root does not reach it.

The controlled-child tests around the setup runner use `kill -0` and are compiled on Unix
hosts only.
