# c-icap interoperability oracle

The image builds the official c-icap source at commit
`25f881d16f4dfbc943ee0a01d4c174d231afbb57`. The primary server provides
deterministic `echo` and `ex206` services on host port 1345. A second server on
port 1346 provides deterministic `204` responses.

## Reference behavior

Run the complete C client-to-C server matrix:

```console
just icap-oracle-test
```

This also runs Rama's client against both pinned C servers. Run only
that direction with:

```console
just icap-oracle-test-rama-client
```

The complete C client matrix can launch and test local Rama servers
without manual process coordination:

```console
just icap-oracle-test-rama-server-local
```

It covers OPTIONS, REQMOD, RESPMOD, null bodies, Preview with `ieof`, Preview
followed by `100 Continue`, zero-byte Preview, no Preview, `204`, negotiated
`206`, `use-original-body`, and the no-`206` fallback. Echo responses are
compared byte-for-byte with their expected bodies. The `206` probes assert the
status, adjusted content length, modified prefix, and original-body offset.

The pinned `c-icap-client` returns as soon as it receives a Preview `206` and
does not consume that response body. The matrix therefore uses direct ICAP
wire probes for `206` response bodies while leaving the reference server
unmodified. Its echo service accepts a trailer-bearing request and echoes the
body, but strips the trailer and close-delimits the response without an ICAP
terminal chunk. The wire matrix records that reference limitation; Rama's
server and Rama-to-Rama tests require complete trailer framing.

The smaller readiness check is available as `just icap-oracle-smoke`.

## Scenario matrix

| Scenario | C to C | Rama to C | C or wire to Rama | Rama to Rama |
|---|---|---|---|---|
| OPTIONS and null body | client | Rust suite | client | async suite |
| Preview `ieof`, `100`, and zero | client | Rust suite | client | async suite |
| Adaptation without Preview | client | Rust suite | client | async suite |
| Preview and non-Preview `204` | client | Rust suite | client | async suite |
| `206 use-original-body` | wire | Rust suite | wire | async suite |
| Complete adapted `206` | no C service | no C service | wire | async suite |
| No-`206` fallback | client | Rust suite | client | async suite |
| Encapsulated HTTP trailers | wire (strips) | C limitation | wire | async suite |

`just icap-oracle-test` runs every applicable cell. The C client and direct
wire probes run inside the pinned image. The local Rama server launcher uses
`host.docker.internal` and verifies that its child remains alive while waiting
for readiness.

The Rust oracle tests run when these endpoint variables are set. They return
without connecting during generic ignored-test CI jobs where the oracle is not
available:

```text
RAMA_ICAP_ORACLE_ECHO_ADDR=127.0.0.1:1345
RAMA_ICAP_ORACLE_204_ADDR=127.0.0.1:1346
```

To run the C client matrix against a Rama server listening on another host or
port:

```console
just icap-oracle-test-rama-server normal host.docker.internal 21344
just icap-oracle-test-rama-server 204 host.docker.internal 21345
```

The Rama server must expose `echo` and `ex206` services with the corresponding
reference behavior when running `normal`, or an `echo` service that returns
`204` when running `204`.

## Lifecycle

```console
just icap-oracle-up
just icap-oracle-down
```

Override published ports with `RAMA_ICAP_C_ICAP_PORT` and
`RAMA_ICAP_C_ICAP_204_PORT`; all `just` recipes honor both overrides.
