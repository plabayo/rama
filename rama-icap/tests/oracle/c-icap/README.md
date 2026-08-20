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

It covers OPTIONS, REQMOD, RESPMOD, null bodies, Preview with `ieof`, Preview
followed by `100 Continue`, zero-byte Preview, no Preview, trailers, `204`,
negotiated `206`, `use-original-body`, and the no-`206` fallback. Echo responses
are compared byte-for-byte with their expected bodies. The `206` probes assert
the status, adjusted content length, modified prefix, and original-body offset.

The pinned `c-icap-client` returns as soon as it receives a Preview `206` and
does not consume that response body. The matrix therefore uses a direct ICAP
wire probe for the two `206` cases while leaving the reference server
unmodified. All other cases use `c-icap-client`.

The smaller readiness check is available as `just icap-oracle-smoke`.

## Interoperability directions

| Client | Server | How it is exercised |
|---|---|---|
| c-icap | c-icap | `just icap-oracle-test` establishes reference behavior. |
| Rama | c-icap | Point Rama tests at `127.0.0.1:1345` (`echo`/`ex206`) and `127.0.0.1:1346` (`echo` for `204`). |
| c-icap | Rama | Run `just icap-oracle-test-rama-server`; the container reaches the host through `host.docker.internal`. |
| Rama | Rama | Use in-process or loopback Rust integration tests without Docker. |

The future Rust oracle tests should use these stable endpoint variables:

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
`RAMA_ICAP_C_ICAP_204_PORT`.
