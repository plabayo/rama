# Examples

## Core TCP Examples

A minimal example of how to create
your own TCP server can be run with:

```
cargo run --example tcp_simple
```

> File: [`examples/tcp_simple.rs`](tcp_simple.rs)

When you connect to that server using `telnet`
at `127.0.0.1:20018` you should be able to see
hello greeting appears in the `stderr` of your server.

A more advanced example which echo's its incoming input
can be run with:

```
cargo run --example tcp_layered_service
```

> File: [`examples/tcp_layered_service.rs`](tcp_layered_service.rs)

Which you can test the same way. This time you will not
only see logs on the server side, but also within
`telnet` you should receive back the same input you sent.
