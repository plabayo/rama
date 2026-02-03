# Rama Examples

This directory contains example implementations demonstrating various features and capabilities of the Rama framework. The examples are organized by category below.

All these examples are tested. This validates that all tests are functional
at any time and it can also serve as an additional example on how the client-side
counterpart of a server-like example looks like.

You can find these integration tests at [../tests/integration/examples](../tests/integration/examples).

## HTTP Servers and Services

### Basic HTTP Services
- [`http_service_hello.rs`](./http_service_hello.rs) - A simple HTTP service that returns "Hello, World!"
- [`http_listener_hello.rs`](./http_listener_hello.rs) - Basic HTTP listener example
- [`http_service_fs.rs`](./http_service_fs.rs) - File system service for serving static files
- [`http_service_include_dir.rs`](./http_service_include_dir.rs) - File system service for serving embedded files
- [`http_web_service_dir_and_api.rs`](./http_web_service_dir_and_api.rs) - Combined directory and API service
- [`http_web_router.rs`](./http_web_router.rs) - HTTP router implementation
- [`http_service_match.rs`](./http_service_match.rs) - Service matching example
- [`http_abort.rs`](./http_abort.rs) - A small example how one can control a lower network layer from within the http (application) layer
- [`http_form.rs`](./http_form.rs) - Form handling example
- [`http_health_check.rs`](./http_health_check.rs) - Health check endpoint implementation
- [`http_har_replay.rs`](./http_har_replay.rs): HAR replay demonstration
- [`http_k8s_health.rs`](./http_k8s_health.rs) - Kubernetes health check implementation
- [`http_record_har.rs`](./http_record_har.rs) - Demo of HAR HTTP layer provided by rama
- [`http_octet_stream.rs`](./http_octet_stream.rs) - Binary data responses with file downloads

### Advanced HTTP Features
- [`http_conn_state.rs`](./http_conn_state.rs) - Connection state management
- [`http_rate_limit.rs`](./http_rate_limit.rs) - Rate limiting implementation
- [`http_key_value_store.rs`](./http_key_value_store.rs) - Key-value store service
- [`http_telemetry.rs`](./http_telemetry.rs) - Telemetry and monitoring
- [`http_user_agent_classifier.rs`](./http_user_agent_classifier.rs) - User agent classification

### gRPC

See [the gRPC examples README at ./grpc/README.md](./grpc/README.md).

### Newline Delimited JSON (ndjson)

- [`http_nd_json`](./http_nd_json.rs) - example demonstrating how one can expose a json stream endpoint (see test of this example to see how client side works)

### Server-Sent Events (SSE)
- [`http_sse`](./http_sse.rs) - simple example demonstrating how one can expose an SSE endpoint
- [`http_sse_json`](./http_sse_json.rs) - same as `http_sse` but using structured _json_ data
- [`http_sse_datastar_hello`](./http_sse_datastar_hello.rs) - a hello world example for datastar (featuring DIY `CQRS` in action);
- [`http_sse_datastar_test_suite`](./http_sse_datastar_test_suite.rs) - datastar sdk test suite server

Rama supports also client-side SSE. See the tests of these examples
at [../tests/integration/examples](../tests/integration/examples) on how the client
side looks like.

### Anti-Bot examples

- [`http_anti_bot_infinite_resource.rs`](./http_anti_bot_infinite_resource.rs) - example demonstrating how to serve an infinite resource
- [`http_anti_bot_zip_bomb.rs`](./http_anti_bot_zip_bomb.rs) - example demonstrating how to serve a zip bomb

## HTTP Clients
- [`http_high_level_client.rs`](./http_high_level_client.rs) - High-level HTTP client implementation
- [`http_pooled_client.rs`](./http_pooled_client.rs) - Connection pooling client

### WebSocket
- [`ws_echo_server.rs`](./ws_echo_server.rs) - WebSocket server which echos all messages back
- [`ws_echo_server_with_compression.rs`](./ws_echo_server_with_compression.rs) - WebSocket server which echos all messages back, with per message deflate compression enabled and supported
- [`ws_chat_server.rs`](./ws_chat_server.rs) - WebSocket chat server
- [`ws_tls_server.rs`](./ws_tls_server.rs) - Secure WebSocket server example (WSS)
- [`ws_over_h2.rs`](./ws_over_h2.rs) - Secure WebSocket server example using h2.
- [`autobahn_client.rs`](./autobahn_client.rs) - Run autobahn WebSocket test suite.

### ACME
The following examples show how you can integrate ACME into you webservices (ACME support in Rama is currently still under heavy development)
- [`acme_http_challenge.rs`](./acme_http_challenge.rs): Authenticate to an acme server using a http challenge
- [`acme_tls_challenge_using_boring.rs`](./acme_tls_challenge_using_boring.rs): Authenticate to an acme server using a tls challenge backed by boringssl
- [`acme_tls_challenge_using_rustls.rs`](./acme_tls_challenge_using_rustls.rs): Authenticate to an acme server using a tls challenge backed by rustls

## Proxies

### Http Proxies

- [`http_connect_proxy.rs`](./http_connect_proxy.rs) - HTTP CONNECT proxy implementation
- [`http_mitm_proxy_rustls.rs`](./http_mitm_proxy_rustls.rs) - MITM proxy using Rustls
- [`http_mitm_proxy_boring.rs`](./http_mitm_proxy_boring.rs) - MITM proxy using BoringSSL

### Http within TLS Proxies

- [`https_connect_proxy.rs`](./https_connect_proxy.rs) - HTTPS CONNECT proxy implementation

### Socks5 Proxies

- [`socks5_connect_proxy.rs`](./socks5_connect_proxy.rs) - SOCKS5 CONNECT proxy implementation
- [`socks5_connect_proxy_mitm_proxy.rs`](./socks5_connect_proxy_mitm_proxy.rs) -
  SOCKS5 CONNECT proxy implementation with HTTP(S) MITM Capabilities
- [`socks5_connect_proxy_over_tls.rs`](./socks5_connect_proxy_over_tls.rs) -
  SOCKS5 CONNECT proxy implementation showing how to run it within a TLS tunnel w/ self-contained socks5 client
- [`socks5_bind_proxy.rs`](./socks5_bind_proxy.rs) -
  SOCKS5 BIND proxy implementation showing how to run it from both client and server
- [`socks5_udp_associate.rs`](./socks5_udp_associate.rs) -
  SOCKS5 UDP Associate client+server example w/ sync inspector added
- [`socks5_udp_associate_framed.rs`](./socks5_udp_associate_framed.rs) -
  Same as `socks5_udp_associate.rs` but demonstrating how to combine it with frames

### Combo Proxies:

- [`socks5_and_http_proxy.rs`](./socks5_and_http_proxy.rs) -
  combines `http_connect_proxy` and `socks5_connect_proxy` into a single server.
- [`http_https_socks5_and_socks5h_connect_proxy.rs`](./http_https_socks5_and_socks5h_connect_proxy.rs) -
  combines `http_connect_proxy`, `https_connect_proxy` and `socks5_connect_proxy` into a single server.
- [`proxy_connectivity_check.rs`](./proxy_connectivity_check.rs) -
  combines an http and socks5 proxy, but mostly is about how you can add a connectivity check,
  used by humans as a sanity check for whether or not they are connected (via) "the" proxy.

### HaProxy

- [`haproxy_client_ip.rs`](./haproxy_client_ip.rs) -
  shows how to support, optionally, HaProxy (v1/v2) in a rama web service,
  supporting load balancers that support the proagation of client IP address.

## TLS and Security

- [`https_web_service_with_hsts.rs`](./https_web_service_with_hsts.rs) - HTTP Strict Transport Security (HSTS) example

### Rustls
- [`tls_rustls_termination.rs`](./tls_rustls_termination.rs) - TLS termination with Rustls
- [`tls_rustls_dynamic_certs.rs`](./tls_rustls_dynamic_certs.rs) - Dynamic certificate management with Rustls
- [`tls_rustls_dynamic_config.rs`](./tls_rustls_dynamic_config.rs) - Dynamic TLS configuration with Rustls

### BoringSSL
- [`tls_boring_termination.rs`](./tls_boring_termination.rs) - TLS termination with BoringSSL
- [`tls_boring_dynamic_certs.rs`](./tls_boring_dynamic_certs.rs) - Dynamic certificate management with BoringSSL

### SNI router

- [`tls_sni_router.rs`](./tls_sni_router.rs) - (TLS) SNI Router with BoringSSL
- [`tls_sni_proxy_mitm.rs`](./tls_sni_proxy_mitm.rs) - (TLS) SNI Proxy with MITM capabilities using BoringSSL

### Mutual TLS
- [`mtls_tunnel_and_service.rs`](./mtls_tunnel_and_service.rs) - Mutual TLS tunnel and service implementation

## Network and Transport
- [`tcp_listener_fd_passing.rs`](./tcp_listener_fd_passing.rs) - FD passing via SCM_RIGHTS for zero-downtime restarts (Unix-only)
- [`tcp_listener_hello.rs`](./tcp_listener_hello.rs) - Basic TCP listener example
- [`tcp_listener_layers.rs`](./tcp_listener_layers.rs) - TCP listener with layers
- [`tcp_nd_json.rs`](./tcp_nd_json.rs) - TCP listener serving a ndjson (Newline Delimited JSON) stream of data
- [`udp_codec.rs`](./udp_codec.rs) - UDP codec implementation
- [`unix_socket.rs`](./unix_socket.rs) - Unix socket server (listener) demonstration of accepting and handling incoming streams
- [`unix_socket_http.rs`](./unix_socket_http.rs) - Serving HTTP over a unix socket, which is a fast and easy local-first solution
- [`unix_datagram_codec.rs`](./unix_datagram_codec.rs) - Unix datagram, frame demonstration via bytes codec

## Tower
- [`http_rama_tower.rs`](./http_rama_tower.rs) - How to integrate tower into your rama HTTP stack

## Running Examples

Most examples can be run using cargo with the appropriate feature flags. For example:

```bash
# Run a basic HTTP service
cargo run --example http_service_hello --features=http-full

# Run a TLS example
cargo run --example tls_rustls_termination --features=tls-rustls

# Run a proxy example
cargo run --example http_mitm_proxy_boring --features=http-full,boring
```

Check each example's documentation for specific feature requirements and usage instructions.

## Contributing

Feel free to contribute new examples or improve existing ones. When adding a new example:

1. Include comprehensive documentation at the top of the file
2. Add clear usage instructions
3. Include any necessary feature flags
4. Add the example to this README in the appropriate category
5. Add comprehensive e2e test(s) for the example
