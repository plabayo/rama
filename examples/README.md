# Rama Examples

This directory contains example implementations demonstrating various features and capabilities of the Rama framework. The examples are organized by category below.

Other example locations in this repository:

- [./grpc](./grpc) for gRPC-focused examples
- [../ffi/apple/examples](../ffi/apple/examples) for Apple FFI and Network Extension examples

All these examples are tested, except where not easily possible.
If an example is not tested it will be mentioned in the module doc of that example.
Otherwise you can assume it has tests, which validates that all tests are functional
at any time and it can also serve as an additional example on how the client-side
counterpart of a server-like example looks like.

You can find these integration tests at [./tests/integration](./tests/integration).

## HTTP Servers and Services

### Basic HTTP Services
- [`http_service_hello.rs`](./src/http_service_hello.rs) - A simple HTTP service that returns "Hello, World!"
- [`http_listener_hello.rs`](./src/http_listener_hello.rs) - Basic HTTP listener example
- [`http_service_fs.rs`](./src/http_service_fs.rs) - File system service for serving static files
- [`http_service_include_dir.rs`](./src/http_service_include_dir.rs) - File system service for serving embedded files
- [`http_web_service_dir_and_api.rs`](./src/http_web_service_dir_and_api.rs) - Combined directory and API service
- [`http_web_router.rs`](./src/http_web_router.rs) - HTTP router implementation
- [`http_service_match.rs`](./src/http_service_match.rs) - Service matching example
- [`http_abort.rs`](./src/http_abort.rs) - A small example how one can control a lower network layer from within the http (application) layer
- [`http_form.rs`](./src/http_form.rs) - Form handling example
- [`http_health_check.rs`](./src/http_health_check.rs) - Health check endpoint implementation
- [`http_har_replay.rs`](./src/http_har_replay.rs): HAR replay demonstration
- [`http_k8s_health.rs`](./src/http_k8s_health.rs) - Kubernetes health check implementation
- [`http_record_har.rs`](./src/http_record_har.rs) - Demo of HAR HTTP layer provided by rama
- [`http_octet_stream.rs`](./src/http_octet_stream.rs) - Binary data responses with file downloads
- [`http_multipart.rs`](./src/http_multipart.rs) - `multipart/form-data` upload handling
- [`http_advanced_router.rs`](./src/http_advanced_router.rs) - Advanced http router composition examples

### Advanced HTTP Features
- [`http_health_check.rs`](./src/http_health_check.rs) - Connection state management
- [`http_rate_limit.rs`](./src/http_rate_limit.rs) - Rate limiting implementation
- [`http_key_value_store.rs`](./src/http_key_value_store.rs) - Key-value store service
- [`http_telemetry.rs`](./src/http_telemetry.rs) - Telemetry and monitoring
- [`http_user_agent_classifier.rs`](./src/http_user_agent_classifier.rs) - User agent classification

### gRPC

See [the gRPC examples README at ./grpc/README.md](./grpc/README.md).

### ttRPC
- [`ttrpc_server.rs`](./src/ttrpc_server.rs) - Serve a ttRPC service (containerd-style RPC, no HTTP/2) over a rama-tcp connection

### Newline Delimited JSON (ndjson)

- [`http_nd_json`](./src/http_nd_json.rs) - example demonstrating how one can expose a json stream endpoint (see test of this example to see how client side works)

### Streaming HTML

- [`http_declarative_partial_updates`](./src/http_declarative_partial_updates.rs) - stream an HTML shell with `<?marker …>` placeholders, then fill them in out-of-order via `<template for=…>` as each async fragment completes ([Chrome declarative partial updates](https://developer.chrome.com/blog/declarative-partial-updates))

### Server-Sent Events (SSE)
- [`http_sse`](./src/http_sse.rs) - simple example demonstrating how one can expose an SSE endpoint
- [`http_sse_json`](./src/http_sse_json.rs) - same as `http_sse` but using structured _json_ data
- [`http_sse_datastar_hello`](./src/http_sse_datastar_hello.rs) - a hello world example for datastar (featuring DIY `CQRS` in action);
- [`http_sse_datastar_test_suite`](./src/http_sse_datastar_test_suite.rs) - datastar sdk test suite server

Rama supports also client-side SSE. See the tests of these examples
at [./tests/integration](./tests/integration) on how the client
side looks like.

### RSS and Atom Feeds

- [`http_rss_blog.rs`](./src/http_rss_blog.rs) - RSS 2.0 and Atom 1.0 blog feed server, showing the type-state builder API and `content:encoded` extension
- [`http_rss_podcast.rs`](./src/http_rss_podcast.rs) - Podcast feed server with iTunes and Podcasting 2.0 extensions, both one-shot and streaming variants

### Anti-Bot examples

- [`http_anti_bot_infinite_resource.rs`](./src/http_anti_bot_infinite_resource.rs) - example demonstrating how to serve an infinite resource
- [`http_anti_bot_zip_bomb.rs`](./src/http_anti_bot_zip_bomb.rs) - example demonstrating how to serve a zip bomb

## HTTP Clients
- [`http_high_level_client.rs`](./src/http_high_level_client.rs) - High-level HTTP client implementation
- [`http_pooled_client.rs`](./src/http_pooled_client.rs) - Connection pooling client

### WebSocket
- [`ws_echo_server.rs`](./src/ws_echo_server.rs) - WebSocket server which echos all messages back
- [`ws_echo_server_with_compression.rs`](./src/ws_echo_server_with_compression.rs) - WebSocket server which echos all messages back, with per message deflate compression enabled and supported
- [`ws_chat_server.rs`](./src/ws_chat_server.rs) - WebSocket chat server
- [`ws_tls_server.rs`](./src/ws_tls_server.rs) - Secure WebSocket server example (WSS)
- [`ws_over_h2.rs`](./src/ws_over_h2.rs) - Secure WebSocket server example using h2.
- [`autobahn_client.rs`](./src/autobahn_client.rs) - Run autobahn WebSocket test suite.

### ACME
The following examples show how you can integrate ACME into you webservices (ACME support in Rama is currently still under heavy development)
- [`acme_http_challenge.rs`](./src/acme_http_challenge.rs): Authenticate to an acme server using a http challenge
- [`acme_tls_challenge_using_boring.rs`](./src/acme_tls_challenge_using_boring.rs): Authenticate to an acme server using a tls challenge backed by boringssl
- [`acme_tls_challenge_using_rustls.rs`](./src/acme_tls_challenge_using_rustls.rs): Authenticate to an acme server using a tls challenge backed by rustls

## Proxies

### Http Proxies

- [`http_connect_proxy.rs`](./src/http_connect_proxy.rs) - HTTP CONNECT proxy implementation
- [`http_mitm_proxy_rustls.rs`](./src/http_mitm_proxy_rustls.rs) - MITM proxy using Rustls
- [`http_mitm_proxy_boring.rs`](./src/http_mitm_proxy_boring.rs) - MITM proxy using BoringSSL
- [`http_mitm_relay_proxy_boring.rs`](./src/http_mitm_relay_proxy_boring.rs) - MITM proxy using BoringSSL with a more advanced relay approach
- [`mitm_ocsp_relay_gate.rs`](./src/mitm_ocsp_relay_gate.rs) - harness for the MITM OCSP-stapling gate (curl/openssl validate stapled leaves through the relay)

### Http within TLS Proxies

- [`https_connect_proxy.rs`](./src/https_connect_proxy.rs) - HTTPS CONNECT proxy implementation

### Socks5 Proxies

- [`socks5_connect_proxy.rs`](./src/socks5_connect_proxy.rs) - SOCKS5 CONNECT proxy implementation
- [`socks5_connect_proxy_mitm_proxy.rs`](./src/socks5_connect_proxy_mitm_proxy.rs) -
  SOCKS5 CONNECT proxy implementation with HTTP(S) MITM Capabilities
- [`socks5_connect_proxy_over_tls.rs`](./src/socks5_connect_proxy_over_tls.rs) -
  SOCKS5 CONNECT proxy implementation showing how to run it within a TLS tunnel w/ self-contained socks5 client
- [`socks5_bind_proxy.rs`](./src/socks5_bind_proxy.rs) -
  SOCKS5 BIND proxy implementation showing how to run it from both client and server
- [`socks5_udp_associate.rs`](./src/socks5_udp_associate.rs) -
  SOCKS5 UDP Associate client+server example w/ sync inspector added
- [`socks5_udp_associate_framed.rs`](./src/socks5_udp_associate_framed.rs) -
  Same as `socks5_udp_associate.rs` but demonstrating how to combine it with frames

### Combo Proxies:

- [`socks5_and_http_proxy.rs`](./src/socks5_and_http_proxy.rs) -
  combines `http_connect_proxy` and `socks5_connect_proxy` into a single server.
- [`http_https_socks5_and_socks5h_connect_proxy.rs`](./src/http_https_socks5_and_socks5h_connect_proxy.rs) -
  combines `http_connect_proxy`, `https_connect_proxy` and `socks5_connect_proxy` into a single server.
- [`proxy_connectivity_check.rs`](./src/proxy_connectivity_check.rs) -
  combines an http and socks5 proxy, but mostly is about how you can add a connectivity check,
  used by humans as a sanity check for whether or not they are connected (via) "the" proxy.

### Transparent Proxies

- [`linux_tproxy_tcp.rs`](./src/linux_tproxy_tcp.rs) -
  Linux-only transparent TCP proxy example using TPROXY, `IP_TRANSPARENT`,
  original-destination recovery via `getsockname`, and byte-for-byte forwarding

Other locations that demonstrate how to make and run a Transparent Proxy:

- [../ffi/apple/examples/transparent_proxy](../ffi/apple/examples/transparent_proxy)
  NetworkExtension (NE) Transparent Proxy for on MacOS (Apple)

### HaProxy

- [`haproxy_client_ip.rs`](./src/haproxy_client_ip.rs) -
  shows how to support, optionally, HaProxy (v1/v2) in a rama web service,
  supporting load balancers that support the proagation of client IP address.

### FastCGI

- [`fastcgi_reverse_proxy.rs`](./src/fastcgi_reverse_proxy.rs) -
  An HTTP reverse proxy that translates incoming HTTP requests into FastCGI requests
  and forwards them to a FastCGI backend application server (embedded in the same binary
  for demonstration). Shows `FastCgiServer` on the backend and `FastCgiClient` on the proxy side.
- [`gateway/fastcgi-php/gateway`](./src/gateway/fastcgi-php/gateway/main.rs) —
  rama terminates HTTPS (rustls self-signed) and forwards every request to
  php-fpm over **TCP**.
- [`gateway/fastcgi-php/migration`](./src/gateway/fastcgi-php/migration/main.rs) —
  rama serves `/api/health` and `/api/version` natively in Rust; everything
  else falls back to php-fpm over a **Unix socket**. The PHP app implements
  the Rust-served routes too, with a payload tag `"source":"php"` that the
  tests assert is never observed — proving the migration boundary.

## TLS and Security

- [`https_web_service_with_hsts.rs`](./src/https_web_service_with_hsts.rs) - HTTP Strict Transport Security (HSTS) example

### Rustls
- [`tls_rustls_cert_pinning.rs`](./src/tls_rustls_cert_pinning.rs) - Server leaf key/certificate pinning with Rustls
- [`tls_rustls_termination.rs`](./src/tls_rustls_termination.rs) - TLS termination with Rustls
- [`tls_rustls_dynamic_certs.rs`](./src/tls_rustls_dynamic_certs.rs) - Dynamic certificate management with Rustls
- [`tls_rustls_dynamic_config.rs`](./src/tls_rustls_dynamic_config.rs) - Dynamic TLS configuration with Rustls

### BoringSSL
- [`tls_boring_cert_pinning.rs`](./src/tls_boring_cert_pinning.rs) - Server leaf key/certificate pinning with BoringSSL
- [`tls_boring_termination.rs`](./src/tls_boring_termination.rs) - TLS termination with BoringSSL
- [`tls_boring_dynamic_certs.rs`](./src/tls_boring_dynamic_certs.rs) - Dynamic certificate management with BoringSSL

### SNI router

- [`tls_sni_router.rs`](./src/tls_sni_router.rs) - (TLS) SNI Router with BoringSSL
- [`tls_sni_proxy_mitm.rs`](./src/tls_sni_proxy_mitm.rs) - (TLS) SNI Proxy with MITM capabilities using BoringSSL

### Mutual TLS
- [`mtls_tunnel_and_service.rs`](./src/mtls_tunnel_and_service.rs) - Mutual TLS tunnel and service implementation

## Apple XPC

- [`xpc_echo.rs`](./src/xpc_echo.rs) - End-to-end XPC echo using an anonymous channel (no launchd required).
  Demonstrates `XpcServer<S>`, anonymous listener acceptance, fire-and-forget send, request-reply,
  graceful shutdown, and tracing output — Apple platforms only.
- [`xpc_ca_exchange.rs`](./src/xpc_ca_exchange.rs) - A control-plane shaped XPC request/reply example.
  Demonstrates fetching CA material over XPC, using the same service-driven anonymous-channel setup
  that can later be moved behind a named Mach service with peer requirements.
- [`../ffi/apple/examples/transparent_proxy`](../ffi/apple/examples/transparent_proxy) - A practical
  Apple Network Extension demo that uses the same pattern to keep the MITM CA private key out of
  the opaque startup config and request it from the host app over local XPC instead.

## Network and Transport
- [`native_dns.rs`](./src/native_dns.rs) - Resolve domains using Rama's native DNS resolver,
  - with Apple-native DNS-SD support on Apple platforms
  - `DnsQueryEx` on Windows
  - `res_nsearch` on gnu/bsd
  - `getaddrinfo` on other Linux platforms,
  - and tokio's basic `lookup_host` on everything else
- [`tcp_listener_fd_passing.rs`](./src/tcp_listener_fd_passing.rs) - FD passing via SCM_RIGHTS for zero-downtime restarts (Unix-only)
- [`tcp_listener_hello.rs`](./src/tcp_listener_hello.rs) - Basic TCP listener example
- [`tcp_listener_layers.rs`](./src/tcp_listener_layers.rs) - TCP listener with layers
- [`tcp_nd_json.rs`](./src/tcp_nd_json.rs) - TCP listener serving a ndjson (Newline Delimited JSON) stream of data
- [`udp_codec.rs`](./src/udp_codec.rs) - UDP codec implementation
- [`udp_over_tcp.rs`](./src/udp_over_tcp.rs) - Tunnel UDP datagrams over a single TCP connection
  (inspired by [Jon Gjengset's `udp-over-tcp`](https://github.com/jonhoo/udp-over-tcp));
  demonstrates `ConnectedUdpFramed` + `StreamForwardService`
- [`unix_socket.rs`](./src/unix_socket.rs) - Unix socket server (listener) demonstration of accepting and handling incoming streams
- [`unix_socket_http.rs`](./src/unix_socket_http.rs) - Serving HTTP over a unix socket, which is a fast and easy local-first solution
- [`unix_datagram_codec.rs`](./src/unix_datagram_codec.rs) - Unix datagram, frame demonstration via bytes codec

## Tower
- [`http_rama_tower.rs`](./src/http_rama_tower.rs) - How to integrate tower into your rama HTTP stack

## Running Examples

Most examples can be run using cargo with the appropriate feature flags. For example:

```bash
# Run a basic HTTP service
cargo run -p rama-examples --bin http_service_hello --features=http-full

# Run a TLS example
cargo run -p rama-examples --bin tls_rustls_termination --features=tls-rustls

# Run a proxy example
cargo run -p rama-examples --bin http_mitm_proxy_boring --features=http-full,boring
```

Check each example's documentation for specific feature requirements and usage instructions.

## Contributing

Feel free to contribute new examples or improve existing ones. When adding a new example:

1. Include comprehensive documentation at the top of the file
2. Add clear usage instructions
3. Include any necessary feature flags
4. Add the example to this README in the appropriate category
5. Add comprehensive e2e test(s) for the example
