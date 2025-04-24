# Rama Examples

This directory contains example implementations demonstrating various features and capabilities of the Rama framework. The examples are organized by category below.

## HTTP Servers and Services

### Basic HTTP Services
- [`http_service_hello.rs`](./http_service_hello.rs) - A simple HTTP service that returns "Hello, World!"
- [`http_listener_hello.rs`](./http_listener_hello.rs) - Basic HTTP listener example
- [`http_service_fs.rs`](./http_service_fs.rs) - File system service for serving static files
- [`http_web_service_dir_and_api.rs`](./http_web_service_dir_and_api.rs) - Combined directory and API service
- [`http_web_router.rs`](./http_web_router.rs) - HTTP router implementation
- [`http_service_match.rs`](./http_service_match.rs) - Service matching example
- [`http_form.rs`](./http_form.rs) - Form handling example
- [`http_health_check.rs`](./http_health_check.rs) - Health check endpoint implementation
- [`http_k8s_health.rs`](./http_k8s_health.rs) - Kubernetes health check implementation

### Advanced HTTP Features
- [`http_conn_state.rs`](./http_conn_state.rs) - Connection state management
- [`http_rate_limit.rs`](./http_rate_limit.rs) - Rate limiting implementation
- [`http_key_value_store.rs`](./http_key_value_store.rs) - Key-value store service
- [`http_telemetry.rs`](./http_telemetry.rs) - Telemetry and monitoring
- [`http_user_agent_classifier.rs`](./http_user_agent_classifier.rs) - User agent classification

## HTTP Clients
- [`http_high_level_client.rs`](./http_high_level_client.rs) - High-level HTTP client implementation
- [`http_pooled_client.rs`](./http_pooled_client.rs) - Connection pooling client

## Proxies
- [`http_connect_proxy.rs`](./http_connect_proxy.rs) - HTTP CONNECT proxy implementation
- [`https_connect_proxy.rs`](./https_connect_proxy.rs) - HTTPS CONNECT proxy implementation
- [`http_mitm_proxy_rustls.rs`](./http_mitm_proxy_rustls.rs) - MITM proxy using Rustls
- [`http_mitm_proxy_boring.rs`](./http_mitm_proxy_boring.rs) - MITM proxy using BoringSSL

## TLS and Security
### Rustls
- [`tls_rustls_termination.rs`](./tls_rustls_termination.rs) - TLS termination with Rustls
- [`tls_rustls_dynamic_certs.rs`](./tls_rustls_dynamic_certs.rs) - Dynamic certificate management with Rustls
- [`tls_rustls_dynamic_config.rs`](./tls_rustls_dynamic_config.rs) - Dynamic TLS configuration with Rustls

### BoringSSL
- [`tls_boring_termination.rs`](./tls_boring_termination.rs) - TLS termination with BoringSSL
- [`tls_boring_dynamic_certs.rs`](./tls_boring_dynamic_certs.rs) - Dynamic certificate management with BoringSSL

### Mutual TLS
- [`mtls_tunnel_and_service.rs`](./mtls_tunnel_and_service.rs) - Mutual TLS tunnel and service implementation

## Network and Transport
- [`tcp_listener_hello.rs`](./tcp_listener_hello.rs) - Basic TCP listener example
- [`tcp_listener_layers.rs`](./tcp_listener_layers.rs) - TCP listener with layers
- [`udp_codec.rs`](./udp_codec.rs) - UDP codec implementation

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
