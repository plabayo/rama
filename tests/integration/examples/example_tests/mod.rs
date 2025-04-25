mod utils;

#[cfg(feature = "http-full")]
mod http_conn_state;
#[cfg(feature = "http-full")]
mod http_connect_proxy;
#[cfg(feature = "http-full")]
mod http_form;
#[cfg(feature = "http-full")]
mod http_health_check;
#[cfg(feature = "http-full")]
mod http_high_level_client;
#[cfg(feature = "http-full")]
mod http_k8s_health;
#[cfg(feature = "http-full")]
mod http_key_value_store;
#[cfg(feature = "http-full")]
mod http_listener_hello;
#[cfg(all(feature = "http-full", feature = "rustls"))]
mod http_mitm_proxy_boring;
#[cfg(all(feature = "http-full", feature = "rustls"))]
mod http_mitm_proxy_rustls;
#[cfg(feature = "http-full")]
mod http_pooled_client;
#[cfg(all(feature = "http-full", feature = "tower"))]
mod http_rama_tower;
#[cfg(feature = "http-full")]
mod http_rate_limit;
#[cfg(feature = "http-full")]
mod http_service_fs;
#[cfg(feature = "http-full")]
mod http_service_hello;
#[cfg(feature = "http-full")]
mod http_service_match;
#[cfg(all(feature = "http-full", feature = "telemetry"))]
mod http_telemetry;
#[cfg(feature = "http-full")]
mod http_user_agent_classifier;
#[cfg(feature = "http-full")]
mod http_web_router;
#[cfg(feature = "http-full")]
mod http_web_service_dir_and_api;
#[cfg(all(feature = "http-full", feature = "rustls"))]
mod https_connect_proxy;
#[cfg(all(feature = "http-full", feature = "rustls"))]
mod mtls_tunnel_and_service;
#[cfg(feature = "tcp")]
mod tcp_listener_hello;
#[cfg(feature = "tcp")]
mod tcp_listener_layers;
#[cfg(feature = "udp")]
mod udp_codec;

#[cfg(all(feature = "boring", feature = "http-full"))]
mod tls_boring_dynamic_certs;

// We should be able to verify these rustls cert using a boring client
#[cfg(all(feature = "boring", feature = "http-full"))]
mod tls_rustls_dynamic_certs;

#[cfg(all(feature = "boring", feature = "http-full"))]
mod tls_rustls_dynamic_config;

#[cfg(all(feature = "boring", feature = "haproxy", feature = "http-full"))]
mod tls_boring_termination;

#[cfg(all(feature = "rustls", feature = "haproxy", feature = "http-full"))]
mod tls_rustls_termination;
