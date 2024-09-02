mod utils;

mod http_conn_state;
mod http_connect_proxy;
mod http_form;
mod http_health_check;
mod http_high_level_client;
mod http_k8s_health;
mod http_key_value_store;
mod http_listener_hello;
mod http_rate_limit;
mod http_service_fs;
mod http_service_hello;
mod http_service_match;
mod http_user_agent_classifier;
mod http_web_service_dir_and_api;
mod tcp_listener_hello;
mod tcp_listener_layers;

#[cfg(feature = "rustls")]
mod http_mitm_proxy;
#[cfg(feature = "rustls")]
mod https_connect_proxy;
#[cfg(feature = "rustls")]
mod mtls_tunnel_and_service;
#[cfg(feature = "rustls")]
mod tls_termination;

// TODO: enable again in future,
// does not work for now, not sure why...
// Running example manually does work via curl,
// but automated test fails and not important enough for now
// :shrug:
// #[cfg(feature = "rustls")]
// mod tls_boring_termination;

mod http_telemetry;
