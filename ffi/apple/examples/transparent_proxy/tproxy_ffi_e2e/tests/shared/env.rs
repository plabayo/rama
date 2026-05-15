use std::{
    sync::{Arc, OnceLock},
    time::Duration,
};

use tokio::sync::Mutex;

use super::{
    ffi::{EngineHandle, default_engine, initialize_ffi, test_storage_dir},
    servers::{
        spawn_combined_proxy, spawn_http_server, spawn_https_server, spawn_raw_tcp_echo,
        spawn_raw_tls_echo, spawn_udp_echo,
    },
    types::{HttpObservation, PortBlock, SharedObservations},
};

/// Owns the spawned server tasks; aborts them all on drop so the
/// listener sockets are freed at test teardown. Without this each
/// test leaks ~6 listening FDs and the suite trips EMFILE on the
/// macOS-default `ulimit -n` 256 around test 38. Lives as a field
/// on `TestEnv` (rather than `Drop` on `TestEnv` itself) so test
/// code can still move other fields (e.g. `env.engine`) out by
/// value at test sites.
pub(crate) struct AbortOnDrop(pub(crate) Vec<tokio::task::JoinHandle<()>>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        for handle in &self.0 {
            handle.abort();
        }
    }
}

pub(crate) struct TestEnv {
    pub(crate) engine: Arc<EngineHandle>,
    pub(crate) ports: PortBlock,
    pub(crate) http_observations: SharedObservations,
    pub(crate) https_observations: SharedObservations,
    #[allow(dead_code, reason = "field exists for its Drop impl")]
    pub(crate) _server_handles: AbortOnDrop,
}

static FFI_INIT: OnceLock<()> = OnceLock::new();

pub(crate) async fn setup_env() -> TestEnv {
    let http_observations = Arc::new(Mutex::new(Vec::<HttpObservation>::new()));
    let https_observations = Arc::new(Mutex::new(Vec::<HttpObservation>::new()));

    let (http_port, http_handle) = spawn_http_server(http_observations.clone()).await;
    let (https_port, https_handle) = spawn_https_server(https_observations.clone()).await;
    let (raw_tcp_port, raw_tcp_handle) = spawn_raw_tcp_echo().await;
    let (raw_tls_port, raw_tls_handle) = spawn_raw_tls_echo().await;
    let (udp_port, udp_handle) = spawn_udp_echo().await;
    let (proxy_port, proxy_handle) = spawn_combined_proxy().await;

    let ports = PortBlock {
        http: http_port,
        https: https_port,
        raw_tcp: raw_tcp_port,
        raw_tls: raw_tls_port,
        udp: udp_port,
        proxy: proxy_port,
    };
    let server_handles = AbortOnDrop(vec![
        http_handle,
        https_handle,
        raw_tcp_handle,
        raw_tls_handle,
        udp_handle,
        proxy_handle,
    ]);

    let storage_dir = test_storage_dir();
    let engine = tokio::task::spawn_blocking(move || {
        std::fs::create_dir_all(&storage_dir).expect("create storage dir");
        FFI_INIT.get_or_init(|| initialize_ffi(&storage_dir));
        default_engine()
    })
    .await
    .expect("join ffi setup task");

    tokio::time::sleep(Duration::from_millis(25)).await;

    TestEnv {
        engine,
        ports,
        http_observations,
        https_observations,
        _server_handles: server_handles,
    }
}
