use std::{sync::Arc, time::Duration};

use tokio::sync::Mutex;

use super::{
    ffi::{EngineHandle, default_engine, initialize_ffi, test_storage_dir},
    servers::{
        spawn_combined_proxy, spawn_http_server, spawn_https_server, spawn_raw_tcp_echo,
        spawn_raw_tls_echo, spawn_udp_echo,
    },
    types::{HttpObservation, PortBlock, SharedObservations},
};

pub(crate) struct TestEnv {
    pub(crate) engine: Arc<EngineHandle>,
    pub(crate) ports: PortBlock,
    pub(crate) http_observations: SharedObservations,
    pub(crate) https_observations: SharedObservations,
}

pub(crate) async fn setup_env() -> TestEnv {
    let http_observations = Arc::new(Mutex::new(Vec::<HttpObservation>::new()));
    let https_observations = Arc::new(Mutex::new(Vec::<HttpObservation>::new()));
    let ports = PortBlock {
        http: spawn_http_server(http_observations.clone()).await,
        https: spawn_https_server(https_observations.clone()).await,
        raw_tcp: spawn_raw_tcp_echo().await,
        raw_tls: spawn_raw_tls_echo().await,
        udp: spawn_udp_echo().await,
        proxy: spawn_combined_proxy().await,
    };

    let storage_dir = test_storage_dir();
    std::fs::create_dir_all(&storage_dir).expect("create storage dir");
    initialize_ffi(&storage_dir);

    tokio::time::sleep(Duration::from_millis(25)).await;

    TestEnv {
        engine: default_engine(),
        ports,
        http_observations,
        https_observations,
    }
}
