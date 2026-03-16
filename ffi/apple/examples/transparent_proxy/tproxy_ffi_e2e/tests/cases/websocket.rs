//! WebSocket E2E coverage.
//!
//! Matrix:
//! - HTTP version: `h1`, `h2`
//! - target: `plain`, `tls`
//! - proxy: `direct`, `http`, `socks5`

use rama::{http::Version, telemetry::tracing};
use serial_test::serial;

use crate::shared::{
    clients::{build_http_client, websocket_echo},
    env::setup_env,
    ffi::load_mitm_ca_store,
    ingress::spawn_ingress_listener,
    types::{HttpTargetKind, ProxyKind, localhost},
};

macro_rules! websocket_test {
    ($name:ident, $version:expr, $target:expr, $proxy:expr) => {
        #[tokio::test]
        #[tracing_test::traced_test]
        #[serial]
        async fn $name() {
            run_websocket_case($version, $target, $proxy).await;
        }
    };
}

websocket_test!(
    ffi_contract_websocket_h1_plain_direct_echo,
    Version::HTTP_11,
    HttpTargetKind::Plain,
    ProxyKind::None
);
websocket_test!(
    ffi_contract_websocket_h1_plain_http_proxy_echo,
    Version::HTTP_11,
    HttpTargetKind::Plain,
    ProxyKind::Http
);
websocket_test!(
    ffi_contract_websocket_h1_plain_socks5_proxy_echo,
    Version::HTTP_11,
    HttpTargetKind::Plain,
    ProxyKind::Socks5
);
websocket_test!(
    ffi_contract_websocket_h1_tls_direct_echo,
    Version::HTTP_11,
    HttpTargetKind::Tls,
    ProxyKind::None
);
websocket_test!(
    ffi_contract_websocket_h1_tls_http_proxy_echo,
    Version::HTTP_11,
    HttpTargetKind::Tls,
    ProxyKind::Http
);
websocket_test!(
    ffi_contract_websocket_h1_tls_socks5_proxy_echo,
    Version::HTTP_11,
    HttpTargetKind::Tls,
    ProxyKind::Socks5
);
websocket_test!(
    ffi_contract_websocket_h2_plain_direct_echo,
    Version::HTTP_2,
    HttpTargetKind::Plain,
    ProxyKind::None
);
websocket_test!(
    ffi_contract_websocket_h2_plain_http_proxy_echo,
    Version::HTTP_2,
    HttpTargetKind::Plain,
    ProxyKind::Http
);
websocket_test!(
    ffi_contract_websocket_h2_plain_socks5_proxy_echo,
    Version::HTTP_2,
    HttpTargetKind::Plain,
    ProxyKind::Socks5
);
websocket_test!(
    ffi_contract_websocket_h2_tls_direct_echo,
    Version::HTTP_2,
    HttpTargetKind::Tls,
    ProxyKind::None
);
websocket_test!(
    ffi_contract_websocket_h2_tls_http_proxy_echo,
    Version::HTTP_2,
    HttpTargetKind::Tls,
    ProxyKind::Http
);
websocket_test!(
    ffi_contract_websocket_h2_tls_socks5_proxy_echo,
    Version::HTTP_2,
    HttpTargetKind::Tls,
    ProxyKind::Socks5
);

async fn run_websocket_case(version: Version, target: HttpTargetKind, proxy: ProxyKind) {
    let env = setup_env().await;
    let remote_port = match target {
        HttpTargetKind::Plain => env.ports.http,
        HttpTargetKind::Tls => env.ports.https,
    };
    let scheme = match target {
        HttpTargetKind::Plain => "ws",
        HttpTargetKind::Tls => "wss",
    };
    let ingress = spawn_ingress_listener(env.engine.clone(), localhost(remote_port)).await;
    let ingress_addr = ingress.local_addr();
    let client = build_http_client(match target {
        HttpTargetKind::Plain => None,
        HttpTargetKind::Tls => Some(load_mitm_ca_store()),
    });
    websocket_echo(
        &client,
        format!("{scheme}://127.0.0.1:{}/ws", ingress_addr.port()),
        version,
        proxy,
        localhost(env.ports.proxy),
    )
    .await;
    drop(client);
    ingress.shutdown().await;
}
