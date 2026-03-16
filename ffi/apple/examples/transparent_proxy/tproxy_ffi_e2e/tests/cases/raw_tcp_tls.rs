//! Raw TCP/TLS E2E coverage.
//!
//! Matrix:
//! - transport: `plain`, `tls`
//! - proxy: `direct`, `http`, `socks5`

use serial_test::serial;

use crate::shared::{
    clients::roundtrip_custom_protocol,
    env::setup_env,
    ingress::spawn_ingress_listener,
    types::{ProxyKind, TcpMode, localhost},
};

macro_rules! raw_protocol_test {
    ($name:ident, $mode:expr, $proxy:expr) => {
        #[tokio::test]
        #[serial]
        async fn $name() {
            run_raw_protocol_case($mode, $proxy).await;
        }
    };
}

raw_protocol_test!(
    ffi_contract_raw_tcp_plain_direct_echo,
    TcpMode::Plain,
    ProxyKind::None
);
raw_protocol_test!(
    ffi_contract_raw_tcp_plain_http_proxy_echo,
    TcpMode::Plain,
    ProxyKind::Http
);
raw_protocol_test!(
    ffi_contract_raw_tcp_plain_socks5_proxy_echo,
    TcpMode::Plain,
    ProxyKind::Socks5
);
raw_protocol_test!(
    ffi_contract_raw_tls_direct_echo,
    TcpMode::Tls,
    ProxyKind::None
);
raw_protocol_test!(
    ffi_contract_raw_tls_http_proxy_echo,
    TcpMode::Tls,
    ProxyKind::Http
);
raw_protocol_test!(
    ffi_contract_raw_tls_socks5_proxy_echo,
    TcpMode::Tls,
    ProxyKind::Socks5
);

async fn run_raw_protocol_case(mode: TcpMode, proxy: ProxyKind) {
    let env = setup_env().await;
    let upstream_port = match mode {
        TcpMode::Plain => env.ports.raw_tcp,
        TcpMode::Tls => env.ports.raw_tls,
    };
    let ingress = spawn_ingress_listener(env.engine.clone(), localhost(upstream_port)).await;
    let ingress_addr = ingress.local_addr();
    let payload = match mode {
        TcpMode::Plain => b"hello raw ffi".as_slice(),
        TcpMode::Tls => b"hello raw tls ffi".as_slice(),
    };
    let echoed = roundtrip_custom_protocol(
        mode,
        proxy,
        ingress_addr.port(),
        ingress_addr,
        localhost(env.ports.proxy),
        payload,
    )
    .await;
    assert_eq!(echoed, payload);
    ingress.shutdown().await;
}
