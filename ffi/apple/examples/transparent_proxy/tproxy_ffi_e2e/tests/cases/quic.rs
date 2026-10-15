//! QUIC through the example's per-destination UDP path: a QUIC client on one flow gets its
//! HTTP/3 terminated by the engine, which relays it to the real origin.

use std::{convert::Infallible, net::SocketAddr, sync::Arc, time::Duration};

use rama::{
    Service,
    crypto::pki_types::{CertificateDer, pem::PemObject as _},
    http::{
        Body, Request, Response, StatusCode,
        body::util::BodyExt as _,
        core::h3::{client as h3_client, connection::Config as H3Config},
        server::HttpServer,
    },
    net::{address::SocketAddress, tls::ApplicationProtocol},
    quic::{ClientConfig, Endpoint, ServerConfig, TransportConfig, tls::TlsOptions},
    rt::Executor,
    service::service_fn,
    tls::{
        client::TlsClientConfig,
        server::{ServerAuthData, TlsServerConfig},
    },
};
use serial_test::serial;
use tokio::{task::JoinHandle, time::timeout};

use crate::shared::{
    clients::UdpFfiSession,
    env::setup_env,
    ffi::{engine_with_udp_quic_ports, mitm_ca_pem},
};

const LIMIT: Duration = Duration::from_secs(30);

/// An HTTP/3 origin on loopback answering every request with `origin`.
async fn spawn_h3_origin() -> (SocketAddr, JoinHandle<()>) {
    let tls = TlsServerConfig::new()
        .with_server_auth(ServerAuthData::new_self_signed_leaf(Default::default()).unwrap())
        .with_alpn([ApplicationProtocol::HTTP_3].into_iter().collect());
    let server = HttpServer::new_http3(Executor::new());
    let mut transport = TransportConfig::default();
    server.http3().configure_transport(&mut transport).unwrap();
    let mut config = ServerConfig::try_from_rama_tls(&tls, TlsOptions::default()).unwrap();
    config.set_transport_config(Arc::new(transport));
    let endpoint = Endpoint::build(Executor::new())
        .with_server_config(config)
        .bind_address(SocketAddress::local_ipv4(0))
        .await
        .unwrap();
    let address = endpoint.local_addr().unwrap();
    let service = server.service(service_fn(async |_: Request| {
        Ok::<_, Infallible>(Response::new(Body::from("origin")))
    }));
    let handle = tokio::spawn(async move {
        while let Some(incoming) = endpoint.accept().await {
            let service = service.clone();
            tokio::spawn(async move {
                if let Ok(connection) = incoming.await {
                    drop(service.serve(connection).await);
                }
            });
        }
    });
    (address, handle)
}

#[tokio::test]
#[serial]
async fn ffi_contract_quic_h3_on_a_udp_flow_is_terminated_and_relayed() {
    // Initializes the FFI once for the binary; this test brings its own engine.
    drop(setup_env().await);
    let (origin, origin_task) = spawn_h3_origin().await;
    let port = origin.port();
    let engine = tokio::task::spawn_blocking(move || engine_with_udp_quic_ports(&[port]))
        .await
        .unwrap();
    let socket = UdpFfiSession::new(engine, origin).into_datagram_socket(origin);
    let client = Endpoint::build(Executor::new())
        .with_datagram_socket(socket)
        .unwrap();
    let ca = CertificateDer::from_pem_slice(mitm_ca_pem().as_bytes()).unwrap();
    let tls = TlsClientConfig::new()
        .try_with_server_trust_anchors([ca])
        .unwrap()
        .with_alpn([ApplicationProtocol::HTTP_3].into_iter().collect());
    let config = ClientConfig::try_from_rama_tls(&tls, TlsOptions::default()).unwrap();
    let connection = timeout(
        LIMIT,
        client.connect_with(config, origin, "localhost").unwrap(),
    )
    .await
    .expect("QUIC handshake through the engine")
    .unwrap();
    let (mut h3, driver) =
        h3_client::handshake::<Body>(connection, H3Config::default(), Executor::new()).unwrap();
    let driver = tokio::spawn(driver.run());
    let request = Request::get(format!("https://localhost:{port}/"))
        .body(Body::empty())
        .unwrap();
    let response = timeout(LIMIT, h3.send_request(request))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get("x-rama-mitm")
            .map(|value| value.to_str().unwrap()),
        Some("h3"),
        "the engine terminated HTTP/3"
    );
    let body = timeout(LIMIT, response.into_body().collect())
        .await
        .unwrap()
        .unwrap()
        .to_bytes();
    assert_eq!(&body[..], b"origin", "the engine relayed to the origin");
    drop(h3);
    client.close(0u32, b"done");
    client.shutdown().await;
    driver.abort();
    origin_task.abort();
}
