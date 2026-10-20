//! QUIC through the example's per-destination UDP path: a QUIC client on one flow gets its
//! HTTP/3 terminated by the engine, which relays it to the real origin, unless the policy
//! or admission leaves it untouched.

use std::{
    convert::Infallible,
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};

use rama::{
    Service,
    bytes::Bytes,
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
        client::{ServerVerifyMode, TlsClientConfig},
        server::{ServerAuthData, TlsServerConfig},
    },
    udp::{DatagramSenderExt as _, DatagramSocket as _, DatagramSocketExt as _, SendDatagram},
};
use serial_test::serial;
use tokio::{net::UdpSocket, task::JoinHandle, time::timeout};

use crate::shared::{
    clients::UdpFfiSession,
    env::setup_env,
    ffi::{EngineHandle, engine_with_udp_quic_ports, mitm_ca_pem},
};

const LIMIT: Duration = Duration::from_secs(30);
/// The bound the Swift lifecycle suite holds an engine detach to.
const STOP_LIMIT: Duration = Duration::from_secs(5);

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

/// An engine serving the origin's port on its QUIC path, with `settings` overriding its config.
async fn engine_for(origin: SocketAddr, settings: serde_json::Value) -> Arc<EngineHandle> {
    // Initializes the FFI once for the binary; each test brings its own engine.
    drop(setup_env().await);
    let port = origin.port();
    tokio::task::spawn_blocking(move || engine_with_udp_quic_ports(&[port], settings))
        .await
        .unwrap()
}

/// One HTTP/3 GET to `origin` on an FFI UDP flow of `engine`: the `x-rama-mitm` header the
/// response carries, if any, and its body.
async fn h3_get(
    engine: Arc<EngineHandle>,
    origin: SocketAddr,
    tls: TlsClientConfig,
) -> (Option<String>, Bytes) {
    let socket = UdpFfiSession::new(engine, origin).into_datagram_socket(origin);
    let client = Endpoint::build(Executor::new())
        .with_datagram_socket(socket)
        .unwrap();
    let tls = tls.with_alpn([ApplicationProtocol::HTTP_3].into_iter().collect());
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
    let request = Request::get(format!("https://localhost:{}/", origin.port()))
        .body(Body::empty())
        .unwrap();
    let response = timeout(LIMIT, h3.send_request(request))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let marker = response
        .headers()
        .get("x-rama-mitm")
        .map(|value| value.to_str().unwrap().to_owned());
    let body = timeout(LIMIT, response.into_body().collect())
        .await
        .unwrap()
        .unwrap()
        .to_bytes();
    drop(h3);
    client.close(0u32, b"done");
    client.shutdown().await;
    driver.abort();
    (marker, body)
}

/// A client that trusts the engine's MITM CA, as an app with it installed does.
fn trusting_the_mitm_ca() -> TlsClientConfig {
    let ca = CertificateDer::from_pem_slice(mitm_ca_pem().as_bytes()).unwrap();
    TlsClientConfig::new()
        .try_with_server_trust_anchors([ca])
        .unwrap()
}

/// A client that reaches the origin's self-signed certificate when it is not intercepted.
fn without_verification() -> TlsClientConfig {
    TlsClientConfig::new().with_server_verify(ServerVerifyMode::Disable)
}

#[tokio::test]
#[serial]
async fn ffi_contract_quic_h3_on_a_udp_flow_is_terminated_and_relayed() {
    let (origin, origin_task) = spawn_h3_origin().await;
    let engine = engine_for(origin, serde_json::json!({})).await;
    let (marker, body) = h3_get(engine, origin, trusting_the_mitm_ca()).await;
    assert_eq!(
        marker.as_deref(),
        Some("h3"),
        "the engine terminated HTTP/3"
    );
    assert_eq!(&body[..], b"origin", "the engine relayed to the origin");
    origin_task.abort();
}

#[tokio::test]
#[serial]
async fn ffi_contract_quic_to_an_excluded_name_is_forwarded_untouched() {
    let (origin, origin_task) = spawn_h3_origin().await;
    let engine = engine_for(
        origin,
        serde_json::json!({ "exclude_domains": ["localhost"] }),
    )
    .await;
    let (marker, body) = h3_get(engine, origin, without_verification()).await;
    assert_eq!(marker, None, "an excluded name is not intercepted");
    assert_eq!(&body[..], b"origin");
    origin_task.abort();
}

#[tokio::test]
#[serial]
async fn ffi_contract_quic_refused_by_admission_is_forwarded_untouched() {
    let (origin, origin_task) = spawn_h3_origin().await;
    let engine = engine_for(origin, serde_json::json!({ "concurrency_global_limit": 0 })).await;
    let (marker, body) = h3_get(engine, origin, without_verification()).await;
    assert_eq!(
        marker, None,
        "an intercept the limiter refuses passes through"
    );
    assert_eq!(&body[..], b"origin");
    origin_task.abort();
}

/// A UDP origin on loopback echoing every datagram back to its sender.
async fn spawn_udp_echo() -> (SocketAddr, JoinHandle<()>) {
    let origin = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = origin.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        let mut buffer = [0; 2048];
        loop {
            let (len, peer) = origin.recv_from(&mut buffer).await.unwrap();
            origin.send_to(&buffer[..len], peer).await.unwrap();
        }
    });
    (address, handle)
}

/// `payload` sent to a UDP echo origin on the engine's QUIC port comes back untouched.
async fn echoed_through_the_quic_path(payload: &[u8]) {
    let (address, echo) = spawn_udp_echo().await;
    let engine = engine_for(address, serde_json::json!({})).await;
    let mut socket = UdpFfiSession::new(engine, address).into_datagram_socket(address);
    socket
        .create_sender()
        .send(SendDatagram::new(address, payload))
        .await
        .unwrap();
    let mut buffer = [0; 2048];
    let metadata = timeout(LIMIT, socket.recv(&mut buffer))
        .await
        .expect("the echo comes back through the engine")
        .unwrap();
    assert_eq!(&buffer[..metadata.len], payload);
    assert_eq!(metadata.peer, SocketAddress::from(address));
    echo.abort();
}

#[tokio::test]
#[serial]
async fn ffi_contract_non_quic_on_a_quic_port_is_forwarded_untouched() {
    echoed_through_the_quic_path(b"not quic").await;
}

/// QUIC the engine cannot inspect, such as a version it does not implement, is forwarded as
/// the TCP path passes through what it cannot peek: the server's version negotiation must reach
/// the client.
#[tokio::test]
#[serial]
async fn ffi_contract_quic_of_an_unknown_version_is_forwarded_untouched() {
    let mut packet = vec![0xc0, 0x1a, 0x2a, 0x3a, 0x4a, 8];
    packet.extend_from_slice(&[1; 8]);
    packet.push(8);
    packet.extend_from_slice(&[2; 8]);
    packet.resize(1200, 0);
    echoed_through_the_quic_path(&packet).await;
}

/// An engine whose UDP flows took the QUIC path stops promptly: no long-lived service holds
/// its shutdown, as one keeping the engine's own executor would.
#[tokio::test]
#[serial]
async fn ffi_contract_an_engine_that_served_quic_stops_promptly() {
    let (origin, origin_task) = spawn_h3_origin().await;
    let engine = engine_for(origin, serde_json::json!({})).await;
    let (marker, _) = h3_get(engine.clone(), origin, trusting_the_mitm_ca()).await;
    assert_eq!(marker.as_deref(), Some("h3"));
    timeout(LIMIT, async {
        while Arc::strong_count(&engine) > 1 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the flow releases the engine");
    let started = Instant::now();
    timeout(LIMIT, tokio::task::spawn_blocking(move || drop(engine)))
        .await
        .expect("the engine stops")
        .unwrap();
    let elapsed = started.elapsed();
    assert!(elapsed < STOP_LIMIT, "stopping took {elapsed:?}");
    origin_task.abort();
}
