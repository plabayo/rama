//! A client's own MASQUE session crosses the FFI transparent proxy on every carrier.
use crate::shared::{
    clients::UdpFfiSession,
    env::{AbortOnDrop, setup_env},
    ffi::{engine_with_udp_quic_ports, mitm_ca_pem},
    ingress::spawn_ingress_listener,
};
use rama::{
    Layer as _, Service, ServiceInput,
    crypto::pki_types::{CertificateDer, pem::PemObject as _},
    extensions::ExtensionsRef as _,
    http::{
        Body, Request, Version,
        body::util::BodyExt as _,
        client::{http_connect, masque_quic_transport},
        conn::TargetHttpVersion,
        core::h3::{client, connection::Config},
        datagram::HttpDatagramSession,
        io::upgrade::handle_upgrade,
        layer::error_handling::ErrorHandlerLayer,
        proto::ext::HttpDatagrams,
        server::HttpServer,
    },
    net::{
        address::{Host, ProxyAddress, SocketAddress},
        tls::ApplicationProtocol,
    },
    proxy::masque::connect_udp::{
        ConnectUdpService, ConnectUdpSocket, ConnectUdpTarget, DestinationScopePolicy,
        connect_udp_request, session_config, validate_connect_udp_response,
    },
    quic::{ClientConfig, Endpoint, ServerConfig, tls::TlsOptions},
    rt::Executor,
    tls::{
        boring::{
            client::{TlsConnectorData, tls_connect},
            server::TlsAcceptorLayer,
        },
        client::{ServerVerifyMode, TlsClientConfig},
        server::{ServerAuthData, TlsServerConfig},
    },
};
use serial_test::serial;
use std::{net::SocketAddr, num::NonZeroU16, sync::Arc, time::Duration};
use tokio::time::timeout;

async fn proxy(native: bool) -> (SocketAddr, AbortOnDrop, Endpoint) {
    let exec = Executor::new();
    let service = Arc::new(
        ErrorHandlerLayer::new().into_layer(
            ConnectUdpService::try_new(exec.clone(), None)
                .unwrap()
                .with_policy(DestinationScopePolicy::allow_private()),
        ),
    );
    let tls = TlsServerConfig::new()
        .with_server_auth(ServerAuthData::new_generated(Default::default()).unwrap())
        .with_alpn(
            [
                ApplicationProtocol::HTTP_3,
                ApplicationProtocol::HTTP_2,
                ApplicationProtocol::HTTP_11,
            ]
            .into_iter()
            .collect(),
        );
    let mut h3 = HttpServer::new_http3(exec.clone());
    h3.http3_mut().extended_connect = true;
    if !native {
        h3.http3_mut().datagrams = None;
    }
    let mut transport = masque_quic_transport();
    h3.http3().configure_transport(&mut transport).unwrap();
    let mut config = ServerConfig::try_from_rama_tls(&tls, TlsOptions::default()).unwrap();
    config.set_transport_config(Arc::new(transport));
    let listener = rama::tcp::server::TcpListener::bind_address("127.0.0.1:0", exec.clone())
        .await
        .unwrap();
    let address = listener.local_addr().unwrap();
    let endpoint = Endpoint::build(exec.clone())
        .with_server_config(config)
        .bind_address(address)
        .await
        .unwrap();
    let mut http = HttpServer::auto(exec.clone());
    http.h2_mut().set_enable_connect_protocol();
    let tcp = TlsAcceptorLayer::new(tls).into_layer(http.service(service.clone()));
    let tcp = tokio::spawn(async move {
        listener.serve(tcp).await;
    });
    let udp = tokio::spawn(endpoint.clone().serve(exec, h3.service(service)));
    (address, AbortOnDrop(vec![tcp, udp]), endpoint)
}

#[tokio::test]
#[serial]
async fn ffi_contract_own_masque_session_on_every_carrier() {
    timeout(Duration::from_secs(120), async {
        drop(setup_env().await);
        let (origin, origin_task) = super::quic::spawn_h3_origin().await;
        let _origin = AbortOnDrop(vec![origin_task]);
        for (version, native) in [(Version::HTTP_11, false), (Version::HTTP_2, false), (Version::HTTP_3, false), (Version::HTTP_3, true)] {
            let (proxy, _tasks, server) = proxy(native).await;
            for intercepted in [false, true] {
                let settings = serde_json::json!({ "exclude_domains": if intercepted {vec![]} else {vec!["localhost"]} });
                let engine = tokio::task::spawn_blocking(move || engine_with_udp_quic_ports(&[proxy.port()], settings)).await.unwrap();
                let ingress = spawn_ingress_listener(engine.clone(), proxy).await;
                for _ in 0..3 {
                    let tls = if intercepted {
                        TlsClientConfig::new().try_with_server_trust_anchors([
                            CertificateDer::from_pem_slice(mitm_ca_pem().as_bytes()).unwrap()]).unwrap()
                    } else { TlsClientConfig::new().with_server_verify(ServerVerifyMode::Disable) };
                    let tls = tls.with_server_name(Host::from_static("localhost"));
                    let address: ProxyAddress = format!("masque://localhost:{}", proxy.port()).parse().unwrap();
                    let target = ConnectUdpTarget::new(Host::from(origin.ip()), NonZeroU16::new(origin.port()).unwrap());
                    let request = connect_udp_request(&address, &target, version).unwrap();
                    request.extensions().insert(HttpDatagrams);
                    request.extensions().insert(TargetHttpVersion(version));
                    let mut outer_endpoint = None;
                    let mut outer_driver = None;
                    let response = if version == Version::HTTP_3 {
                        let endpoint = Endpoint::build(Executor::new()).with_datagram_socket(
                            UdpFfiSession::new(engine.clone(), proxy).into_datagram_socket(proxy)).unwrap();
                        let tls = tls.with_alpn([ApplicationProtocol::HTTP_3].into_iter().collect());
                        let mut config = ClientConfig::try_from_rama_tls(&tls, TlsOptions::default()).unwrap();
                        config.set_transport_config(Arc::new(masque_quic_transport()));
                        let connection = endpoint.connect_with(config, proxy, "localhost").unwrap().await.unwrap();
                        let (mut client, driver) = client::handshake::<Body>(connection, Config::default(), Executor::new()).unwrap();
                        outer_driver = Some(tokio::spawn(driver.run()));
                        outer_endpoint = Some(endpoint);
                        client.send_request(request).await.unwrap().map(Body::new)
                    } else {
                        let stream = tokio::net::TcpStream::connect(ingress.local_addr()).await.unwrap();
                        let tls = tls.with_alpn([if version == Version::HTTP_2 { ApplicationProtocol::HTTP_2 } else { ApplicationProtocol::HTTP_11 }].into_iter().collect());
                        let stream = tls_connect(ServiceInput::new(stream), Some(TlsConnectorData::try_from(&tls).unwrap())).await.unwrap();
                        let established = http_connect::<_, _, Body>(stream, request, Executor::new()).await.unwrap();
                        established.conn.serve(established.input).await.unwrap()
                    };
                    validate_connect_udp_response(version, &response).unwrap();
                    let upgraded = handle_upgrade(&response).await.unwrap();
                    let socket = ConnectUdpSocket::new(&Executor::new(), HttpDatagramSession::with_config(upgraded, session_config()),
                        SocketAddress::local_ipv4(0), origin.into(), Default::default());
                    let inner = Endpoint::build(Executor::new()).with_datagram_socket(socket).unwrap();
                    let tls = TlsClientConfig::new().with_server_verify(ServerVerifyMode::Disable)
                        .with_alpn([ApplicationProtocol::HTTP_3].into_iter().collect());
                    let config = ClientConfig::try_from_rama_tls(&tls, TlsOptions::default()).unwrap();
                    let connection = inner.connect_with(config, origin, "localhost").unwrap().await.unwrap();
                    let (mut client, driver) = client::handshake::<Body>(connection, Config::default(), Executor::new()).unwrap();
                    let driver = tokio::spawn(driver.run());
                    let response = client.send_request(Request::get("https://localhost/").body(Body::empty()).unwrap()).await.unwrap();
                    assert_eq!(response.into_body().collect().await.unwrap().to_bytes(), "origin", "{version:?} native={native} intercepted={intercepted}");
                    drop(client);
                    inner.close(0u32, b"done");
                    inner.shutdown().await;
                    driver.abort();
                    if let Some(endpoint) = outer_endpoint { endpoint.close(0u32, b"done"); endpoint.shutdown().await; }
                    if let Some(driver) = outer_driver { driver.abort(); }
                }
                ingress.shutdown().await;
                timeout(Duration::from_secs(5), async {
                    while Arc::strong_count(&engine) > 1 { tokio::time::sleep(Duration::from_millis(10)).await; }
                }).await.expect("MASQUE flows release the engine");
                timeout(Duration::from_secs(5), tokio::task::spawn_blocking(move || drop(engine))).await.unwrap().unwrap();
            }
            server.close(0u32, b"done");
            server.shutdown().await;
        }
    }).await.unwrap();
}
