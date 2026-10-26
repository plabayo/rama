//! Upstream verification and unconditional SPKI rejection through the real FFI engine.
use crate::shared::{
    clients::UdpFfiSession,
    env::{AbortOnDrop, setup_env},
    ffi::{EngineHandle, engine_with_udp_quic_ports},
    ingress::spawn_ingress_listener,
};
use rama::{
    Layer as _, ServiceInput,
    crypto::{
        cert::{
            CertificateAuthorityData, CertificateValidity, LeafCertRequest,
            generate_certificate_authority,
        },
        pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject as _},
    },
    http::{
        Body, Request, Response,
        core::h3::{client, connection::Config},
        server::HttpServer,
    },
    net::{
        address::{Domain, Host, SocketAddress},
        tls::ApplicationProtocol,
    },
    quic::{ClientConfig, Endpoint, ServerConfig, tls::TlsOptions},
    rt::Executor,
    service::service_fn,
    tls::{
        boring::{
            client::{TlsConnectorData, tls_connect},
            core::x509::X509,
            server::TlsAcceptorLayer,
        },
        client::{ServerVerifyMode, TlsClientConfig},
        server::{ServerAuthData, TlsServerConfig},
    },
};
use serial_test::serial;
use std::{convert::Infallible, net::SocketAddr, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    time::timeout,
};

const LIMIT: Duration = Duration::from_secs(15);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Identity {
    Allowed,
    WrongName,
    Expired,
    Denied,
    DeniedIssuerOmitted,
}

fn identity(kind: Identity) -> (ServerAuthData, String) {
    let ca = if matches!(kind, Identity::Denied | Identity::DeniedIssuerOmitted) {
        CertificateAuthorityData::try_new(
            vec![
                CertificateDer::from_pem_slice(include_bytes!(
                    "../../../tproxy_rs/testdata/denied-ca.pem"
                ))
                .unwrap(),
            ],
            PrivateKeyDer::from_pem_slice(include_bytes!(
                "../../../tproxy_rs/testdata/denied-ca.key.pem"
            ))
            .unwrap(),
        )
        .unwrap()
    } else {
        let mut config = rama::crypto::cert::SelfSignedCaConfig::default();
        config.validity.not_before_skew = Duration::from_hours(24);
        generate_certificate_authority(config).unwrap()
    };
    let (ca_chain, key) = ca.into_parts();
    let pem = String::from_utf8(X509::from_der(&ca_chain[0]).unwrap().to_pem().unwrap()).unwrap();
    let ca = CertificateAuthorityData::try_new(ca_chain, key).unwrap();
    let mut leaf = if kind == Identity::WrongName {
        LeafCertRequest::new(Domain::from_static("different.example"))
    } else {
        LeafCertRequest::default()
    };
    if kind == Identity::Expired {
        leaf.config.validity =
            CertificateValidity::new(Duration::from_secs(60), Duration::from_secs(3600));
    }
    let (mut cert_chain, private_key) = ca.issue_leaf(leaf).unwrap();
    if kind == Identity::DeniedIssuerOmitted {
        cert_chain.truncate(1);
    }
    (
        ServerAuthData {
            cert_chain,
            private_key,
            ocsp: None,
        },
        pem,
    )
}

async fn origins(auth: ServerAuthData) -> (SocketAddr, SocketAddr, AbortOnDrop, Endpoint) {
    let exec = Executor::new();
    let tls = TlsServerConfig::new().with_server_auth(auth).with_alpn(
        [
            ApplicationProtocol::HTTP_3,
            ApplicationProtocol::HTTP_2,
            ApplicationProtocol::HTTP_11,
        ]
        .into_iter()
        .collect(),
    );
    let app = service_fn(async |_: Request| {
        Ok::<_, Infallible>(Response::new(Body::from("verified origin")))
    });
    let listener = rama::tcp::server::TcpListener::bind_address("127.0.0.1:0", exec.clone())
        .await
        .unwrap();
    let tcp = listener.local_addr().unwrap();
    let server = TlsAcceptorLayer::new(tls.clone())
        .into_layer(HttpServer::auto(exec.clone()).service(app.clone()));
    let tcp_task = tokio::spawn(async move {
        listener.serve(server).await;
    });
    let endpoint = Endpoint::build(exec.clone())
        .with_server_config(ServerConfig::try_from_rama_tls(&tls, TlsOptions::default()).unwrap())
        .bind_address(SocketAddress::local_ipv4(0))
        .await
        .unwrap();
    let udp = endpoint.local_addr().unwrap();
    let ep = endpoint.clone();
    let h3_task = tokio::spawn(async move {
        ep.serve(exec.clone(), HttpServer::new_http3(exec).service(app))
            .await;
    });
    (tcp, udp, AbortOnDrop(vec![tcp_task, h3_task]), endpoint)
}

async fn tcp_request(engine: Arc<EngineHandle>, origin: SocketAddr) -> bool {
    let ingress = spawn_ingress_listener(engine, origin).await;
    let result = timeout(LIMIT, async {
        let stream = tokio::net::TcpStream::connect(ingress.local_addr())
            .await
            .unwrap();
        let config = TlsClientConfig::new()
            .with_server_name(Host::from_static("localhost"))
            .with_server_verify(ServerVerifyMode::Disable);
        let Ok(mut stream) = tls_connect(
            ServiceInput::new(stream),
            Some(TlsConnectorData::try_from(&config).unwrap()),
        )
        .await
        else {
            return false;
        };
        if stream
            .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .await
            .is_err()
        {
            return false;
        }
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await.is_ok()
            && response
                .windows(b"verified origin".len())
                .any(|s| s == b"verified origin")
    })
    .await
    .expect("TCP certificate decision must finish");
    ingress.shutdown().await;
    result
}

async fn quic_request(engine: Arc<EngineHandle>, origin: SocketAddr) -> bool {
    let socket = UdpFfiSession::new(engine, origin).into_datagram_socket(origin);
    let endpoint = Endpoint::build(Executor::new())
        .with_datagram_socket(socket)
        .unwrap();
    let tls = TlsClientConfig::new()
        .with_server_verify(ServerVerifyMode::Disable)
        .with_alpn([ApplicationProtocol::HTTP_3].into_iter().collect());
    let config = ClientConfig::try_from_rama_tls(&tls, TlsOptions::default()).unwrap();
    let result = timeout(LIMIT, async {
        let Ok(connection) = endpoint
            .connect_with(config, origin, "localhost")
            .unwrap()
            .await
        else {
            return false;
        };
        let (mut client, driver) =
            client::handshake::<Body>(connection, Config::default(), Executor::new()).unwrap();
        let driver = tokio::spawn(driver.run());
        let result = client
            .send_request(
                Request::get("https://localhost/")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await;
        driver.abort();
        result.is_ok_and(|response| response.status().is_success())
    })
    .await
    .expect("QUIC certificate decision must finish");
    endpoint.close(0u32, b"done");
    endpoint.shutdown().await;
    result
}

#[tokio::test]
#[serial]
async fn ffi_contract_upstream_certificate_policy_tcp_and_quic() {
    drop(setup_env().await);
    // Identity, verify, add trust, expected.
    for (kind, verify, trust, expected) in [
        (Identity::Allowed, false, false, true),
        (Identity::Allowed, true, false, false),
        (Identity::Allowed, true, true, true),
        (Identity::WrongName, false, false, true),
        (Identity::WrongName, true, true, false),
        (Identity::Expired, false, false, true),
        (Identity::Expired, true, true, false),
        (Identity::Denied, false, false, false),
        (Identity::Denied, true, true, false),
        (Identity::DeniedIssuerOmitted, true, true, false),
        // A deny-only check cannot identify an issuer the peer withheld.
        (Identity::DeniedIssuerOmitted, false, false, true),
    ] {
        let (auth, ca) = identity(kind);
        let (tcp, udp, _tasks, endpoint) = origins(auth).await;
        let settings = serde_json::json!({"verify_upstream_certificates": verify, "upstream_test_ca_pem": if trust {Some(ca)} else {None}});
        let engine = tokio::task::spawn_blocking(move || {
            engine_with_udp_quic_ports(&[udp.port()], settings)
        })
        .await
        .unwrap();
        // Retry too: upstream rejection must never install a bypass exception.
        for _ in 0..2 {
            assert_eq!(
                tcp_request(engine.clone(), tcp).await,
                expected,
                "TCP {kind:?}, verify={verify}"
            );
            assert_eq!(
                quic_request(engine.clone(), udp).await,
                expected,
                "QUIC {kind:?}, verify={verify}"
            );
        }
        endpoint.close(0u32, b"done");
        endpoint.shutdown().await;
    }
}
