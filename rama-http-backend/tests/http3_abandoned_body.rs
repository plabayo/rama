//! A pooled HTTP/3 connection survives its response bodies being dropped unread:
//! only the stream is cancelled, HTTP/1 body draining is not involved.

use rama_core::{
    Service,
    extensions::{Extensions, ExtensionsRef as _},
    rt::Executor,
    service::service_fn,
};
use rama_http::{Body, Request, Response, Version, body::util::BodyExt as _};
use rama_http_backend::{
    client::{Http3Transport, HttpConnectRequestAdapter, HttpConnector, HttpPooledConnectorConfig},
    server::HttpServer,
};
use rama_http_core::h3::connection::Config;
use rama_net::{
    address::SocketAddress,
    client::{
        ConnectRequest, ConnectionError, ConnectorService as _, EstablishedClientConnection,
        pool::{ConnectionReuse, ConnectionReusePolicy, ReuseKey},
    },
};
use rama_quic::{ClientConfig, Endpoint, ServerConfig, TransportConfig, tls::TlsOptions};
use rama_tls::{
    client::TlsClientConfig,
    server::{GeneratedServerAuthConfig, ServerAuthData, TlsServerConfig},
};
use rama_udp::test_utils::MemoryDatagramSocket;
use std::{
    convert::Infallible,
    num::NonZeroUsize,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::time::timeout;

const LIMIT: Duration = Duration::from_secs(5);

#[derive(Debug)]
struct FixedTlsPolicy;

impl ConnectionReusePolicy for FixedTlsPolicy {
    fn classifier(&self) -> ReuseKey {
        ReuseKey::of::<Self>()
    }

    fn connection_key(&self) -> Option<ReuseKey> {
        Some(ReuseKey::of::<Self>())
    }

    fn request_key(&self, _: &Extensions) -> Option<ReuseKey> {
        self.connection_key()
    }
}

#[tokio::test]
async fn pooled_http3_connection_survives_unread_response_bodies() {
    let identity = ServerAuthData::new_generated(GeneratedServerAuthConfig::default())
        .expect("server identity");
    let alpn = || [b"h3".as_slice().into()].into_iter().collect();
    let server_tls = TlsServerConfig::new()
        .with_alpn(alpn())
        .with_server_auth(identity.clone());
    let client_tls = TlsClientConfig::new()
        .with_alpn(alpn())
        .try_with_server_trust_anchors([identity.cert_chain.last().expect("certificate").clone()])
        .expect("trust anchors");
    let transport = || {
        let mut transport = TransportConfig::default();
        Config::default()
            .configure_transport(&mut transport)
            .expect("HTTP/3 transport config");
        Arc::new(transport)
    };
    let mut server_config = ServerConfig::try_from_rama_tls(&server_tls, TlsOptions::default())
        .expect("server TLS config");
    server_config.set_transport_config(transport());
    let mut client_config = ClientConfig::try_from_rama_tls(&client_tls, TlsOptions::default())
        .expect("client TLS config");
    client_config.set_transport_config(transport());
    let (server_socket, client_socket) = MemoryDatagramSocket::pair(
        SocketAddress::local_ipv4(443),
        SocketAddress::local_ipv4(444),
        NonZeroUsize::MIN,
    );
    let server_endpoint = Endpoint::build(Executor::new())
        .with_server_config(server_config)
        .with_datagram_socket(server_socket)
        .expect("server endpoint");
    let client_endpoint = Endpoint::build(Executor::new())
        .with_datagram_socket(client_socket)
        .expect("client endpoint");
    let address = server_endpoint.local_addr().expect("server address");
    let accepted = Arc::new(AtomicUsize::new(0));
    let server_task = tokio::spawn({
        let endpoint = server_endpoint.clone();
        let accepted = accepted.clone();
        async move {
            while let Some(incoming) = endpoint.accept().await {
                let connection = incoming.await.expect("accepted QUIC connection");
                accepted.fetch_add(1, Ordering::SeqCst);
                tokio::spawn(async move {
                    _ = HttpServer::new_http3(Executor::new())
                        .serve(
                            connection,
                            service_fn(async |request: Request| {
                                let body = if request.uri().path_or_root() == "/large" {
                                    Body::from(vec![0u8; 256 * 1024])
                                } else {
                                    Body::from("ok")
                                };
                                Ok::<_, Infallible>(Response::new(body))
                            }),
                        )
                        .await;
                });
            }
        }
    });
    let dials = Arc::new(AtomicUsize::new(0));
    let connector = service_fn({
        let endpoint = client_endpoint.clone();
        let dials = dials.clone();
        move |input: ConnectRequest| {
            let endpoint = endpoint.clone();
            let client_config = client_config.clone();
            let dials = dials.clone();
            async move {
                dials.fetch_add(1, Ordering::SeqCst);
                let connection = endpoint
                    .connect_with(client_config, address, "localhost")
                    .expect("start QUIC connection")
                    .await
                    .expect("connect QUIC");
                connection
                    .extensions()
                    .insert(ConnectionReuse::new(FixedTlsPolicy));
                Ok::<_, ConnectionError>(EstablishedClientConnection {
                    conn: Http3Transport {
                        connection,
                        config: Config::default().into(),
                    },
                    input,
                })
            }
        }
    });
    let client = HttpConnectRequestAdapter::new(
        HttpPooledConnectorConfig::default()
            .build_connector(HttpConnector::<_, Body>::new(connector, Executor::new())),
    );
    for path in ["/large", "/large", "/small"] {
        let request = Request::builder()
            .version(Version::HTTP_3)
            .uri(format!("https://localhost{path}"))
            .body(Body::empty())
            .expect("request");
        let EstablishedClientConnection { conn, input } = timeout(LIMIT, client.connect(request))
            .await
            .expect("pool checkout deadline")
            .expect("pool checkout");
        let response = timeout(LIMIT, conn.serve(input))
            .await
            .expect("request deadline")
            .expect("request");
        assert_eq!(response.version(), Version::HTTP_3);
        if path == "/small" {
            let body = timeout(LIMIT, response.into_body().collect())
                .await
                .expect("response body deadline")
                .expect("response body")
                .to_bytes();
            assert_eq!(body.as_ref(), b"ok");
        } else {
            // dropped unread
            drop(response);
        }
    }
    assert_eq!(dials.load(Ordering::SeqCst), 1);
    assert_eq!(accepted.load(Ordering::SeqCst), 1);
    drop(client);
    client_endpoint.close(0_u32, b"test complete");
    server_endpoint.close(0_u32, b"test complete");
    timeout(LIMIT, server_task)
        .await
        .expect("server shutdown deadline")
        .expect("server accept task");
}
