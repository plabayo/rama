//! rama's HTTP server and client over QUIC connections with reversed roles: the QUIC client
//! serves HTTP/3 and the QUIC server sends the requests.
#![expect(clippy::expect_used, reason = "test assertions identify failed stages")]

use rama_core::{
    Service,
    rt::{Executor, spawn},
    service::service_fn,
};
use rama_http::{Body, Request, Response, Version, body::util::BodyExt as _};
use rama_http_backend::{
    client::{Http3Transport, http_connect},
    server::HttpServer,
};
use rama_http_core::h3::{
    connection::Config,
    transport::{BoxedConnection, Reversed},
};
use rama_net::{address::SocketAddress, tls::ApplicationProtocol};
use rama_quic::{Connection, Endpoint, TransportConfig, tls::TlsOptions};
use rama_tls::{
    client::TlsClientConfig,
    server::{GeneratedServerAuthConfig, ServerAuthData, TlsServerConfig},
};
use rama_udp::test_utils::MemoryDatagramSocket;
use std::{convert::Infallible, num::NonZeroUsize, sync::Arc, time::Duration};
use tokio::time::timeout;

const LIMIT: Duration = Duration::from_secs(20);

#[tokio::test]
async fn http_server_and_client_run_over_reversed_quic_roles() {
    timeout(LIMIT, async {
        let quic = QuicPair::new(Reversed::application_protocol()).await;
        let mut server = HttpServer::new_http3(Executor::new());
        server.http3_mut().application_protocol = Reversed::application_protocol();
        let service = server.service(service_fn(echo));
        let served_by_quic_client = Reversed::new(quic.client.clone());
        let serving = spawn(async move { service.serve(served_by_quic_client).await });

        let transport = Http3Transport {
            connection: BoxedConnection::new(Reversed::new(quic.server.clone())),
            config: Arc::new(reversed_config()),
        };
        let client = http_connect::<_, _, Body>(transport, request("/", ""), Executor::new())
            .await
            .expect("HTTP/3 client")
            .conn;
        for path in ["/first", "/second"] {
            let response = client.serve(request(path, path)).await.expect("response");
            assert_eq!(response.version(), Version::HTTP_3);
            let body = response.into_body().collect().await.expect("body");
            assert_eq!(body.to_bytes(), path);
        }

        drop(client);
        serving.abort();
        quic.close().await;
    })
    .await
    .expect("reversed HTTP/3 deadline");
}

#[tokio::test]
async fn reversed_ends_refuse_a_plain_h3_peer_right_away() {
    timeout(LIMIT, async {
        let quic = QuicPair::new(ApplicationProtocol::HTTP_3).await;
        let mut server = HttpServer::new_http3(Executor::new());
        server.http3_mut().application_protocol = Reversed::application_protocol();
        let served = server
            .service(service_fn(echo))
            .serve(Reversed::new(quic.client.clone()))
            .await;
        assert!(served.is_err(), "the reversed server accepted plain h3");

        let transport = Http3Transport {
            connection: BoxedConnection::new(Reversed::new(quic.server.clone())),
            config: Arc::new(reversed_config()),
        };
        let connected =
            http_connect::<_, _, Body>(transport, request("/", ""), Executor::new()).await;
        assert!(connected.is_err(), "the reversed client accepted plain h3");
        quic.close().await;
    })
    .await
    .expect("a plain h3 peer must fail fast, not hang");
}

fn reversed_config() -> Config {
    Config {
        application_protocol: Reversed::application_protocol(),
        ..Config::default()
    }
}

async fn echo(request: Request) -> Result<Response, Infallible> {
    let body = request.into_body().collect().await.expect("request body");
    Ok(Response::new(Body::from(body.to_bytes())))
}

fn request(path: &str, body: &'static str) -> Request {
    Request::builder()
        .method("POST")
        .version(Version::HTTP_3)
        .uri(format!("https://localhost{path}"))
        .body(Body::from(body))
        .expect("request")
}

/// A connected in-memory QUIC pair.
struct QuicPair {
    client_endpoint: Endpoint,
    server_endpoint: Endpoint,
    client: Connection,
    server: Connection,
}

impl QuicPair {
    async fn new(alpn: ApplicationProtocol) -> Self {
        let identity = ServerAuthData::new_generated(GeneratedServerAuthConfig::default())
            .expect("server identity");
        let alpn = || [alpn.clone()].into_iter().collect();
        let server_tls = TlsServerConfig::new()
            .with_alpn(alpn())
            .with_server_auth(identity.clone());
        let client_tls = TlsClientConfig::new()
            .with_alpn(alpn())
            .try_with_server_trust_anchors([identity
                .cert_chain
                .last()
                .expect("certificate")
                .clone()])
            .expect("trust anchors");
        let transport = || {
            let mut transport = TransportConfig::default();
            Config::default()
                .configure_transport(&mut transport)
                .expect("transport config");
            Arc::new(transport)
        };
        let mut server_config =
            rama_quic::ServerConfig::try_from_rama_tls(&server_tls, TlsOptions::default())
                .expect("server config");
        server_config.set_transport_config(transport());
        let mut client_config =
            rama_quic::ClientConfig::try_from_rama_tls(&client_tls, TlsOptions::default())
                .expect("client config");
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
        let accept = spawn({
            let endpoint = server_endpoint.clone();
            async move {
                endpoint
                    .accept()
                    .await
                    .expect("incoming")
                    .await
                    .expect("accepted")
            }
        });
        let client = client_endpoint
            .connect_with(
                client_config,
                server_endpoint.local_addr().expect("server address"),
                "localhost",
            )
            .expect("connect")
            .await
            .expect("connected");
        let server = accept.await.expect("accept task");
        Self {
            client_endpoint,
            server_endpoint,
            client,
            server,
        }
    }

    async fn close(self) {
        self.client.close(0u32, b"test complete");
        tokio::join!(
            self.client_endpoint.shutdown(),
            self.server_endpoint.shutdown()
        );
    }
}
