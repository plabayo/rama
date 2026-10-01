//! A pooled HTTP/2 connection admits requests by the streams actually open on it: a stream
//! that outlives its response (an upgraded tunnel, a request body still being sent) keeps its
//! slot, so ordinary requests open another connection instead of stalling behind it.

use super::{TEST_TIMEOUT, TlsAcceptorLayer, credentials};
use rama::{
    Layer,
    bytes::Bytes,
    futures::{StreamExt as _, stream},
    http::{
        Body, Method, Request, StatusCode, Version,
        body::util::BodyExt as _,
        client::{EasyHttpConnectorBuilder, HttpPooledConnectorConfig},
        conn::TargetHttpVersion,
        header::SEC_WEBSOCKET_VERSION,
        io::upgrade::handle_upgrade,
        layer::error_handling::ErrorHandlerLayer,
        proto::ext::Protocol,
        server::HttpServer,
        service::{client::HttpClientExt as _, web::Router},
        ws::handshake::server::WebSocketAcceptor,
    },
    layer::{ArcLayer, ConsumeErrLayer, MapInputLayer},
    net::address::SocketAddress,
    rt::Executor,
    tcp::{TcpStream, server::TcpListener},
    tls::server::{ServerAuthData, TlsServerConfig},
};
use std::{
    convert::Infallible,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};
use tokio::{
    task::{JoinHandle, spawn},
    time::timeout,
};

/// A TLS HTTP/2 server allowing one concurrent stream, and a pooled client for it.
struct OneStreamServer {
    port: u16,
    accepted: Arc<AtomicUsize>,
    server: JoinHandle<()>,
}

impl OneStreamServer {
    async fn start(auth: ServerAuthData) -> Self {
        let accepted = Arc::new(AtomicUsize::new(0));
        let mut http = HttpServer::new_h2(Executor::new());
        http.h2_mut().set_enable_connect_protocol();
        http.h2_mut().set_max_concurrent_streams(1);
        let service = (
            MapInputLayer::new({
                let accepted = accepted.clone();
                move |input: TcpStream| {
                    accepted.fetch_add(1, Ordering::SeqCst);
                    input
                }
            }),
            TlsAcceptorLayer::new(
                TlsServerConfig::new()
                    .with_server_auth(auth)
                    .with_alpn_http_2(),
            ),
        )
            .into_layer(
                http.service(
                    (ArcLayer::new(), ErrorHandlerLayer::new()).into_layer(
                        Router::new()
                            .with_get("/", "ordinary")
                            .with_connect(
                                "/tunnel",
                                ConsumeErrLayer::trace_as_debug()
                                    .into_layer(WebSocketAcceptor::new().into_echo_service()),
                            )
                            // Answers at once, and keeps reading the request body meanwhile.
                            .with_post("/upload", async |request: Request| {
                                spawn(async move {
                                    _ = request.into_body().collect().await;
                                });
                                "ok"
                            }),
                    ),
                ),
            );
        let listener = TcpListener::bind_address(SocketAddress::local_ipv4(0), Executor::new())
            .await
            .unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = spawn(listener.serve(service));
        Self {
            port,
            accepted,
            server,
        }
    }

    fn accepted(&self) -> usize {
        self.accepted.load(Ordering::SeqCst)
    }

    fn url(&self, path: &str) -> String {
        format!("https://localhost:{}{path}", self.port)
    }
}

impl Drop for OneStreamServer {
    fn drop(&mut self) {
        self.server.abort();
    }
}

/// A pooled HTTPS client trusting the test credentials, capped at two connections so a
/// request that finds both busy waits for a stream to retire instead of dialing a third.
macro_rules! client {
    ($tls:expr) => {{
        let tls = $tls;
        let builder = EasyHttpConnectorBuilder::new()
            .with_default_transport_connector()
            .with_default_dns_connector()
            .without_tls_proxy_support()
            .with_http_proxy_support();
        #[cfg(feature = "boring")]
        let builder = builder.with_tls_support_using_boringssl(tls);
        #[cfg(not(feature = "boring"))]
        let builder = builder.with_tls_support_using_rustls(tls);
        builder
            .with_default_http_connector(Executor::new())
            .try_with_connection_pool(HttpPooledConnectorConfig {
                max_total: 2,
                ..Default::default()
            })
            .unwrap()
            .build_client()
    }};
}

/// An ordinary request that completes, which it only can on a connection with a free stream.
macro_rules! ordinary {
    ($client:expr, $url:expr) => {{
        let request = $client
            .get($url)
            .version(Version::HTTP_2)
            .extension(TargetHttpVersion(Version::HTTP_2));
        let response = timeout(TEST_TIMEOUT, request.send())
            .await
            .expect("an ordinary request never stalls behind a live stream")
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(body, "ordinary");
    }};
}

#[tokio::test]
async fn an_upgraded_tunnel_keeps_its_stream_slot_after_its_response() {
    let (auth, tls) = credentials();
    let server = OneStreamServer::start(auth).await;
    let client = client!(tls);
    let response = timeout(
        TEST_TIMEOUT,
        client
            .request(Method::CONNECT, server.url("/tunnel"))
            .version(Version::HTTP_2)
            .extension(TargetHttpVersion(Version::HTTP_2))
            .extension(Protocol::WEBSOCKET)
            .header(SEC_WEBSOCKET_VERSION, "13")
            .send(),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let tunnel = timeout(TEST_TIMEOUT, handle_upgrade(&response))
        .await
        .unwrap()
        .unwrap();
    // The raw upgrade path: the response goes, the tunnel stays on the only stream.
    drop(response);
    ordinary!(client, server.url("/"));
    assert_eq!(server.accepted(), 2, "the busy connection was not used");

    // Keep the second connection busy with an upload that never ends, so only the tunnel's
    // connection can serve what follows once the tunnel ends.
    let upload = stream::once(async { Ok::<_, Infallible>(Bytes::from_static(b"part")) })
        .chain(stream::pending());
    let response = timeout(
        TEST_TIMEOUT,
        client
            .post(server.url("/upload"))
            .version(Version::HTTP_2)
            .extension(TargetHttpVersion(Version::HTTP_2))
            .body(Body::from_stream(upload))
            .send(),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    drop(response.into_body().collect().await.unwrap());
    assert_eq!(
        server.accepted(),
        2,
        "the upload took the second connection"
    );

    // Both connections are busy; the next request is served only once the tunnel's stream
    // retires and its connection admits again.
    drop(tunnel);
    ordinary!(client, server.url("/"));
    assert_eq!(server.accepted(), 2);
}

#[tokio::test]
async fn a_request_body_still_being_sent_keeps_its_stream_slot() {
    let (auth, tls) = credentials();
    let server = OneStreamServer::start(auth).await;
    let client = client!(tls);
    // One chunk, then the body never ends.
    let body = stream::once(async { Ok::<_, Infallible>(Bytes::from_static(b"part")) })
        .chain(stream::pending());
    let response = timeout(
        TEST_TIMEOUT,
        client
            .post(server.url("/upload"))
            .version(Version::HTTP_2)
            .extension(TargetHttpVersion(Version::HTTP_2))
            .body(Body::from_stream(body))
            .send(),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let answer = response.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(answer, "ok");
    // The response is complete, but the stream is not: the request body is still open.
    ordinary!(client, server.url("/"));
    assert_eq!(server.accepted(), 2, "the busy connection was not used");
}
