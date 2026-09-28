//! Extended CONNECT WebSockets (RFC 8441) share pooled HTTP/2 connections with ordinary requests.

use super::{TEST_TIMEOUT, TlsAcceptorLayer, credentials};
use rama::{
    Layer,
    extensions::Extensions,
    http::{
        StatusCode, Version,
        body::util::BodyExt as _,
        client::EasyHttpConnectorBuilder,
        conn::TargetHttpVersion,
        layer::error_handling::ErrorHandlerLayer,
        server::HttpServer,
        service::{client::HttpClientExt as _, web::Router},
        ws::{
            Message,
            handshake::{client::HttpClientWebSocketExt as _, server::WebSocketAcceptor},
        },
    },
    layer::{ArcLayer, ConsumeErrLayer, MapInputLayer},
    net::address::SocketAddress,
    rt::Executor,
    tcp::{TcpStream, server::TcpListener},
    tls::server::TlsServerConfig,
};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use tokio::{task::spawn, time::timeout};

/// One pooled H2 connection serves ordinary requests, a refused and two live WebSockets,
/// whichever kind opens it.
async fn check_one_pooled_connection(websocket_first: bool) {
    let (auth, tls) = credentials();
    let accepted = Arc::new(AtomicUsize::new(0));
    let mut http = HttpServer::new_h2(Executor::new());
    http.h2_mut().set_enable_connect_protocol();
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
                    Router::new().with_get("/", "ordinary").with_connect(
                        "/echo",
                        ConsumeErrLayer::trace_as_debug()
                            .into_layer(WebSocketAcceptor::new().into_echo_service()),
                    ),
                ),
            ),
        );
    let listener = TcpListener::bind_address(SocketAddress::local_ipv4(0), Executor::new())
        .await
        .unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = spawn(listener.serve(service));
    let builder = EasyHttpConnectorBuilder::new()
        .with_default_transport_connector()
        .with_default_dns_connector()
        .without_tls_proxy_support()
        .with_http_proxy_support();
    #[cfg(feature = "boring")]
    let builder = builder.with_tls_support_using_boringssl(tls);
    #[cfg(not(feature = "boring"))]
    let builder = builder.with_tls_support_using_rustls(tls);
    let client = builder
        .with_default_http_connector(Executor::new())
        .with_default_connection_pool()
        .build_client();
    let base = format!("https://localhost:{port}");
    let socket = format!("wss://localhost:{port}");

    let ordinary = async || {
        // Targeted like the WebSocket builder targets HTTP/2, so only the scheme differs.
        let request = client
            .get(base.as_str())
            .version(Version::HTTP_2)
            .extension(TargetHttpVersion(Version::HTTP_2));
        let response = timeout(TEST_TIMEOUT, request.send())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            (response.status(), response.version()),
            (StatusCode::OK, Version::HTTP_2)
        );
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(body, "ordinary");
    };
    let handshake = async |path: &str| {
        timeout(
            TEST_TIMEOUT,
            client
                .websocket_h2(format!("{socket}{path}"))
                .handshake(Extensions::new()),
        )
        .await
        .unwrap()
    };

    let (mut first, mut second) = if websocket_first {
        let first = handshake("/echo").await.unwrap();
        ordinary().await;
        assert!(handshake("/missing").await.is_err(), "no route refuses");
        (first, handshake("/echo").await.unwrap())
    } else {
        ordinary().await;
        assert!(handshake("/missing").await.is_err(), "no route refuses");
        (
            handshake("/echo").await.unwrap(),
            handshake("/echo").await.unwrap(),
        )
    };
    ordinary().await;
    for (socket, text) in [(&mut first, "first"), (&mut second, "second")] {
        socket.send_message(Message::text(text)).await.unwrap();
        let echo = timeout(TEST_TIMEOUT, socket.recv_message())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(echo.into_text().unwrap(), text);
    }
    drop((first, second));
    ordinary().await;
    assert_eq!(accepted.load(Ordering::SeqCst), 1, "one pooled connection");
    server.abort();
}

#[tokio::test]
async fn pooled_http2_connections_carry_websockets_between_ordinary_requests() {
    check_one_pooled_connection(false).await;
}

#[tokio::test]
async fn websockets_opening_the_pooled_http2_connection_share_it_with_ordinary_requests() {
    check_one_pooled_connection(true).await;
}
