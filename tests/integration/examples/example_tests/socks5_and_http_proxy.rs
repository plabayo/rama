use super::utils;

use std::sync::Arc;

use rama::{
    Context, Service,
    http::{
        Body, BodyExtractExt, Request, client::HttpConnector, server::HttpServer,
        service::web::Router,
    },
    net::{
        Protocol,
        address::{ProxyAddress, SocketAddress},
        client::{ConnectorService, EstablishedClientConnection},
        user::{Basic, ProxyCredential},
    },
    proxy::socks5::Socks5ProxyConnector,
    rt::Executor,
    tcp::{client::service::TcpConnector, server::TcpListener},
    telemetry::tracing,
};

#[tokio::test]
#[ignore]
async fn test_socks5_and_http_proxy() {
    utils::init_tracing();

    let runner = utils::ExampleRunner::interactive("socks5_and_http_proxy", None);

    let http_socket_addr = spawn_http_server().await;

    let mut ctx = Context::default();
    ctx.insert(ProxyAddress::try_from("http://tom:clancy@127.0.0.1:62023").unwrap());

    // test regular proxy flow
    let uri = format!("http://{http_socket_addr}/ping");
    let result = runner
        .get(uri)
        .send(ctx.clone())
        .await
        .unwrap()
        .try_into_string()
        .await
        .unwrap();

    assert_eq!("pong", result);
    tracing::info!("http ping-pong succeeded, bye now!");

    test_http_client_over_socks5_proxy_connect(http_socket_addr).await;
}

async fn test_http_client_over_socks5_proxy_connect(http_socket_addr: SocketAddress) {
    let proxy_socket_addr = SocketAddress::local_ipv4(62023);

    tracing::info!(
        "local servers up and running (proxy = {} ; http = {})",
        proxy_socket_addr,
        http_socket_addr,
    );

    // TODO: once we have socks5 support in Easy http web client
    // we can probably simplify this by using the interactive runner client
    // instead of having to do this manually...

    let client = HttpConnector::new(Socks5ProxyConnector::required(TcpConnector::new()));

    let mut ctx = Context::default();
    ctx.insert(ProxyAddress {
        protocol: Some(Protocol::SOCKS5),
        authority: proxy_socket_addr.into(),
        credential: Some(ProxyCredential::Basic(Basic::new("john", "secret"))),
    });

    let uri = format!("http://{http_socket_addr}/ping");
    tracing::info!(
        url.full = %uri,
        "try to establish proxied connection over SOCKS5 within a TLS Tunnel",
    );

    let request = Request::builder()
        .uri(uri.clone())
        .body(Body::empty())
        .expect("build simple GET request");

    let EstablishedClientConnection {
        ctx,
        req,
        conn: http_service,
    } = client
        .connect(ctx, request)
        .await
        .expect("establish a proxied connection ready to make http requests");

    tracing::info!(
        url.full = %uri,
        "try to make GET http request and try to receive response text",
    );

    let resp = http_service
        .serve(ctx, req)
        .await
        .expect("make http request via socks5 proxy")
        .try_into_string()
        .await
        .expect("get response text");

    assert_eq!("pong", resp);
    tracing::info!("socks5 ping-pong succeeded, bye now!")
}

async fn spawn_http_server() -> SocketAddress {
    let tcp_service = TcpListener::bind(SocketAddress::default_ipv4(63007))
        .await
        .expect("bind HTTP server on open port");

    let bind_addr = tcp_service
        .local_addr()
        .expect("get bind address of http server")
        .into();

    let app = Router::new().get("/ping", "pong");
    let server = HttpServer::auto(Executor::default()).service(Arc::new(app));

    tokio::spawn(tcp_service.serve(server));

    bind_addr
}
