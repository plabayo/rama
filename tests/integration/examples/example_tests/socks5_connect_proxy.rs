use std::{sync::Arc, time::Duration};

use crate::examples::example_tests::utils::ExampleRunner;

use super::utils;

use rama::{
    Context,
    http::{BodyExtractExt, server::HttpServer, service::web::Router},
    net::{
        Protocol,
        address::{ProxyAddress, SocketAddress},
        user::{Basic, ProxyCredential},
    },
    rt::Executor,
    tcp::server::TcpListener,
    telemetry::tracing,
};

#[tokio::test]
#[ignore]
async fn test_socks5_connect_proxy() {
    utils::init_tracing();

    let runner = utils::ExampleRunner::interactive("socks5_connect_proxy", Some("socks5,dns"));

    // wait for example to run... this is dirty
    tokio::time::sleep(Duration::from_secs(10)).await;

    let http_socket_addr = spawn_http_server().await;

    test_http_client_over_socks5_proxy_connect(http_socket_addr, runner).await;
}

async fn test_http_client_over_socks5_proxy_connect(
    http_socket_addr: SocketAddress,
    runner: ExampleRunner,
) {
    let proxy_socket_addr = SocketAddress::local_ipv4(62021);

    tracing::info!(
        "local servers up and running (proxy = {}; http = {})",
        proxy_socket_addr,
        http_socket_addr,
    );

    let mut ctx = Context::default();
    ctx.insert(ProxyAddress {
        protocol: Some(Protocol::SOCKS5),
        authority: proxy_socket_addr.into(),
        credential: Some(ProxyCredential::Basic(Basic::new_static("john", "secret"))),
    });

    let uri = format!("http://{http_socket_addr}/ping");
    tracing::info!(
        url.full = %uri,
        "try to establish proxied connection over SOCKS5 within a TLS Tunnel",
    );

    tracing::info!(
        url.full = %uri,
        "try to make GET http request and try to receive response text",
    );

    let resp = runner
        .get(uri)
        .send(ctx)
        .await
        .expect("make http request via socks5 proxy")
        .try_into_string()
        .await
        .expect("get response text");

    assert_eq!("pong", resp);
    tracing::info!("ping-pong succeeded, bye now!")
}

async fn spawn_http_server() -> SocketAddress {
    let tcp_service = TcpListener::bind(SocketAddress::default_ipv4(63008))
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
