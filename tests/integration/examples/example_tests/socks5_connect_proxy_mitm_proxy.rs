use std::{sync::Arc, time::Duration};

use crate::examples::example_tests::utils::ExampleRunner;

use super::utils;

use rama::{
    error::{ErrorContext, OpaqueError},
    http::{BodyExtractExt, server::HttpServer, service::web::Router},
    net::{
        Protocol,
        address::{ProxyAddress, SocketAddress},
        tls::{
            ApplicationProtocol,
            server::{SelfSignedData, ServerAuth, ServerConfig},
        },
        user::{Basic, ProxyCredential},
    },
    rt::Executor,
    tcp::server::TcpListener,
    telemetry::tracing,
    tls::boring::server::{TlsAcceptorData, TlsAcceptorService},
    utils::str::non_empty_str,
};

#[tokio::test]
#[ignore]
async fn test_socks5_connect_proxy_mitm_proxy() {
    utils::init_tracing();

    let runner = utils::ExampleRunner::interactive(
        "socks5_connect_proxy_mitm_proxy",
        Some("socks5,boring,dns"),
    );

    // wait for example to run... this is dirty
    tokio::time::sleep(Duration::from_secs(10)).await;

    let http_socket_addr = spawn_http_server().await;
    let https_socket_addr = spawn_https_server().await;

    test_http_client_over_socks5_proxy_connect_with_mitm_cap(
        http_socket_addr,
        https_socket_addr,
        runner,
    )
    .await;
}

async fn test_http_client_over_socks5_proxy_connect_with_mitm_cap(
    http_socket_addr: SocketAddress,
    https_socket_addr: SocketAddress,
    runner: ExampleRunner,
) {
    let proxy_socket_addr = SocketAddress::local_ipv4(62022);

    tracing::info!(
        "local servers up and running (proxy = {}; http = {}; https = {})",
        proxy_socket_addr,
        http_socket_addr,
        https_socket_addr,
    );

    let proxy_address = ProxyAddress {
        protocol: Some(Protocol::SOCKS5),
        address: proxy_socket_addr.into(),
        credential: Some(ProxyCredential::Basic(Basic::new(
            non_empty_str!("john"),
            non_empty_str!("secret"),
        ))),
    };

    let test_uris = [
        format!("http://{http_socket_addr}/ping"),
        format!("https://{https_socket_addr}/ping"),
    ];

    for uri in test_uris {
        tracing::info!(
            url.full = %uri,
            "try to establish proxied connection over SOCKS5 MITM Proxy",
        );

        tracing::info!(
            url.full = %uri,
            "try to make GET http(s) request and try to receive response text",
        );

        let resp = runner
            .get(uri)
            .extension(proxy_address.clone())
            .send()
            .await
            .expect("make http(s) request via socks5 proxy")
            .try_into_string()
            .await
            .expect("get response text");

        assert_eq!("pong", resp);
        tracing::info!("ping-pong succeeded");
    }

    tracing::info!("bye now!");
}

async fn spawn_http_server() -> SocketAddress {
    let tcp_service = TcpListener::bind(SocketAddress::default_ipv4(63009), Executor::default())
        .await
        .expect("bind HTTP server on open port");

    let bind_addr = tcp_service
        .local_addr()
        .expect("get bind address of http server")
        .into();

    let app = Router::new().with_get("/ping", "pong");
    let server = HttpServer::auto(Executor::default()).service(Arc::new(app));

    tokio::spawn(tcp_service.serve(server));

    bind_addr
}

async fn spawn_https_server() -> SocketAddress {
    let tcp_service = TcpListener::bind(SocketAddress::default_ipv4(63010), Executor::default())
        .await
        .expect("bind HTTP server on open port");

    let bind_addr = tcp_service
        .local_addr()
        .expect("get bind address of http server")
        .into();

    let app = Router::new().with_get("/ping", "pong");
    let http_server = HttpServer::auto(Executor::default()).service(Arc::new(app));

    let data = try_new_tls_service_data().expect("create tls service data");
    let https_server = TlsAcceptorService::new(data, http_server, false);

    tokio::spawn(tcp_service.serve(https_server));

    bind_addr
}

fn try_new_tls_service_data() -> Result<TlsAcceptorData, OpaqueError> {
    let tls_server_config = ServerConfig {
        application_layer_protocol_negotiation: Some(vec![
            ApplicationProtocol::HTTP_2,
            ApplicationProtocol::HTTP_11,
        ]),
        ..ServerConfig::new(ServerAuth::SelfSigned(SelfSignedData {
            organisation_name: Some("Socks5 Https Test Server".to_owned()),
            ..Default::default()
        }))
    };
    tls_server_config
        .try_into()
        .context("create tls server config")
}
