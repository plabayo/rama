use std::{sync::Arc, time::Duration};

use super::utils;

use rama::{
    Context, Service,
    error::{ErrorContext, OpaqueError},
    http::{
        Body, BodyExtractExt, Request, client::HttpConnector, server::HttpServer,
        service::web::Router,
    },
    net::{
        Protocol,
        address::{ProxyAddress, SocketAddress},
        client::{ConnectorService, EstablishedClientConnection},
        tls::{
            ApplicationProtocol,
            client::ServerVerifyMode,
            server::{SelfSignedData, ServerAuth, ServerConfig},
        },
        user::{Basic, ProxyCredential},
    },
    proxy::socks5::Socks5ProxyConnector,
    rt::Executor,
    tcp::{client::service::TcpConnector, server::TcpListener},
    telemetry::tracing,
    tls::boring::{
        client::{TlsConnector, TlsConnectorDataBuilder},
        server::{TlsAcceptorData, TlsAcceptorService},
    },
};

#[tokio::test]
#[ignore]
async fn test_socks5_connect_proxy_mitm_proxy() {
    utils::init_tracing();

    let _runner = utils::ExampleRunner::<()>::interactive(
        "socks5_connect_proxy_mitm_proxy",
        Some("socks5,boring,dns"),
    );

    // wait for example to run... this is dirty
    tokio::time::sleep(Duration::from_secs(10)).await;

    let http_socket_addr = spawn_http_server().await;
    let https_socket_addr = spawn_https_server().await;

    test_http_client_over_socks5_proxy_connect_with_mitm_cap(http_socket_addr, https_socket_addr)
        .await;
}

async fn test_http_client_over_socks5_proxy_connect_with_mitm_cap(
    http_socket_addr: SocketAddress,
    https_socket_addr: SocketAddress,
) {
    let proxy_socket_addr = SocketAddress::local_ipv4(62022);

    tracing::info!(
        %proxy_socket_addr,
        %http_socket_addr,
        %https_socket_addr,
        "local servers up and running",
    );

    // TODO: once we have socks5 support in Easy http web client
    // we can probably simplify this by using the interactive runner client
    // instead of having to do this manually...

    let tls_config = TlsConnectorDataBuilder::new_http_auto()
        .with_store_server_certificate_chain(true)
        .with_server_verify_mode(ServerVerifyMode::Disable)
        .into_shared_builder();

    let client = HttpConnector::new(
        TlsConnector::auto(Socks5ProxyConnector::required(TcpConnector::new()))
            .with_connector_data(tls_config),
    );

    let mut ctx = Context::default();
    ctx.insert(ProxyAddress {
        protocol: Some(Protocol::SOCKS5),
        authority: proxy_socket_addr.into(),
        credential: Some(ProxyCredential::Basic(Basic::new("john", "secret"))),
    });

    let test_uris = [
        format!("http://{http_socket_addr}/ping"),
        format!("https://{https_socket_addr}/ping"),
    ];

    for uri in test_uris {
        tracing::info!(
            %uri,
            "try to establish proxied connection over SOCKS5 MITM Proxy",
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
            .connect(ctx.clone(), request)
            .await
            .expect("establish a proxied connection ready to make http(s) requests");

        tracing::info!(
            %uri,
            "try to make GET http(s) request and try to receive response text",
        );

        let resp = http_service
            .serve(ctx, req)
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
    let tcp_service = TcpListener::bind(SocketAddress::default_ipv4(63009))
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

async fn spawn_https_server() -> SocketAddress {
    let tcp_service = TcpListener::bind(SocketAddress::default_ipv4(63010))
        .await
        .expect("bind HTTP server on open port");

    let bind_addr = tcp_service
        .local_addr()
        .expect("get bind address of http server")
        .into();

    let app = Router::new().get("/ping", "pong");
    let http_server = HttpServer::auto(Executor::default()).service(Arc::new(app));

    let data = new_tls_service_data().expect("create tls service data");
    let https_server = TlsAcceptorService::new(data, http_server, false);

    tokio::spawn(tcp_service.serve(https_server));

    bind_addr
}

fn new_tls_service_data() -> Result<TlsAcceptorData, OpaqueError> {
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
