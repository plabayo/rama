use std::{sync::Arc, time::Duration};

use super::utils;

use rama::{
    Service,
    error::{BoxError, ErrorContext},
    extensions::ExtensionsMut,
    http::{
        Body, BodyExtractExt, Request, client::EasyHttpWebClient, server::HttpServer,
        service::web::Router,
    },
    net::{
        Protocol,
        address::{ProxyAddress, SocketAddress},
        tls::{
            ApplicationProtocol,
            client::ServerVerifyMode,
            server::{SelfSignedData, ServerAuth, ServerConfig},
        },
        user::{Basic, ProxyCredential},
    },
    rt::Executor,
    tcp::server::TcpListener,
    telemetry::tracing,
    tls::boring::{
        client::TlsConnectorDataBuilder,
        server::{TlsAcceptorData, TlsAcceptorService},
    },
    utils::str::non_empty_str,
};

#[tokio::test]
#[ignore]
async fn test_http_https_socks5_and_socks5h_connect_proxy() {
    utils::init_tracing();

    let runner = utils::ExampleRunner::interactive(
        "http_https_socks5_and_socks5h_connect_proxy",
        Some("socks5,dns,boring"),
    );

    // wait for example to run... this is dirty
    tokio::time::sleep(Duration::from_secs(10)).await;

    let http_socket_addr = spawn_http_server().await;
    let https_socket_addr = spawn_https_server().await;

    let test_uris = [
        format!("http://{http_socket_addr}/ping"),
        format!("https://{https_socket_addr}/ping"),
    ];

    for uri in test_uris.iter() {
        // test regular proxy flow
        let result = runner
            .get(uri)
            .extension(ProxyAddress::try_from("http://tom:clancy@127.0.0.1:62029").unwrap())
            .send()
            .await
            .unwrap()
            .try_into_string()
            .await
            .unwrap();
        assert_eq!("pong", result);
        tracing::info!("http ping-pong succeeded");
    }

    for uri in test_uris {
        // test regular proxy flow
        let result = runner
            .get(uri)
            .extension(ProxyAddress::try_from("https://tom:clancy@127.0.0.1:62029").unwrap())
            .send()
            .await
            .unwrap()
            .try_into_string()
            .await
            .unwrap();
        assert_eq!("pong", result);
        tracing::info!("https ping-pong succeeded");
    }

    test_http_client_over_socks5_proxy_connect(http_socket_addr, https_socket_addr).await;
}

async fn test_http_client_over_socks5_proxy_connect(
    http_socket_addr: SocketAddress,
    https_socket_addr: SocketAddress,
) {
    let proxy_socket_addr = SocketAddress::local_ipv4(62029);

    tracing::info!(
        "local servers up and running (http = {}; https = {}; proxy = {})",
        http_socket_addr,
        https_socket_addr,
        proxy_socket_addr,
    );

    let tls_config = TlsConnectorDataBuilder::new_http_auto()
        .with_store_server_certificate_chain(true)
        .with_server_verify_mode(ServerVerifyMode::Disable)
        .into_shared_builder();

    let client = EasyHttpWebClient::connector_builder()
        .with_default_transport_connector()
        .without_tls_proxy_support()
        .with_proxy_support()
        .with_tls_support_using_boringssl(Some(tls_config))
        .with_default_http_connector(Executor::default())
        .build_client();

    let test_uris = [
        format!("http://{http_socket_addr}/ping"),
        format!("https://{https_socket_addr}/ping"),
    ];
    for uri in test_uris {
        tracing::info!(
            url.full = %uri,
            "try to establish proxied connection over SOCKS5",
        );

        let mut request = Request::builder()
            .uri(uri.clone())
            .body(Body::empty())
            .expect("build simple GET request");

        request.extensions_mut().insert(ProxyAddress {
            protocol: Some(Protocol::SOCKS5),
            address: proxy_socket_addr.into(),
            credential: Some(ProxyCredential::Basic(Basic::new(
                non_empty_str!("john"),
                non_empty_str!("secret"),
            ))),
        });

        tracing::info!(
            url.full = %uri,
            "try to make GET http(s) request and try to receive response text",
        );

        let resp = client
            .serve(request)
            .await
            .expect("make http(s) request via socks5 proxy")
            .try_into_string()
            .await
            .expect("get response text");

        assert_eq!("pong", resp);
        tracing::info!("socks5 ping-pong succeeded")
    }
    tracing::info!("bye now!");
}

async fn spawn_http_server() -> SocketAddress {
    let tcp_service = TcpListener::bind(SocketAddress::default_ipv4(63179), Executor::default())
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
    let tcp_service = TcpListener::bind(SocketAddress::default_ipv4(63181), Executor::default())
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

fn try_new_tls_service_data() -> Result<TlsAcceptorData, BoxError> {
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
