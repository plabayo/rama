use super::utils;

use rama::{
    Context, Service,
    http::{Body, BodyExtractExt, Request, client::HttpConnector},
    net::{
        Protocol,
        address::{ProxyAddress, SocketAddress},
        client::{ConnectorService, EstablishedClientConnection},
        user::{Basic, ProxyCredential},
    },
    proxy::socks5::Socks5ProxyConnector,
    tcp::client::service::TcpConnector,
    telemetry::tracing,
};

#[tokio::test]
#[ignore]
async fn test_proxy_connectivity_check() {
    utils::init_tracing();

    let runner = utils::ExampleRunner::interactive("proxy_connectivity_check", Some("socks5,tls"));

    let mut ctx = Context::default();
    ctx.insert(ProxyAddress::try_from("http://tom:clancy@127.0.0.1:62030").unwrap());
    // test regular proxy flow
    let result = runner
        .get("http://example.com")
        .send(ctx.clone())
        .await
        .unwrap()
        .try_into_string()
        .await
        .unwrap();
    assert!(result.contains("Connectivity Example"));
    tracing::info!("http proxy: connectivity check succeeded");

    test_http_client_over_socks5_proxy_connect().await;
}

async fn test_http_client_over_socks5_proxy_connect() {
    let proxy_socket_addr = SocketAddress::local_ipv4(62030);

    tracing::info!(
        network.local.address = %proxy_socket_addr.ip_addr(),
        network.local.port = %proxy_socket_addr.port(),
        "local servers up and running",
    );

    // TODO: once we have socks5 support in Easy http web client
    // we can probably simplify this by using the interactive runner client
    // instead of having to do this manually...

    let client = HttpConnector::new(Socks5ProxyConnector::required(TcpConnector::new()));

    let mut ctx = Context::default();
    ctx.insert(ProxyAddress {
        protocol: Some(Protocol::SOCKS5),
        authority: proxy_socket_addr.into(),
        credential: Some(ProxyCredential::Basic(Basic::new_static("john", "secret"))),
    });

    tracing::info!("try to establish proxied connection over SOCKS5");

    let request = Request::builder()
        .uri("http://example.com")
        .body(Body::empty())
        .expect("build simple GET request");

    let EstablishedClientConnection {
        ctx,
        req,
        conn: http_service,
    } = client
        .connect(ctx.clone(), request)
        .await
        .expect("establish a proxied connection ready to make http requests");

    tracing::info!("try to make GET http request and try to receive response text",);

    let resp = http_service
        .serve(ctx, req)
        .await
        .expect("make http request via socks5 proxy")
        .try_into_string()
        .await
        .expect("get response text");

    assert!(resp.contains("Connectivity Example"));
    tracing::info!("socks5 proxy: connectivity check succeeded");
}
