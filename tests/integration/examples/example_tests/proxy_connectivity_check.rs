use crate::examples::example_tests::utils::ExampleRunner;

use super::utils;

use rama::{
    Context,
    http::BodyExtractExt,
    net::{
        Protocol,
        address::{ProxyAddress, SocketAddress},
        user::{Basic, ProxyCredential},
    },
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

    test_http_client_over_socks5_proxy_connect(runner).await;
}

async fn test_http_client_over_socks5_proxy_connect(runner: ExampleRunner) {
    let proxy_socket_addr = SocketAddress::local_ipv4(62030);

    tracing::info!(
        network.local.address = %proxy_socket_addr.ip_addr(),
        network.local.port = %proxy_socket_addr.port(),
        "local servers up and running",
    );

    let mut ctx = Context::default();
    ctx.insert(ProxyAddress {
        protocol: Some(Protocol::SOCKS5),
        authority: proxy_socket_addr.into(),
        credential: Some(ProxyCredential::Basic(Basic::new_static("john", "secret"))),
    });

    let resp = runner
        .get("http://example.com")
        .send(ctx)
        .await
        .expect("make http request via socks5 proxy")
        .try_into_string()
        .await
        .expect("get response text");

    assert!(resp.contains("Connectivity Example"));
    tracing::info!("socks5 proxy: connectivity check succeeded");
}
