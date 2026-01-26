use super::utils;

use rama::Layer as _;
use rama::http::BodyExtractExt;
use rama::http::server::HttpServer;
use rama::http::{StatusCode, service::web::IntoEndpointService, utils::HeaderValueGetter};
use rama::net::{address::HostWithPort, client::ConnectorTarget};
use rama::rt::Executor;
use rama::tcp::server::TcpListener;
use rama::tls::boring::server::TlsAcceptorLayer;
use rama_net::tls::ApplicationProtocol;
use rama_net::tls::server::{SelfSignedData, ServerAuth, ServerConfig};

#[tokio::test]
#[ignore]
async fn test_tls_sni_proxy_mitm() {
    utils::init_tracing();

    spawn_test_egres_server().await;

    let runner = utils::ExampleRunner::interactive_with_envs(
        "tls_sni_proxy_mitm",
        Some("boring"),
        [("EXAMPLE_EGRESS_SERVER_ADDR", "127.0.0.1:63015")],
    );

    // -- test example.com: hijacked completely (MITM)

    let resp_example_com = runner
        .get("https://example.com")
        .extension(ConnectorTarget(HostWithPort::local_ipv4(62045)))
        .send()
        .await
        .unwrap();
    assert_eq!(StatusCode::OK, resp_example_com.status());
    assert!(!resp_example_com.headers().contains_key("x-proxy-via"));

    let payload_example_com = resp_example_com.try_into_string().await.unwrap();
    assert!(payload_example_com.contains("Rama Example"));
    assert!(payload_example_com.contains("<h1>Example Domain</h1>"));
    assert!(payload_example_com.contains("Served by the Rama SNI TLS proxy Example"));

    // -- test ramaproxy.org: forwarded but with header added,
    // for both domain and subdomain

    for uri in [
        "https://ramaproxy.org",
        "https://echo.ramaproxy.org",
        "https://ipv4.ramaproxy.org/foo/bar",
    ] {
        let resp_ramaproxy_org = runner
            .get(uri)
            .extension(ConnectorTarget(HostWithPort::local_ipv4(62045)))
            .send()
            .await
            .unwrap();
        assert_eq!(StatusCode::OK, resp_ramaproxy_org.status());
        assert_eq!(
            "rama-sni-proxy-example",
            resp_ramaproxy_org.header_str("x-proxy-via").unwrap()
        );
    }

    // -- test plabayo.tech: should not be MITM'd at all

    let resp_plabayo_tech = runner
        .get("https://plabayo.tech")
        .extension(ConnectorTarget(HostWithPort::local_ipv4(62045)))
        .send()
        .await
        .unwrap();
    assert_eq!(StatusCode::OK, resp_plabayo_tech.status());
    assert!(!resp_plabayo_tech.headers().contains_key("x-proxy-via"));

    let payload_plabayo_tech = resp_plabayo_tech.try_into_string().await.unwrap();
    assert_eq!("tls-sni-proxy-mitm-example", payload_plabayo_tech.trim());
}

async fn spawn_test_egres_server() {
    let data = ServerConfig {
        application_layer_protocol_negotiation: Some(vec![
            ApplicationProtocol::HTTP_2,
            ApplicationProtocol::HTTP_11,
        ]),
        ..ServerConfig::new(ServerAuth::SelfSigned(SelfSignedData::default()))
    }
    .try_into()
    .unwrap();

    let tcp_service = TlsAcceptorLayer::new(data).into_layer(
        HttpServer::default().service("tls-sni-proxy-mitm-example".into_endpoint_service()),
    );

    let listener = TcpListener::bind("127.0.0.1:63015", Executor::default())
        .await
        .unwrap_or_else(|e| panic!("bind TCP Listener: secure web service: {e}"));

    tokio::spawn(listener.serve(tcp_service));
}
