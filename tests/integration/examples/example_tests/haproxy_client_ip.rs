use std::net::IpAddr;

use super::utils;

use rama::{
    Service,
    extensions::ExtensionsMut,
    http::layer::required_header::AddRequiredRequestHeaders,
    http::{Body, BodyExtractExt, Request, client::HttpConnector},
    net::{
        client::{ConnectorService, EstablishedClientConnection},
        forwarded::{Forwarded, ForwardedElement},
    },
    proxy::haproxy::client::HaProxyService,
    tcp::client::service::TcpConnector,
};

#[tokio::test]
#[ignore]
async fn test_haproxy_client_ip() {
    utils::init_tracing();

    let runner = utils::ExampleRunner::interactive("haproxy_client_ip", None);

    // try direct
    let resp = runner
        .get("http://127.0.0.1:62025")
        .send()
        .await
        .expect("make http request")
        .try_into_string()
        .await
        .expect("get response text");
    assert_eq!("127.0.0.1", resp);

    // try with haproxy prefixes
    test_server_with_haproxy_v1().await;
    test_server_with_haproxy_v2().await;
}

async fn test_server_with_haproxy_v1() {
    let client = HttpConnector::new(HaProxyService::tcp(TcpConnector::new()).v1());

    let mut request = Request::builder()
        .uri("http://127.0.0.1:62025")
        .method("GET")
        .header("Connection", "close")
        .body(Body::empty())
        .expect("build simple GET request");

    request
        .extensions_mut()
        .insert(Forwarded::new(ForwardedElement::forwarded_for((
            IpAddr::V4([1u8, 2u8, 3u8, 4u8].into()),
            0,
        ))));

    let EstablishedClientConnection {
        req,
        conn: http_service,
    } = client
        .connect(request)
        .await
        .expect("establish a connection to the http server using haproxy v1");

    let resp = AddRequiredRequestHeaders::new(http_service)
        .serve(req)
        .await
        .expect("make http request")
        .try_into_string()
        .await
        .expect("get response text");

    assert_eq!("1.2.3.4", resp);
}

async fn test_server_with_haproxy_v2() {
    let client = HttpConnector::new(HaProxyService::tcp(TcpConnector::new()));

    let mut request = Request::builder()
        .uri("http://127.0.0.1:62025")
        .method("GET")
        .header("Connection", "close")
        .body(Body::empty())
        .expect("build simple GET request");

    request
        .extensions_mut()
        .insert(Forwarded::new(ForwardedElement::forwarded_for((
            IpAddr::V4([2u8, 3u8, 4u8, 5u8].into()),
            0,
        ))));

    let EstablishedClientConnection {
        req,
        conn: http_service,
    } = client
        .connect(request)
        .await
        .expect("establish a connection to the http server using haproxy v2");

    let resp = AddRequiredRequestHeaders::new(http_service)
        .serve(req)
        .await
        .expect("make http request")
        .try_into_string()
        .await
        .expect("get response text");

    assert_eq!("2.3.4.5", resp);
}
