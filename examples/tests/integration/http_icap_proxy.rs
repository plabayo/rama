//! End-to-end test for the combined HTTP proxy and ICAP server example.

use std::{convert::Infallible, time::Duration};

use rama::{
    bytes::Bytes,
    extensions::ExtensionsRef as _,
    futures::stream,
    http::{
        Body, HeaderMap, HeaderValue, Request, Response, Version,
        body::{Frame, util::BodyExt as _},
        client::EasyHttpWebClient,
        conn::TargetHttpVersion,
        header,
        server::HttpServer,
    },
    net::{
        address::{HostWithPort, ProxyAddress, SocketAddress},
        client::{ConnectRequest, ConnectorService as _, ProxyRoute},
    },
    rt::Executor,
    service::service_fn,
    tcp::{client::service::TcpConnector, server::TcpListener},
};

use super::utils::{self, ExampleRunner};

const PROXY_URI: &str = "http://127.0.0.1:62059";

#[tokio::test]
#[ignore]
async fn test_http_icap_proxy() {
    utils::init_tracing();

    let (origin_port, expected) = spawn_origin().await;
    let _runner = ExampleRunner::interactive_with_args(
        "http_icap_proxy",
        Some("icap"),
        ["--target-host", "localhost"],
    );
    wait_for_proxy().await;
    let proxy = ProxyAddress::try_from(PROXY_URI).unwrap();
    let client = EasyHttpWebClient::connector_builder()
        .with_default_transport_connector()
        .with_default_dns_connector()
        .without_tls_proxy_support()
        .with_proxy_support()
        .without_tls_support()
        .with_default_http_connector(Executor::default())
        .without_connection_pool()
        .build_client();

    for version in [Version::HTTP_11, Version::HTTP_2] {
        println!("testing {version:?} adapted response");
        let response = proxy_get(
            &client,
            &proxy,
            "localhost",
            origin_port,
            "/adapted",
            version,
        )
        .await;
        assert_eq!(response.version(), version);
        assert_eq!(response.headers()["x-rama-icap"], "adapted");
        let body = response.into_body().collect().await.unwrap();
        assert_eq!(body.to_bytes(), expected);

        println!("testing {version:?} trailer response");
        let response = proxy_get(
            &client,
            &proxy,
            "localhost",
            origin_port,
            "/trailers",
            version,
        )
        .await;
        assert_eq!(response.version(), version);
        assert_eq!(response.headers()["x-rama-icap"], "adapted");
        let body = response.into_body().collect().await.unwrap();
        assert_eq!(body.trailers().unwrap()["x-end"], "kept");
        assert!(body.to_bytes().is_empty());

        println!("testing {version:?} non-target passthrough");
        let response = proxy_get(
            &client,
            &proxy,
            "127.0.0.1",
            origin_port,
            "/adapted",
            version,
        )
        .await;
        assert_eq!(response.version(), version);
        assert!(!response.headers().contains_key("x-rama-icap"));
        let body = response.into_body().collect().await.unwrap();
        assert_eq!(body.to_bytes(), expected);
    }
}

async fn proxy_get(
    client: &impl rama::Service<Request, Output = Response, Error: std::fmt::Debug>,
    proxy: &ProxyAddress,
    origin_host: &str,
    origin_port: u16,
    path: &str,
    version: Version,
) -> Response {
    let request = Request::builder()
        .uri(format!("http://{origin_host}:{origin_port}{path}"))
        .version(version)
        .header(header::TE, "trailers")
        .body(Body::empty())
        .unwrap();
    request
        .extensions()
        .insert(ProxyRoute::Proxy(proxy.clone()));
    request.extensions().insert(TargetHttpVersion(version));
    tokio::time::timeout(Duration::from_secs(10), client.serve(request))
        .await
        .unwrap_or_else(|_elapsed| panic!("{version:?} proxy request timed out for {path}"))
        .unwrap_or_else(|error| panic!("proxy request failed: {error:?}"))
}

async fn wait_for_proxy() {
    let connector = TcpConnector::new();
    for _attempt in 0..40 {
        if connector
            .connect(ConnectRequest::new(HostWithPort::local_ipv4(62059)))
            .await
            .is_ok()
        {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("proxy did not start");
}

async fn spawn_origin() -> (u16, Bytes) {
    let listener = TcpListener::bind_address(SocketAddress::default_ipv4(0), Executor::default())
        .await
        .unwrap();
    let port = listener.local_addr().unwrap().port();
    let payload = Bytes::from("rama".repeat(1025));
    let response_payload = payload.clone();
    let service = service_fn(move |request: Request| {
        let payload = response_payload.clone();
        async move {
            let trailer_only = request.uri().path().is_some_and(|path| path == "/trailers");
            let body = if trailer_only {
                let mut trailers = HeaderMap::new();
                trailers.insert("x-end", HeaderValue::from_static("kept"));
                Body::from_frame_stream(stream::iter([Ok::<_, Infallible>(Frame::trailers(
                    trailers,
                ))]))
            } else {
                Body::from(payload)
            };
            let mut response = Response::new(body);
            if trailer_only {
                response
                    .headers_mut()
                    .insert(header::TRAILER, HeaderValue::from_static("x-end"));
            } else {
                response
                    .headers_mut()
                    .insert(header::CONTENT_LENGTH, HeaderValue::from_static("4100"));
            }
            Ok::<_, Infallible>(response)
        }
    });
    let server = HttpServer::auto(Executor::default()).service(service);
    tokio::spawn(listener.serve(server));
    (port, payload)
}
