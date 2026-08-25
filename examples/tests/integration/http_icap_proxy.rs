//! End-to-end test for the combined HTTP proxy and ICAP server example.

use std::{convert::Infallible, time::Duration};

use rama::{
    Layer as _,
    bytes::Bytes,
    extensions::ExtensionsRef as _,
    futures::stream,
    http::{
        Body, HeaderMap, HeaderValue, Request, Response, StatusCode, Version,
        body::{Frame, util::BodyExt as _},
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
    tls::{
        boring::server::TlsAcceptorLayer,
        server::{GeneratedServerAuthConfig, TlsServerConfig},
    },
};

use super::utils::{self, ExampleRunner};

const PROXY_URI: &str = "http://127.0.0.1:62061";

#[tokio::test]
#[ignore]
async fn test_http_icap_proxy() {
    utils::init_tracing();

    let (http_port, https_port, expected) = spawn_origins().await;
    let runner = ExampleRunner::interactive_with_args(
        "http_icap_proxy",
        Some("icap,boring"),
        ["--target-host", "localhost"],
    );
    wait_for_proxy().await;
    let proxy = ProxyAddress::try_from(PROXY_URI).unwrap();

    for version in [Version::HTTP_11, Version::HTTP_2] {
        for (scheme, origin_port) in [("http", http_port), ("https", https_port)] {
            println!("testing {version:?} {scheme} adapted response");
            let response = proxy_get(
                &runner.client,
                &proxy,
                scheme,
                "localhost",
                origin_port,
                "/adapted",
                version,
            )
            .await;
            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(response.version(), version);
            assert_eq!(response.headers()["x-rama-icap"], "adapted");
            let body = response.into_body().collect().await.unwrap();
            assert_eq!(body.to_bytes(), expected);

            println!("testing {version:?} {scheme} trailer response");
            let response = proxy_get(
                &runner.client,
                &proxy,
                scheme,
                "localhost",
                origin_port,
                "/trailers",
                version,
            )
            .await;
            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(response.version(), version);
            assert_eq!(response.headers()["x-rama-icap"], "adapted");
            let body = response.into_body().collect().await.unwrap();
            assert_eq!(body.trailers().unwrap()["x-end"], "kept");
            assert!(body.to_bytes().is_empty());

            println!("testing {version:?} {scheme} non-target passthrough");
            let response = proxy_get(
                &runner.client,
                &proxy,
                scheme,
                "127.0.0.1",
                origin_port,
                "/adapted",
                version,
            )
            .await;
            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(response.version(), version);
            assert!(!response.headers().contains_key("x-rama-icap"));
            let body = response.into_body().collect().await.unwrap();
            assert_eq!(body.to_bytes(), expected);
        }
    }
}

async fn proxy_get(
    client: &impl rama::Service<Request, Output = Response, Error: std::fmt::Debug>,
    proxy: &ProxyAddress,
    scheme: &str,
    origin_host: &str,
    origin_port: u16,
    path: &str,
    version: Version,
) -> Response {
    let request = Request::builder()
        .uri(format!("{scheme}://{origin_host}:{origin_port}{path}"))
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
            .connect(ConnectRequest::new(HostWithPort::local_ipv4(62061)))
            .await
            .is_ok()
        {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("proxy did not start");
}

async fn spawn_origins() -> (u16, u16, Bytes) {
    let http_listener =
        TcpListener::bind_address(SocketAddress::default_ipv4(0), Executor::default())
            .await
            .unwrap();
    let http_port = http_listener.local_addr().unwrap().port();
    let payload = Bytes::from("rama".repeat(1025));
    let http_server =
        HttpServer::auto(Executor::default()).service(origin_service(payload.clone()));
    tokio::spawn(http_listener.serve(http_server));

    let https_listener =
        TcpListener::bind_address(SocketAddress::default_ipv4(0), Executor::default())
            .await
            .unwrap();
    let https_port = https_listener.local_addr().unwrap().port();
    let tls = TlsServerConfig::new()
        .try_with_generated_server_auth(GeneratedServerAuthConfig::default())
        .unwrap()
        .with_alpn_http_auto();
    let https_server = TlsAcceptorLayer::new(tls)
        .into_layer(HttpServer::auto(Executor::default()).service(origin_service(payload.clone())));
    tokio::spawn(https_listener.serve(https_server));

    (http_port, https_port, payload)
}

fn origin_service(
    response_payload: Bytes,
) -> impl rama::Service<Request, Output = Response, Error = Infallible> + Clone {
    service_fn(move |request: Request| {
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
    })
}
