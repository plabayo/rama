use std::{
    convert::Infallible,
    time::{Duration, Instant},
};

use tokio::time::sleep;

use rama_core::{Layer, graceful::Shutdown, layer::ArcLayer};
use rama_core::{Service, rt::Executor, service::service_fn};
use rama_core::{futures::future::join, layer::ConsumeErrLayer};
use rama_http::{
    HeaderName, HeaderValue,
    body::util::BodyExt as _,
    layer::set_header::{SetRequestHeaderLayer, SetResponseHeaderLayer},
};
use rama_http_types::{Body, Request, Response, StatusCode, Version};
use rama_net::{
    proxy::StreamBridge,
    test_utils::client::{MockConnectorService, MockSocket},
};
use tokio_util::sync::CancellationToken;

use crate::proxy::mitm::DefaultErrorResponse;

use super::{
    client::{HttpConnectorLayer, http_connect},
    proxy::mitm::HttpMitmRelay,
    server::HttpServer,
};

#[tokio::test]
async fn test_http11_pipelining() {
    let connector = HttpConnectorLayer::default().into_layer(MockConnectorService::new(|| {
        HttpServer::auto(Executor::default()).service(service_fn(server_svc_fn))
    }));

    let conn = connector
        .serve(create_test_request(Version::HTTP_11))
        .await
        .unwrap()
        .conn;

    // Http 1.1 should pipeline requests. Pipelining is important when trying to send multiple
    // requests on the same connection. This is something we generally don't do, but we do
    // trigger the same problem when we re-use a connection too fast. However triggering that
    // bug consistently has proven very hard so we trigger this one instead. Both of them
    // should be fixed by waiting for conn.isready().await before trying to send data on the connection.
    // For http1.1 this will result in pipelining (http2 will still be multiplexed)
    let start = Instant::now();
    let (res1, res2) = join(
        conn.serve(create_test_request(Version::HTTP_11)),
        conn.serve(create_test_request(Version::HTTP_11)),
    )
    .await;
    let duration = start.elapsed();

    res1.unwrap();
    res2.unwrap();

    assert!(duration > Duration::from_millis(200));
}

#[tokio::test]
async fn test_http2_multiplex() {
    let connector = HttpConnectorLayer::default().into_layer(MockConnectorService::new(|| {
        HttpServer::auto(Executor::default()).service(service_fn(server_svc_fn))
    }));

    let conn = connector
        .serve(create_test_request(Version::HTTP_2))
        .await
        .unwrap()
        .conn;

    // We have an artificial sleep of 100ms, so multiplexing should be < 200ms
    let start = Instant::now();
    let (res1, res2) = join(
        conn.serve(create_test_request(Version::HTTP_2)),
        conn.serve(create_test_request(Version::HTTP_2)),
    )
    .await;

    let duration = start.elapsed();
    res1.unwrap();
    res2.unwrap();

    assert!(duration < Duration::from_millis(200));
}

async fn server_svc_fn(_: Request) -> Result<Response, Infallible> {
    sleep(Duration::from_millis(100)).await;
    Ok(Response::new(Body::from("a random response body")))
}

async fn mitm_relay_server_svc_fn(req: Request) -> Result<Response, Infallible> {
    assert!(req.headers().contains_key("x-observed-req"));
    Ok(Response::new(Body::from("a random response body")))
}

fn create_test_request(version: Version) -> Request {
    Request::builder()
        .uri("https://www.example.com")
        .version(version)
        .body(Body::from("a reandom request body"))
        .unwrap()
}

async fn test_mitm_relay_roundtrip_inner(version: Version) {
    let (client_stream, relay_ingress_stream) = tokio::io::duplex(16 * 1024);
    let (relay_egress_stream, server_stream) = tokio::io::duplex(16 * 1024);

    let token = CancellationToken::new();
    let graceful = Shutdown::new(token.clone().cancelled_owned());
    let cancel_drop_guard = token.drop_guard();

    graceful.spawn_task_fn(async move |guard| {
        HttpServer::auto(Executor::graceful(guard))
            .service(service_fn(mitm_relay_server_svc_fn))
            .serve(MockSocket::new(server_stream))
            .await
            .unwrap();
    });

    graceful.spawn_task_fn(async move |guard| {
        HttpMitmRelay::new(Executor::graceful(guard))
            .with_http_middleware((
                ConsumeErrLayer::trace_as_debug().with_response(DefaultErrorResponse::new()),
                SetRequestHeaderLayer::overriding(
                    HeaderName::from_static("x-observed-req"),
                    HeaderValue::from_static("1"),
                ),
                SetResponseHeaderLayer::overriding(
                    HeaderName::from_static("x-observed-res"),
                    HeaderValue::from_static("1"),
                ),
                ArcLayer::new(),
            ))
            .serve(StreamBridge {
                left: MockSocket::new(relay_ingress_stream),
                right: MockSocket::new(relay_egress_stream),
            })
            .await
            .unwrap();
    });

    let request = create_test_request(version);
    let conn = http_connect(
        MockSocket::new(client_stream),
        request,
        Executor::graceful(graceful.guard()),
    )
    .await
    .unwrap()
    .conn;

    let response = conn.serve(create_test_request(version)).await.unwrap();

    assert!(response.headers().contains_key("x-observed-res"));

    assert_eq!(response.status(), StatusCode::OK);
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(bytes, "a random response body");

    drop(conn);
    cancel_drop_guard.disarm().cancel();
    let fut = graceful.shutdown();

    fut.await;
}

#[tokio::test]
async fn test_http11_mitm_relay_roundtrip() {
    test_mitm_relay_roundtrip_inner(Version::HTTP_11).await;
}

#[tokio::test]
async fn test_http2_mitm_relay_roundtrip() {
    test_mitm_relay_roundtrip_inner(Version::HTTP_2).await;
}
