use std::{
    convert::Infallible,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use tokio::time::sleep;

use rama_core::{
    Layer, Service,
    futures::future::{join, join_all},
    graceful::Shutdown,
    io::BridgeIo,
    layer::ArcLayer,
    layer::ConsumeErrLayer,
    rt::Executor,
    service::service_fn,
};
use rama_http::{
    HeaderName, HeaderValue,
    body::util::BodyExt as _,
    layer::set_header::{SetRequestHeaderLayer, SetResponseHeaderLayer},
};
use rama_http_types::{Body, Request, Response, StatusCode, Version};
use rama_net::test_utils::client::{MockConnectorService, MockSocket};
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

#[tokio::test]
async fn test_http11_handles_4_concurrent_requests() {
    let connector = HttpConnectorLayer::default().into_layer(MockConnectorService::new(|| {
        HttpServer::auto(Executor::default()).service(service_fn(server_svc_fn))
    }));

    let conn = connector
        .serve(create_test_request(Version::HTTP_11))
        .await
        .unwrap()
        .conn;

    let responses =
        join_all((0..4).map(|_| conn.serve(create_test_request(Version::HTTP_11)))).await;

    assert_eq!(responses.len(), 4);
    for response in responses {
        let response = response.unwrap();
        assert_eq!(response.status(), 200);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(body, "a random response body");
    }
}

#[tokio::test]
async fn test_http2_handles_200_concurrent_requests() {
    let connector = HttpConnectorLayer::default().into_layer(MockConnectorService::new(|| {
        HttpServer::auto(Executor::default()).service(service_fn(server_svc_fn))
    }));

    let conn = connector
        .serve(create_test_request(Version::HTTP_2))
        .await
        .unwrap()
        .conn;

    let responses =
        join_all((0..200).map(|_| conn.serve(create_test_request(Version::HTTP_2)))).await;

    assert_eq!(responses.len(), 200);
    for response in responses {
        let response = response.unwrap();
        assert_eq!(response.status(), 200);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(body, "a random response body");
    }
}

async fn server_svc_fn(_: Request) -> Result<Response, Infallible> {
    sleep(Duration::from_millis(100)).await;
    Ok(Response::new(Body::from("a random response body")))
}

async fn mitm_relay_server_svc_fn(req: Request) -> Result<Response, Infallible> {
    assert!(req.headers().contains_key("x-observed-req"));
    let body = req
        .headers()
        .get("x-test-id")
        .and_then(|v| v.to_str().ok())
        .map(|id| format!("a random response body ({id})"))
        .unwrap_or_else(|| "a random response body".to_owned());
    Ok(Response::new(Body::from(body)))
}

async fn mitm_relay_server_close_after_first_request_svc_fn(
    req: Request,
    request_count: Arc<AtomicUsize>,
) -> Result<Response, Infallible> {
    assert!(req.headers().contains_key("x-observed-req"));

    let id = request_count.fetch_add(1, Ordering::SeqCst);
    let mut response = Response::new(Body::from(format!("single response body ({id})")));
    if id == 0 {
        response.headers_mut().insert(
            HeaderName::from_static("connection"),
            HeaderValue::from_static("close"),
        );
    }
    Ok(response)
}

fn create_test_request(version: Version) -> Request {
    Request::builder()
        .uri("https://www.example.com")
        .version(version)
        .body(Body::from("a reandom request body"))
        .unwrap()
}

fn create_test_request_with_id(version: Version, id: usize) -> Request {
    Request::builder()
        .uri("https://www.example.com")
        .version(version)
        .header("x-test-id", id.to_string())
        .body(Body::from(format!("a reandom request body ({id})")))
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
            .serve(BridgeIo(
                MockSocket::new(relay_ingress_stream),
                MockSocket::new(relay_egress_stream),
            ))
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

async fn test_mitm_relay_concurrency_inner(version: Version, n: usize) {
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
            .serve(BridgeIo(
                MockSocket::new(relay_ingress_stream),
                MockSocket::new(relay_egress_stream),
            ))
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

    let mut ids = Vec::with_capacity(n);
    let mut futures = Vec::with_capacity(n);
    for id in 0..n {
        ids.push(id);
        futures.push(conn.serve(create_test_request_with_id(version, id)));
    }

    let responses = join_all(futures).await;
    assert_eq!(responses.len(), n);

    for (id, response) in ids.into_iter().zip(responses) {
        let response = response.unwrap();
        assert!(response.headers().contains_key("x-observed-res"));
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(bytes, format!("a random response body ({id})"));
    }

    drop(conn);
    cancel_drop_guard.disarm().cancel();
    graceful.shutdown().await;
}

#[tokio::test]
async fn test_http11_mitm_relay_roundtrip() {
    test_mitm_relay_roundtrip_inner(Version::HTTP_11).await;
}

#[tokio::test]
async fn test_http2_mitm_relay_roundtrip() {
    test_mitm_relay_roundtrip_inner(Version::HTTP_2).await;
}

#[tokio::test]
async fn test_http11_mitm_relay_handles_4_concurrent_requests() {
    test_mitm_relay_concurrency_inner(Version::HTTP_11, 4).await;
}

#[tokio::test]
async fn test_http2_mitm_relay_handles_200_concurrent_requests() {
    test_mitm_relay_concurrency_inner(Version::HTTP_2, 200).await;
}

#[tokio::test]
async fn test_http11_mitm_relay_closes_downstream_after_upstream_close() {
    let (client_stream, relay_ingress_stream) = tokio::io::duplex(16 * 1024);
    let (relay_egress_stream, server_stream) = tokio::io::duplex(16 * 1024);

    let token = CancellationToken::new();
    let graceful = Shutdown::new(token.clone().cancelled_owned());
    let cancel_drop_guard = token.drop_guard();
    let request_count = Arc::new(AtomicUsize::new(0));

    graceful.spawn_task_fn({
        let request_count = request_count.clone();
        async move |guard| {
            HttpServer::auto(Executor::graceful(guard))
                .service(service_fn(move |req| {
                    let request_count = request_count.clone();
                    async move {
                        mitm_relay_server_close_after_first_request_svc_fn(req, request_count).await
                    }
                }))
                .serve(MockSocket::new(server_stream))
                .await
                .unwrap();
        }
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
            .serve(BridgeIo(
                MockSocket::new(relay_ingress_stream),
                MockSocket::new(relay_egress_stream),
            ))
            .await
            .unwrap();
    });

    let request = create_test_request(Version::HTTP_11);
    let conn = http_connect(
        MockSocket::new(client_stream),
        request,
        Executor::graceful(graceful.guard()),
    )
    .await
    .unwrap()
    .conn;

    let response = conn
        .serve(create_test_request(Version::HTTP_11))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get("connection")
            .and_then(|v| v.to_str().ok()),
        Some("close")
    );

    let second = conn.serve(create_test_request(Version::HTTP_11)).await;
    assert!(
        second.is_err(),
        "downstream connection should close after upstream close"
    );

    drop(conn);
    cancel_drop_guard.disarm().cancel();
    graceful.shutdown().await;
}

#[tokio::test]
async fn test_http11_mitm_relay_task_finishes_after_ingress_disconnect() {
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

    let (relay_done_tx, relay_done_rx) = tokio::sync::oneshot::channel::<()>();

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
            .serve(BridgeIo(
                MockSocket::new(relay_ingress_stream),
                MockSocket::new(relay_egress_stream),
            ))
            .await
            .unwrap();
        let _ = relay_done_tx.send(());
    });

    let request = create_test_request(Version::HTTP_11);
    let conn = http_connect(
        MockSocket::new(client_stream),
        request,
        Executor::graceful(graceful.guard()),
    )
    .await
    .unwrap()
    .conn;

    let response = conn
        .serve(create_test_request(Version::HTTP_11))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let _ = response.into_body().collect().await.unwrap();

    drop(conn);

    tokio::time::timeout(std::time::Duration::from_secs(1), relay_done_rx)
        .await
        .expect("relay task should finish after ingress disconnect")
        .expect("relay completion signal");

    cancel_drop_guard.disarm().cancel();
    graceful.shutdown().await;
}
