//! Abandoned HTTP/1 response bodies over real loopback TCP: drained bodies
//! keep their connection, failed drains close it without failing the next request.

#![expect(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "Integration fixtures fail immediately at the failing setup or assertion"
)]

use std::{
    convert::Infallible,
    num::NonZeroUsize,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use rama_core::{
    Layer as _, Service,
    bytes::Bytes,
    error::{BoxError, BoxErrorExt as _},
    futures::{StreamExt as _, stream},
    layer::MapInputLayer,
    rt::Executor,
    service::service_fn,
};
use rama_http_backend::{
    client::{
        Http1BodyDrainConfig, HttpConnectRequestAdapter, HttpConnector, HttpPooledConnectorConfig,
    },
    server::HttpServer,
};
use rama_http_types::{
    Body, Request, Response,
    body::{StreamingBody as _, util::BodyExt as _},
    header::CONTENT_LENGTH,
};
use rama_net::{
    address::SocketAddress,
    client::{ConnectorService, EstablishedClientConnection, pool::SaturationPolicy},
};
use rama_tcp::{client::service::TcpConnector, server::TcpListener};
use rama_utils::octets::kib;
use tokio::{sync::Notify, time::timeout};

const LIMIT: Duration = Duration::from_secs(10);

struct Origin {
    addr: SocketAddress,
    accepted: Arc<AtomicUsize>,
    fail_body: Arc<Notify>,
}

async fn origin() -> Origin {
    let exec = Executor::new();
    let listener = TcpListener::build(exec.clone())
        .bind_address(SocketAddress::local_ipv4(0))
        .await
        .unwrap();
    let addr = listener.local_addr().unwrap().into();
    let accepted = Arc::new(AtomicUsize::new(0));
    let fail_body = Arc::new(Notify::new());
    let count = MapInputLayer::new({
        let accepted = accepted.clone();
        move |stream| {
            accepted.fetch_add(1, Ordering::SeqCst);
            stream
        }
    });
    let http = HttpServer::new_http1(exec.clone()).service(service_fn({
        let fail_body = fail_body.clone();
        move |request| respond(request, fail_body.clone())
    }));
    exec.spawn_task(listener.serve(count.into_layer(http)));
    Origin {
        addr,
        accepted,
        fail_body,
    }
}

/// Sized responses, or half a 4 KiB body followed by a controlled stream error.
async fn respond(request: Request, fail_body: Arc<Notify>) -> Result<Response, Infallible> {
    let path = request.uri().path_or_root();
    let len = match path.as_ref() {
        "/large" => kib(64),
        "/huge" => kib(768),
        _ => kib(4),
    };
    let body = if path == "/truncated" {
        let prefix = Bytes::from(vec![b'x'; len / 2]);
        Body::from_stream(
            stream::iter([Ok::<_, BoxError>(prefix)]).chain(stream::once(async move {
                // Let the client receive the headers and abandon the body before
                // failing it; the HTTP server closes the incomplete response.
                fail_body.notified().await;
                Err::<Bytes, _>(BoxError::from_static_str("test response body truncated"))
            })),
        )
    } else {
        Body::from(vec![b'x'; len])
    };
    Ok(Response::builder()
        .header(CONTENT_LENGTH, len)
        .body(body)
        .unwrap())
}

async fn send<C>(client: &C, addr: SocketAddress, path: &str) -> Response
where
    C: ConnectorService<Request, Connection: Service<Request, Output = Response, Error = BoxError>>,
{
    let request = Request::builder()
        .uri(format!("http://{addr}{path}"))
        .body(Body::empty())
        .unwrap();
    timeout(LIMIT, async {
        let EstablishedClientConnection { conn, input } = client.connect(request).await.unwrap();
        conn.serve(input).await.unwrap()
    })
    .await
    .expect("request deadline")
}

fn client(
    drain: Option<Http1BodyDrainConfig>,
) -> impl ConnectorService<Request, Connection: Service<Request, Output = Response, Error = BoxError>>
{
    HttpConnectRequestAdapter::new(
        HttpPooledConnectorConfig {
            max_connections_total: NonZeroUsize::new(1),
            saturation_policy: SaturationPolicy::Wait,
            http1_body_drain: drain,
            ..Default::default()
        }
        .build_connector(HttpConnector::<_, Body>::new(
            TcpConnector::new(),
            Executor::new(),
        )),
    )
}

#[tokio::test]
async fn unread_bodies_keep_their_loopback_connection() {
    const REQUESTS: usize = 20;
    for (drain, expected) in [(Some(Http1BodyDrainConfig::default()), 1), (None, REQUESTS)] {
        let origin = origin().await;
        let client = client(drain);
        for request in 0..REQUESTS {
            let path = if request % 2 == 0 { "/" } else { "/large" };
            drop(send(&client, origin.addr, path).await);
        }
        assert_eq!(origin.accepted.load(Ordering::SeqCst), expected);
    }
}

#[tokio::test]
async fn partially_read_body_keeps_its_loopback_connection() {
    let origin = origin().await;
    let client = client(Some(Http1BodyDrainConfig::default()));
    for _ in 0..5 {
        let mut body = send(&client, origin.addr, "/huge").await.into_body();
        body.frame().await.unwrap().unwrap();
        assert!(!body.is_end_stream());
        drop(body);
    }
    assert_eq!(origin.accepted.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn over_budget_drains_replace_their_loopback_connection() {
    let origin = origin().await;
    let client = client(Some(Http1BodyDrainConfig::default().with_max_bytes(kib(1))));
    drop(send(&client, origin.addr, "/large").await);
    let body = send(&client, origin.addr, "/")
        .await
        .into_body()
        .collect()
        .await;
    assert_eq!(body.unwrap().to_bytes().len(), kib(4));
    assert_eq!(origin.accepted.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn truncated_drains_replace_their_loopback_connection() {
    let origin = origin().await;
    let client = client(Some(Http1BodyDrainConfig::default()));
    drop(send(&client, origin.addr, "/truncated").await);
    origin.fail_body.notify_one();
    let body = send(&client, origin.addr, "/")
        .await
        .into_body()
        .collect()
        .await;
    assert_eq!(body.unwrap().to_bytes().len(), kib(4));
    assert_eq!(origin.accepted.load(Ordering::SeqCst), 2);
}
