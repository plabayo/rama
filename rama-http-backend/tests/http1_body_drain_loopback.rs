//! Abandoned HTTP/1 response bodies over real loopback TCP: drained bodies
//! keep their connection, failed drains close it without failing the next request.

#![expect(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "Integration fixtures fail immediately at the failing setup or assertion"
)]

use std::{
    net::SocketAddr,
    num::NonZeroUsize,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use rama_core::{Service, rt::Executor};
use rama_http_backend::client::{
    Http1BodyDrainConfig, HttpConnectRequestAdapter, HttpConnector, HttpPooledConnectorConfig,
};
use rama_http_types::{
    Body, Request, Response,
    body::{StreamingBody as _, util::BodyExt as _},
};
use rama_net::client::{ConnectorService, EstablishedClientConnection, pool::SaturationPolicy};
use rama_tcp::client::service::TcpConnector;
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::{TcpListener, TcpStream},
    time::timeout,
};

const LIMIT: Duration = Duration::from_secs(10);

/// Answers `/large` with 64 KiB, `/huge` with 768 KiB, `/truncated` with half a body then a close,
/// and anything else with 4 KiB; each body is unread by the client.
async fn origin() -> (SocketAddr, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let accepted = Arc::new(AtomicUsize::new(0));
    tokio::spawn({
        let accepted = accepted.clone();
        async move {
            loop {
                let (socket, _) = listener.accept().await.unwrap();
                accepted.fetch_add(1, Ordering::SeqCst);
                tokio::spawn(serve(socket));
            }
        }
    });
    (addr, accepted)
}

async fn serve(mut socket: TcpStream) {
    let mut buf = Vec::new();
    loop {
        let head_end = loop {
            if let Some(at) = buf.windows(4).position(|window| window == b"\r\n\r\n") {
                break at + 4;
            }
            let mut chunk = [0u8; 4096];
            match socket.read(&mut chunk).await {
                Ok(0) | Err(_) => return,
                Ok(read) => buf.extend_from_slice(&chunk[..read]),
            }
        };
        let head = String::from_utf8_lossy(&buf[..head_end]).into_owned();
        buf.drain(..head_end);
        let path = head.split(' ').nth(1).unwrap_or("/");
        let (len, truncated) = match path {
            "/large" => (64 * 1024, false),
            "/huge" => (768 * 1024, false),
            "/truncated" => (4096, true),
            _ => (4096, false),
        };
        let mut response = format!("HTTP/1.1 200 OK\r\ncontent-length: {len}\r\n\r\n").into_bytes();
        response.extend(std::iter::repeat_n(
            b'x',
            if truncated { len / 2 } else { len },
        ));
        if socket.write_all(&response).await.is_err() || truncated {
            return;
        }
    }
}

async fn send<C>(client: &C, addr: SocketAddr, path: &str) -> Response
where
    C: ConnectorService<
            Request,
            Connection: Service<Request, Output = Response, Error = rama_core::error::BoxError>,
        >,
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
) -> impl ConnectorService<
    Request,
    Connection: Service<Request, Output = Response, Error = rama_core::error::BoxError>,
> {
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
        let (addr, accepted) = origin().await;
        let client = client(drain);
        for request in 0..REQUESTS {
            let path = if request % 2 == 0 { "/" } else { "/large" };
            drop(send(&client, addr, path).await);
        }
        assert_eq!(accepted.load(Ordering::SeqCst), expected);
    }
}

#[tokio::test]
async fn partially_read_body_keeps_its_loopback_connection() {
    let (addr, accepted) = origin().await;
    let client = client(Some(Http1BodyDrainConfig::default()));
    for _ in 0..5 {
        let mut body = send(&client, addr, "/huge").await.into_body();
        body.frame().await.unwrap().unwrap();
        assert!(!body.is_end_stream());
        drop(body);
    }
    assert_eq!(accepted.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn failed_drains_replace_their_loopback_connection() {
    let (addr, accepted) = origin().await;
    // over budget, then truncated by the peer
    let client = client(Some(Http1BodyDrainConfig::default().with_max_bytes(1024)));
    drop(send(&client, addr, "/large").await);
    drop(send(&client, addr, "/truncated").await);
    let body = send(&client, addr, "/").await.into_body().collect().await;
    assert_eq!(body.unwrap().to_bytes().len(), 4096);
    assert_eq!(accepted.load(Ordering::SeqCst), 3);
}
