//! A request body still ends when the response went out before it was read: a service that
//! answers first and streams the body elsewhere (as proxies do) must see its end while the
//! connection idles, not only once the client sends another request or closes.

use std::{convert::Infallible, sync::Arc, time::Duration};

use parking_lot::Mutex;
use rama::{
    ServiceInput,
    http::{
        Body, Request, Response,
        body::util::BodyExt,
        core::{server::conn::http1, service::RamaHttpService},
    },
    service::service_fn,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::oneshot,
};

/// Answers before reading the body, then collects the body in a task; returns that body.
async fn body_read_after_response(head: &'static [u8], body: &'static [u8]) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (done_tx, done_rx) = oneshot::channel::<String>();
    let done_tx = Arc::new(Mutex::new(Some(done_tx)));

    let server = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let svc = RamaHttpService::new(service_fn(move |req: Request| {
            let done_tx = done_tx.clone();
            async move {
                tokio::spawn(async move {
                    let collected = req.into_body().collect().await.unwrap();
                    let trailers = collected.trailers().cloned();
                    let summary = format!("{:?} {trailers:?}", collected.to_bytes());
                    if let Some(tx) = done_tx.lock().take() {
                        _ = tx.send(summary);
                    }
                });
                Ok::<_, Infallible>(Response::new(Body::from("ok")))
            }
        }));
        _ = http1::Builder::new()
            .serve_connection(ServiceInput::new(socket), svc)
            .await;
    });

    let mut tcp = TcpStream::connect(addr).await.unwrap();
    tcp.write_all(head).await.unwrap();
    let mut response = Vec::new();
    let mut buf = [0u8; 1024];
    while !response.ends_with(b"ok") {
        let n = tcp.read(&mut buf).await.unwrap();
        assert_ne!(n, 0, "server closed early");
        response.extend_from_slice(&buf[..n]);
    }
    tcp.write_all(body).await.unwrap();

    let summary = tokio::time::timeout(Duration::from_secs(5), done_rx)
        .await
        .expect("the body end is delivered while the connection idles")
        .unwrap();
    drop(tcp);
    server.abort();
    summary
}

#[tokio::test]
async fn content_length_body_ends_after_the_response() {
    let summary = body_read_after_response(
        b"POST / HTTP/1.1\r\nhost: x\r\ncontent-length: 5\r\n\r\n",
        b"hello",
    )
    .await;
    assert_eq!(summary, "b\"hello\" None");
}

#[tokio::test]
async fn chunked_body_with_trailers_ends_after_the_response() {
    let summary = body_read_after_response(
        b"POST / HTTP/1.1\r\nhost: x\r\ntransfer-encoding: chunked\r\ntrailer: x-t\r\n\r\n",
        b"5\r\nhello\r\n0\r\nx-t: 1\r\n\r\n",
    )
    .await;
    assert!(summary.starts_with("b\"hello\" Some("), "{summary}");
    assert!(summary.contains("x-t"), "{summary}");
}

#[tokio::test]
async fn chunked_body_ends_after_the_response() {
    let summary = body_read_after_response(
        b"POST / HTTP/1.1\r\nhost: x\r\ntransfer-encoding: chunked\r\n\r\n",
        b"5\r\nhello\r\n0\r\n\r\n",
    )
    .await;
    assert_eq!(summary, "b\"hello\" None");
}
