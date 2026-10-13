//! Paused-clock checks of request-head, connection-idle and active-request budgets.

use std::{
    convert::Infallible,
    future::poll_fn,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    task::Poll,
    time::Duration,
};

use rama::{
    ServiceInput,
    http::{
        Body, Response,
        core::{
            server::conn::{HeaderReadTimeout, http1},
            service::RamaHttpService,
        },
    },
    service::service_fn,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    task::JoinHandle,
    time::advance,
};

fn connection(
    builder: http1::Builder,
) -> (
    tokio::io::DuplexStream,
    JoinHandle<rama::http::core::Result<()>>,
) {
    let (client, server) = tokio::io::duplex(64 * 1024);
    let task = tokio::spawn(async move {
        builder
            .serve_connection(
                ServiceInput::new(server),
                RamaHttpService::new(service_fn(|_| async {
                    Ok::<_, Infallible>(Response::new(Body::empty()))
                })),
            )
            .await
    });
    (client, task)
}

async fn settle() {
    for _ in 0..8 {
        tokio::task::yield_now().await;
    }
}

#[tokio::test(start_paused = true)]
async fn idle_window_is_earned_by_a_request() {
    let (mut client, task) = connection(http1::Builder::new().maybe_with_lingering_close(None));
    settle().await;
    advance(Duration::from_secs(9)).await;
    assert!(!task.is_finished());
    advance(Duration::from_secs(1)).await;
    settle().await;
    // An idle close ends the connection cleanly, as an EOF does.
    task.await.unwrap().unwrap();
    let mut rest = Vec::new();
    client.read_to_end(&mut rest).await.unwrap();
    assert!(rest.is_empty(), "nothing is written on an idle close");

    let (mut client, task) = connection(http1::Builder::new().maybe_with_lingering_close(None));
    client
        .write_all(b"GET / HTTP/1.1\r\nHost: test\r\n\r\n")
        .await
        .unwrap();
    let mut response = [0; 1024];
    assert!(client.read(&mut response).await.unwrap() > 0);
    settle().await;
    advance(Duration::from_secs(29)).await;
    assert!(!task.is_finished());
    advance(Duration::from_secs(1)).await;
    settle().await;
    task.await.unwrap().unwrap();
}

#[tokio::test(start_paused = true)]
async fn head_grace_starts_at_first_byte_and_trickle_does_not_renew_it() {
    let (mut client, task) = connection(http1::Builder::new().maybe_with_lingering_close(None));
    settle().await;
    advance(Duration::from_secs(9)).await;
    client.write_all(b"G").await.unwrap();
    settle().await;
    for _ in 0..9 {
        advance(Duration::from_secs(1)).await;
        client.write_all(b"E").await.unwrap();
        settle().await;
        assert!(!task.is_finished());
    }
    advance(Duration::from_secs(1)).await;
    settle().await;
    assert!(task.await.unwrap().unwrap_err().is_timeout());
}

#[tokio::test(start_paused = true)]
async fn steady_head_progress_is_allowed_past_grace() {
    let (mut client, task) = connection(http1::Builder::new().maybe_with_lingering_close(None));
    client
        .write_all(b"GET / HTTP/1.1\r\nHost: test\r\nX-Padding: ")
        .await
        .unwrap();
    let padding = [b'a'; 300];
    for _ in 0..15 {
        client.write_all(&padding).await.unwrap();
        settle().await;
        advance(Duration::from_secs(1)).await;
        assert!(!task.is_finished());
    }
    client.write_all(b"\r\n\r\n").await.unwrap();
    let mut response = [0; 1024];
    let n = client.read(&mut response).await.unwrap();
    assert!(response[..n].starts_with(b"HTTP/1.1 200"));
    drop(client);
    task.await.unwrap().unwrap();
}

#[tokio::test(start_paused = true)]
async fn disabled_budgets_allow_idle_and_partial_heads() {
    let (mut client, task) = connection(
        http1::Builder::new()
            .without_header_read_timeout()
            .without_idle_timeout()
            .maybe_with_lingering_close(None),
    );
    settle().await;
    advance(Duration::from_hours(1)).await;
    assert!(!task.is_finished());
    client.write_all(b"GET / HTTP/1.1\r\n").await.unwrap();
    settle().await;
    advance(Duration::from_hours(1)).await;
    assert!(!task.is_finished());
    client.write_all(b"Host: test\r\n\r\n").await.unwrap();
    let mut response = [0; 1024];
    assert!(client.read(&mut response).await.unwrap() > 0);
    drop(client);
    task.await.unwrap().unwrap();
}

#[tokio::test(start_paused = true)]
async fn hard_ceiling_cuts_a_large_progressing_head() {
    let (mut client, task) = connection(
        http1::Builder::new()
            .with_header_read_timeout(HeaderReadTimeout {
                grace: Duration::from_secs(1),
                min_rate: 1,
                ceiling: Duration::from_secs(3),
            })
            .maybe_with_lingering_close(None),
    );
    client
        .write_all(b"GET / HTTP/1.1\r\nHost: test\r\n")
        .await
        .unwrap();
    settle().await;
    advance(Duration::from_secs(3)).await;
    settle().await;
    assert!(task.await.unwrap().unwrap_err().is_timeout());
}

#[tokio::test(start_paused = true)]
async fn active_service_never_uses_idle_budget() {
    let (mut client, server) = tokio::io::duplex(4096);
    let (release, wait) = tokio::sync::watch::channel(false);
    let task = tokio::spawn(async move {
        http1::Builder::new()
            .maybe_with_lingering_close(None)
            .serve_connection(
                ServiceInput::new(server),
                RamaHttpService::new(service_fn(move |_| {
                    let mut wait = wait.clone();
                    async move {
                        wait.wait_for(|ready| *ready).await.unwrap();
                        Ok::<_, Infallible>(Response::new(Body::empty()))
                    }
                })),
            )
            .await
    });
    client
        .write_all(b"GET / HTTP/1.1\r\nHost: test\r\n\r\n")
        .await
        .unwrap();
    settle().await;
    advance(Duration::from_hours(1)).await;
    assert!(!task.is_finished());
    release.send(true).unwrap();
    let mut response = [0; 1024];
    assert!(client.read(&mut response).await.unwrap() > 0);
    drop(client);
    task.await.unwrap().unwrap();
}

#[tokio::test(start_paused = true)]
async fn active_response_body_never_uses_idle_budget() {
    let (mut client, server) = tokio::io::duplex(4096);
    let (release, wait) = tokio::sync::watch::channel(false);
    let task = tokio::spawn(async move {
        http1::Builder::new()
            .maybe_with_lingering_close(None)
            .serve_connection(
                ServiceInput::new(server),
                RamaHttpService::new(service_fn(move |_| {
                    let mut wait = wait.clone();
                    async move {
                        let body = Body::from_stream(rama::futures::stream::once(async move {
                            wait.wait_for(|ready| *ready).await.unwrap();
                            Ok::<_, Infallible>(rama::bytes::Bytes::from_static(b"finished"))
                        }));
                        Ok::<_, Infallible>(Response::new(body))
                    }
                })),
            )
            .await
    });
    client
        .write_all(b"GET / HTTP/1.1\r\nHost: test\r\n\r\n")
        .await
        .unwrap();
    let mut response = [0; 1024];
    let n = client.read(&mut response).await.unwrap();
    assert!(response[..n].starts_with(b"HTTP/1.1 200"));
    settle().await;
    advance(Duration::from_hours(1)).await;
    assert!(!task.is_finished());
    release.send(true).unwrap();
    assert!(client.read(&mut response).await.unwrap() > 0);
    drop(client);
    task.await.unwrap().unwrap();
}

#[tokio::test(start_paused = true)]
async fn ready_remainder_cannot_revive_an_expired_head() {
    for (min_rate, ceiling) in [(0, Duration::from_secs(3)), (256, Duration::from_secs(30))] {
        let (mut client, server) = tokio::io::duplex(4096);
        let calls = Arc::new(AtomicUsize::new(0));
        let observed = calls.clone();
        let builder = http1::Builder::new()
            .with_header_read_timeout(HeaderReadTimeout {
                grace: Duration::from_secs(3),
                min_rate,
                ceiling,
            })
            .maybe_with_lingering_close(None);
        let connection = builder.serve_connection(
            ServiceInput::new(server),
            RamaHttpService::new(service_fn(move |_| {
                observed.fetch_add(1, Ordering::Relaxed);
                async { Ok::<_, Infallible>(Response::new(Body::empty())) }
            })),
        );
        tokio::pin!(connection);
        client
            .write_all(b"GET / HTTP/1.1\r\nHost: test\r\n")
            .await
            .unwrap();
        assert!(
            poll_fn(|cx| Poll::Ready(connection.as_mut().poll(cx)))
                .await
                .is_pending()
        );
        advance(Duration::from_secs(4)).await;
        client.write_all(b"\r\n").await.unwrap();
        assert!(connection.await.unwrap_err().is_timeout());
        assert_eq!(calls.load(Ordering::Relaxed), 0);
    }
}
