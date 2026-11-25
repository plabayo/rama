//! A peer's `RST_STREAM` on an HTTP/2 CONNECT tunnel is a reset carrying its reason, so a relay
//! reflects it (RFC 9113 §8.5); only `NO_ERROR` ends the tunnel as a FIN would.

#![expect(clippy::unwrap_used, reason = "test fixtures")]

use std::{
    convert::Infallible,
    io,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use rama_core::{
    Service as _, ServiceInput,
    bytes::Bytes,
    extensions::ExtensionsRef as _,
    graceful::WeakScope,
    io::{AbortIo, BridgeIo},
    service::service_fn,
};
use rama_http::{
    Body, Method, Request,
    io::upgrade::{Upgraded, handle_upgrade},
};
use rama_http_core::{
    client::conn::http2,
    h2::{Error as H2Error, Reason, server as h2_server},
    server::conn::http2 as http2_server,
    service::RamaHttpService,
};
use rama_http_types::{Response, StatusCode};
use rama_net::{proxy::IoForwardService, uri::Uri};
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _, DuplexStream, duplex},
    time::timeout,
};

const TIMEOUT: Duration = Duration::from_secs(5);

/// A client tunnel whose origin answers 200 and then resets with `reason`.
async fn reset_tunnel(reason: Reason) -> Upgraded {
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    tokio::spawn(async move {
        let mut origin = h2_server::handshake(ServiceInput::new(server_io))
            .await
            .unwrap();
        let (request, mut respond) = origin.accept().await.unwrap().unwrap();
        // The connection only makes progress while it is polled.
        tokio::spawn(async move { while origin.accept().await.is_some() {} });
        let mut stream = respond.send_response(Response::new(()), false).unwrap();
        stream
            .send_data(Bytes::from_static(b"hello"), false)
            .unwrap();
        // Reset only once the client holds the tunnel, so the reset reaches the tunnel.
        let mut body = request.into_body();
        let go = std::future::poll_fn(|cx| body.poll_data(cx)).await;
        assert!(
            go.is_some_and(|data| data.is_ok()),
            "the client starts the tunnel"
        );
        stream.send_reset(reason);
    });
    let (mut client, conn) = http2::handshake(WeakScope::detached(), ServiceInput::new(client_io))
        .await
        .unwrap();
    tokio::spawn(conn);
    let request = Request::builder()
        .method(Method::CONNECT)
        .uri(Uri::parse_authority_form("origin.test:443").unwrap())
        .body(Body::empty())
        .unwrap();
    let response = client.send_request(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let mut tunnel = handle_upgrade(response).await.unwrap();
    tunnel.write_all(b"go").await.unwrap();
    tunnel
}

fn reset_reason(error: &io::Error) -> Option<Reason> {
    error
        .get_ref()
        .and_then(|cause| cause.downcast_ref::<H2Error>())
        .and_then(H2Error::reason)
}

#[tokio::test]
async fn received_resets_fail_both_directions_with_their_reason() {
    for reason in [Reason::STREAM_CLOSED, Reason::CANCEL, Reason::CONNECT_ERROR] {
        let mut tunnel = timeout(TIMEOUT, reset_tunnel(reason)).await.unwrap();
        let mut hello = [0; 5];
        tunnel.read_exact(&mut hello).await.unwrap();
        let read = loop {
            match timeout(TIMEOUT, tunnel.read(&mut [0; 16])).await.unwrap() {
                Ok(0) => panic!("{reason:?}: a reset must not read as an end"),
                Ok(_) => {}
                Err(error) => break error,
            }
        };
        assert_eq!(read.kind(), io::ErrorKind::ConnectionReset, "{reason:?}");
        assert_eq!(reset_reason(&read), Some(reason), "{reason:?}");

        let write = timeout(TIMEOUT, tunnel.write_all(b"late"))
            .await
            .unwrap()
            .unwrap_err();
        assert_eq!(write.kind(), io::ErrorKind::ConnectionReset, "{reason:?}");
    }
}

#[tokio::test]
async fn a_reset_without_error_ends_the_tunnel_in_order() {
    let mut tunnel = timeout(TIMEOUT, reset_tunnel(Reason::NO_ERROR))
        .await
        .unwrap();
    let mut rest = Vec::new();
    timeout(TIMEOUT, tunnel.read_to_end(&mut rest))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(rest, b"hello");
    let write = timeout(TIMEOUT, tunnel.write_all(b"late"))
        .await
        .unwrap()
        .unwrap_err();
    assert_eq!(write.kind(), io::ErrorKind::BrokenPipe);
}

/// The far side of a relay sees the tunnel's reset as a reset, and its orderly end in order.
#[tokio::test]
async fn relays_reflect_received_resets_on_the_far_side() {
    for (reason, reflected) in [
        (Reason::STREAM_CLOSED, true),
        (Reason::CANCEL, true),
        (Reason::NO_ERROR, false),
    ] {
        let tunnel = timeout(TIMEOUT, reset_tunnel(reason)).await.unwrap();
        let (far, mut far_peer) = tokio::io::duplex(64 * 1024);
        let far = ServiceInput::<DuplexStream>::new(far);
        let aborts = Arc::new(AtomicUsize::new(0));
        far.extensions().insert(AbortIo::new({
            let aborts = aborts.clone();
            move || {
                aborts.fetch_add(1, Ordering::SeqCst);
            }
        }));
        let relay = tokio::spawn(async move {
            IoForwardService::default()
                .serve(BridgeIo(tunnel, far))
                .await
        });
        let mut received = Vec::new();
        timeout(TIMEOUT, far_peer.read_to_end(&mut received))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(received, b"hello", "{reason:?}");
        drop(far_peer);
        _ = timeout(TIMEOUT, relay).await.unwrap().unwrap();
        assert_eq!(aborts.load(Ordering::SeqCst) > 0, reflected, "{reason:?}");
    }
}

/// A tunnel resolves its own abort hook, not the carrier connection's: aborting it resets that
/// stream only, and the connection keeps serving its other requests.
#[tokio::test]
async fn tunnel_abort_resets_its_stream_and_not_the_carrier() {
    let (client_io, server_io) = duplex(64 * 1024);
    let server_io = ServiceInput::new(server_io);
    let carrier_aborted = Arc::new(AtomicUsize::new(0));
    let carrier_abort = server_io.extensions().insert_arc(Arc::new(AbortIo::new({
        let carrier_aborted = carrier_aborted.clone();
        move || {
            carrier_aborted.fetch_add(1, Ordering::SeqCst);
        }
    })));
    let tunnel_abort_was_own = Arc::new(AtomicUsize::new(0));
    let service = {
        let tunnel_abort_was_own = tunnel_abort_was_own.clone();
        service_fn(move |request: Request| {
            let carrier_abort = carrier_abort.clone();
            let tunnel_abort_was_own = tunnel_abort_was_own.clone();
            async move {
                if request.method() == Method::CONNECT {
                    tokio::spawn(async move {
                        let mut tunnel = handle_upgrade(request).await.unwrap();
                        // Abort only once the client holds the tunnel.
                        tunnel.read_exact(&mut [0; 2]).await.unwrap();
                        let abort = tunnel.extensions().get_arc::<AbortIo>().unwrap();
                        if !Arc::ptr_eq(&abort, &carrier_abort) {
                            tunnel_abort_was_own.fetch_add(1, Ordering::SeqCst);
                        }
                        abort.abort();
                    });
                }
                Ok::<_, Infallible>(Response::new(Body::empty()))
            }
        })
    };
    tokio::spawn(
        http2_server::Builder::new(WeakScope::detached())
            .serve_connection(server_io, RamaHttpService::new(service)),
    );
    let (mut client, conn) = http2::handshake(WeakScope::detached(), ServiceInput::new(client_io))
        .await
        .unwrap();
    tokio::spawn(conn);

    timeout(TIMEOUT, async {
        let connect = Request::builder()
            .method(Method::CONNECT)
            .uri(Uri::parse_authority_form("origin.test:443").unwrap())
            .body(Body::empty())
            .unwrap();
        let response = client.send_request(connect).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let mut tunnel = handle_upgrade(response).await.unwrap();
        tunnel.write_all(b"go").await.unwrap();
        let read = tunnel.read(&mut [0; 16]).await.unwrap_err();
        assert_eq!(reset_reason(&read), Some(Reason::CONNECT_ERROR));

        let sibling = Request::builder()
            .uri("http://origin.test/")
            .body(Body::empty())
            .unwrap();
        let response = client.send_request(sibling).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    })
    .await
    .unwrap();
    assert_eq!(tunnel_abort_was_own.load(Ordering::SeqCst), 1);
    assert_eq!(carrier_aborted.load(Ordering::SeqCst), 0);
}
