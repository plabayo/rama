//! Middleware kept around never holds a shutdown open, and a refused task never outlives the
//! moment it is refused, not even inside an error a sink keeps.

#![expect(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "integration fixtures fail immediately at the failing setup or assertion"
)]

use parking_lot::Mutex;
use std::{convert::Infallible, sync::Arc, time::Duration};

use rama_core::{
    Layer as _, Service as _, ServiceInput,
    bytes::Bytes,
    error::BoxError,
    extensions::ExtensionsRef as _,
    futures::stream,
    graceful::{Cause, Scope, WeakScope},
    io::BridgeIo,
    matcher::service::MatcherServicePair,
    service::service_fn,
};
use rama_http::{
    Body, Request, Response,
    body::util::BodyExt as _,
    io::upgrade::{Upgraded, pending},
    layer::{
        traffic_writer::{
            BidirectionalWriter, RequestWriterLayer, ResponseWriterLayer, WriterMode,
        },
        upgrade::{UpgradeLayer, UpgradeResponse, mitm::HttpUpgradeMitmRelay},
    },
};
use tokio::{
    io::{AsyncRead, AsyncReadExt as _, DuplexStream, duplex},
    sync::mpsc,
    time::timeout,
};

const WAIT: Duration = Duration::from_millis(500);

/// A weak scope whose scope is closed: every hold taken on it is refused.
async fn closed_scope() -> WeakScope {
    let root = Scope::new();
    let scope = root.clone_weak();
    root.cancel(Cause::Owner);
    root.join().await.unwrap();
    scope
}

/// An upgrade that is already done, and the peer of its IO.
fn upgraded() -> (rama_http::io::upgrade::OnUpgrade, DuplexStream) {
    let (io, peer) = duplex(64);
    let (pending, on_upgrade) = pending();
    pending.fulfill(Upgraded::new(ServiceInput::new(io), Bytes::new()));
    (on_upgrade, peer)
}

/// Whether the other end of `peer` was dropped.
async fn is_closed(peer: &mut (impl AsyncRead + Unpin)) -> bool {
    let mut byte = [0];
    matches!(timeout(WAIT, peer.read(&mut byte)).await, Ok(Ok(0)))
}

#[tokio::test]
async fn a_refused_upgrade_reports_without_keeping_its_io() {
    let (on_upgrade, mut peer) = upgraded();
    let request = Request::new(Body::empty());
    request.extensions().insert(on_upgrade);
    let responder = service_fn(async |request: Request| {
        Ok::<_, Response>(
            UpgradeResponse::new(request, Response::new(Body::empty()))
                .with_handler(async |_| Ok::<_, BoxError>(())),
        )
    });
    let inner = service_fn(async |_: Request| Ok::<_, Infallible>(Response::new(Body::empty())));
    let (errors, mut reported) = mpsc::unbounded_channel::<BoxError>();
    let service = UpgradeLayer::new(closed_scope().await, true, responder)
        .with_upgrade_error_sink(move |error| errors.send(error).unwrap())
        .into_layer(inner);
    drop(service.serve(request).await.unwrap());

    let kept = timeout(WAIT, reported.recv()).await.unwrap().unwrap();
    assert!(is_closed(&mut peer).await, "the kept error holds no IO");
    drop(kept);
}

#[tokio::test]
async fn a_refused_upgrade_error_does_not_keep_its_sink() {
    let errors = Arc::new(Mutex::new(Vec::<BoxError>::new()));
    let store = Arc::downgrade(&errors);
    let (on_upgrade, _peer) = upgraded();
    let request = Request::new(Body::empty());
    request.extensions().insert(on_upgrade);
    let responder = service_fn(async |request: Request| {
        Ok::<_, Response>(
            UpgradeResponse::new(request, Response::new(Body::empty()))
                .with_handler(async |_| Ok::<_, BoxError>(())),
        )
    });
    let inner = service_fn(async |_: Request| Ok::<_, Infallible>(Response::new(Body::empty())));
    let sink = errors.clone();
    let service = UpgradeLayer::new(closed_scope().await, true, responder)
        .with_upgrade_error_sink(move |error| sink.lock().push(error))
        .into_layer(inner);
    drop(service.serve(request).await.unwrap());
    assert_eq!(errors.lock().len(), 1);

    drop((service, errors));
    assert!(
        store.upgrade().is_none(),
        "no cycle through the refused task"
    );
}

#[tokio::test]
async fn a_refused_relay_reports_without_keeping_either_leg() {
    let (ingress, mut ingress_peer) = upgraded();
    let (egress, mut egress_peer) = upgraded();
    let request = Request::new(Body::empty());
    request.extensions().insert(ingress);
    let upstream = service_fn(move |_: Request| {
        let response = Response::new(Body::empty());
        response.extensions().insert(egress.clone());
        async { Ok::<_, Infallible>(response) }
    });
    let relay = service_fn(async |_: BridgeIo<Upgraded, Upgraded>| Ok::<_, Infallible>(()));
    let matcher = MatcherServicePair::new(true, MatcherServicePair::new(true, relay));
    let (errors, mut reported) = mpsc::unbounded_channel::<BoxError>();
    let service = HttpUpgradeMitmRelay::new(closed_scope().await, matcher, upstream)
        .with_error_sink(move |error| errors.send(error).unwrap());
    drop(service.serve(request).await.unwrap());
    drop(service);

    let kept = timeout(WAIT, reported.recv()).await.unwrap().unwrap();
    assert!(
        is_closed(&mut ingress_peer).await,
        "the kept error holds no ingress"
    );
    assert!(
        is_closed(&mut egress_peer).await,
        "the kept error holds no egress"
    );
    drop(kept);
}

/// Cancel `root` with `kept` alive: its join must complete all the same.
async fn assert_kept_does_not_hold(root: Scope, kept: impl Sized) {
    root.cancel(Cause::Owner);
    timeout(WAIT, root.join())
        .await
        .expect("the join completes with the writer kept")
        .expect("joined");
    drop(kept);
}

#[tokio::test]
async fn an_idle_request_writer_kept_around_does_not_hold_the_join() {
    let root = Scope::new();
    let layer =
        RequestWriterLayer::writer_unbounded(&root, tokio::io::sink(), Some(WriterMode::Headers));
    assert_kept_does_not_hold(root, layer).await;
}

#[tokio::test]
async fn an_idle_response_writer_kept_around_does_not_hold_the_join() {
    let root = Scope::new();
    let layer = ResponseWriterLayer::writer(&root, tokio::io::sink(), 8, Some(WriterMode::Headers));
    assert_kept_does_not_hold(root, layer).await;
}

#[tokio::test]
async fn an_idle_bidirectional_writer_kept_around_does_not_hold_the_join() {
    let root = Scope::new();
    let writer = BidirectionalWriter::new(
        &root,
        tokio::io::sink(),
        8,
        Some(WriterMode::Headers),
        Some(WriterMode::Headers),
    );
    assert_kept_does_not_hold(root, writer).await;
}

fn get(path: &str) -> Request {
    Request::builder()
        .uri(format!("http://example.com{path}"))
        .body(Body::empty())
        .unwrap()
}

fn ok() -> impl rama_core::Service<Request, Output = Response, Error = Infallible> + Clone {
    service_fn(async |_: Request| {
        Ok::<_, Infallible>(
            Response::builder()
                .header("x-written", "yes")
                .body(Body::empty())
                .unwrap(),
        )
    })
}

/// Cancel `root` and let go of it, then read everything its writer wrote until it ended.
async fn written_once_ended(root: Scope, mut captured: DuplexStream) -> String {
    root.cancel(Cause::Owner);
    let mut written = String::new();
    let (joined, read) = tokio::join!(
        timeout(WAIT, root.join()),
        timeout(WAIT, captured.read_to_string(&mut written)),
    );
    joined.expect("the writer ends").expect("joined");
    read.expect("the writer flushed and went").unwrap();
    written
}

// No yield between the call and the cancel: the capture task has not run when the cancel
// comes, yet it was admitted when the message was served.

#[tokio::test]
async fn a_request_capture_admitted_before_the_cancel_is_written() {
    let root = Scope::new();
    let (output, captured) = duplex(4096);
    let service = RequestWriterLayer::writer_unbounded(&root, output, Some(WriterMode::Headers))
        .into_layer(ok());
    service.serve(get("/admitted")).await.unwrap();
    drop(service);
    let written = written_once_ended(root, captured).await;
    assert!(written.contains("/admitted"), "{written}");
}

#[tokio::test]
async fn a_response_capture_admitted_before_the_cancel_is_written() {
    let root = Scope::new();
    let (output, captured) = duplex(4096);
    let service = ResponseWriterLayer::writer_unbounded(&root, output, Some(WriterMode::Headers))
        .into_layer(ok());
    drop(service.serve(get("/")).await.unwrap());
    drop(service);
    let written = written_once_ended(root, captured).await;
    assert!(written.contains("x-written"), "{written}");
}

#[tokio::test]
async fn bidirectional_captures_admitted_before_the_cancel_are_written() {
    let root = Scope::new();
    let (output, captured) = duplex(4096);
    let writer = BidirectionalWriter::new(
        &root,
        output,
        8,
        Some(WriterMode::Headers),
        Some(WriterMode::Headers),
    );
    let service = (writer.request_layer(), writer.response_layer()).into_layer(ok());
    drop(service.serve(get("/both")).await.unwrap());
    drop((service, writer));
    let written = written_once_ended(root, captured).await;
    assert!(written.contains("/both"), "{written}");
    assert!(written.contains("x-written"), "{written}");
}

#[tokio::test]
async fn captures_blocked_on_a_full_queue_at_the_cancel_are_written() {
    let root = Scope::new();
    // A queue of one and an output nobody reads yet: later captures block on their send.
    let (output, captured) = duplex(16);
    let service =
        RequestWriterLayer::writer(&root, output, 1, Some(WriterMode::Headers)).into_layer(ok());
    for path in ["/first", "/second", "/third"] {
        service.serve(get(path)).await.unwrap();
    }
    for _ in 0..8 {
        tokio::task::yield_now().await;
    }
    drop(service);
    let written = written_once_ended(root, captured).await;
    for path in ["/first", "/second", "/third"] {
        assert!(written.contains(path), "{path} in {written}");
    }
}

#[tokio::test]
async fn a_capture_served_while_another_is_pending_after_the_cancel_is_admitted() {
    let root = Scope::new();
    let (output, captured) = duplex(4096);
    let service = RequestWriterLayer::writer_unbounded(&root, output, Some(WriterMode::Headers))
        .into_layer(ok());
    service.serve(get("/before")).await.unwrap();
    root.cancel(Cause::Owner);
    // The capture of /before has not run yet: it still holds the admission.
    service.serve(get("/during")).await.unwrap();
    drop(service);
    let written = written_once_ended(root, captured).await;
    assert!(written.contains("/before"), "{written}");
    assert!(written.contains("/during"), "{written}");
}

#[tokio::test]
async fn a_capture_served_once_the_writer_drained_is_refused() {
    let root = Scope::new();
    let (output, captured) = duplex(4096);
    let service = RequestWriterLayer::writer_unbounded(&root, output, Some(WriterMode::Headers))
        .into_layer(ok());
    let weak = root.clone_weak();
    let written = written_once_ended(root, captured).await;
    assert!(written.is_empty(), "{written}");
    assert!(weak.try_hold().is_err(), "the writer's scope is closed");
    // Served as usual, but its capture is refused and nothing holds a drain open.
    service.serve(get("/after")).await.unwrap();
    timeout(WAIT, weak.drained())
        .await
        .expect("nothing was admitted");
}

#[tokio::test]
async fn a_writer_blocked_on_its_output_is_dropped_at_the_hard_phase() {
    let root = Scope::new();
    // One byte of room and nobody reading: the writer blocks on its first message.
    let (output, _unread) = duplex(1);
    let layer = RequestWriterLayer::writer_unbounded(&root, output, Some(WriterMode::Headers));
    let service = layer.into_layer(service_fn(async |_: Request| {
        Ok::<_, Infallible>(Response::new(Body::empty()))
    }));
    let request = Request::builder()
        .uri("http://example.com/blocked")
        .body(Body::empty())
        .unwrap();
    service.serve(request).await.unwrap();
    for _ in 0..8 {
        tokio::task::yield_now().await;
    }

    // Only the writer holds the scope from here on.
    let root = root.into_weak_scope();
    let drained = root.drained();
    let mut drained = std::pin::pin!(drained);
    root.cancel(Cause::Owner);
    assert!(
        timeout(WAIT, drained.as_mut()).await.is_err(),
        "a blocked writer cannot drain in the graceful phase"
    );
    root.abort(Cause::Owner);
    timeout(WAIT, drained)
        .await
        .expect("the hard phase drops the blocked writer");
    drop(service);
}

#[tokio::test]
async fn a_writer_whose_scope_closed_serves_a_streaming_request_uncaptured() {
    let root = Scope::new();
    let (output, captured) = duplex(4096);
    let service = RequestWriterLayer::writer_unbounded(&root, output, Some(WriterMode::All))
        .into_layer(service_fn(async |request: Request| {
            let body = request.into_body().collect().await.unwrap().to_bytes();
            Ok::<_, Infallible>(Response::new(Body::from(body)))
        }));
    assert!(written_once_ended(root, captured).await.is_empty());

    // Far more than the capture channel's one frame: a kept capture would stall this body.
    let chunks = (0..64).map(|_| Ok::<_, BoxError>(Bytes::from_static(&[7; 1024])));
    let request = Request::builder()
        .uri("http://example.com/after")
        .body(Body::from_stream(stream::iter(chunks)))
        .unwrap();
    let response = timeout(WAIT, service.serve(request))
        .await
        .expect("the request is served without its capture")
        .unwrap();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(body.len(), 64 * 1024);
}

#[tokio::test]
async fn a_writer_whose_scope_closed_serves_a_streaming_response_uncaptured() {
    let root = Scope::new();
    let (output, captured) = duplex(4096);
    let service = ResponseWriterLayer::writer_unbounded(&root, output, Some(WriterMode::All))
        .into_layer(service_fn(async |_: Request| {
            let chunks = (0..64).map(|_| Ok::<_, BoxError>(Bytes::from_static(&[7; 1024])));
            Ok::<_, Infallible>(Response::new(Body::from_stream(stream::iter(chunks))))
        }));
    assert!(written_once_ended(root, captured).await.is_empty());

    let request = Request::builder()
        .uri("http://example.com/after")
        .body(Body::empty())
        .unwrap();
    let response = service.serve(request).await.unwrap();
    // Far more than the capture channel's one frame: a kept capture would stall this body.
    let body = timeout(WAIT, response.into_body().collect())
        .await
        .expect("the response is served without its capture")
        .unwrap()
        .to_bytes();
    assert_eq!(body.len(), 64 * 1024);
}
