use super::*;
use crate::{
    Body, HeaderMap, Response, StatusCode,
    body::{
        CollectOptions, Frame, SizeHint,
        util::{Full, StreamBody},
    },
    request::Parts,
};
use rama_core::{
    bytes::Bytes,
    error::BoxErrorExt as _,
    futures::{StreamExt as _, stream},
    service::service_fn,
};
use std::{
    cell::Cell,
    convert::Infallible,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

fn trailers() -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert("x-checksum", "hello-world".parse().unwrap());
    headers
}

#[tokio::test]
async fn declined_body_is_not_polled_or_cloned_before_service() {
    let polls = Arc::new(AtomicUsize::new(0));
    let body_polls = polls.clone();
    // Cell makes this Send but not Sync; Cursor tests generic Buf adaptation.
    let next = Cell::new(0);
    let body = StreamBody::new(stream::poll_fn(move |_| {
        body_polls.fetch_add(1, Ordering::Relaxed);
        let frame = match next.replace(next.get() + 1) {
            0 => Some(Frame::data(std::io::Cursor::new(b"hello".to_vec()))),
            1 => Some(Frame::trailers(trailers())),
            _ => None,
        };
        std::task::Poll::Ready(frame.map(Ok::<_, Infallible>))
    }));
    let policy = Arc::new(
        ManagedPolicy::default()
            .with_prepare_body(|parts: &Parts, _: bool, _: &SizeHint| {
                assert_eq!(parts.method, crate::Method::POST);
                None
            })
            .with_clone(|_: &Request<RetryBody>| -> Option<Request<RetryBody>> {
                panic!("one-shot body must not be cloned")
            }),
    );
    let retry = Retry::new(
        policy,
        service_fn(move |req: Request<RetryBody>| {
            assert_eq!(polls.load(Ordering::Relaxed), 0);
            async move {
                assert!(req.body().try_clone().is_none());
                let mut collected = req.into_body().collect().await.unwrap();
                assert_eq!(collected.take_trailers(), Some(trailers()));
                assert_eq!(collected.to_bytes(), "hello");
                Ok::<_, BoxError>(Response::builder().status(500).body(Body::empty()).unwrap())
            }
        }),
    );
    let req = Request::builder().method("POST").body(body).unwrap();
    assert_eq!(
        retry.serve(req).await.unwrap().status(),
        StatusCode::INTERNAL_SERVER_ERROR
    );
}

#[tokio::test]
async fn policy_can_decline_empty_bodies_and_do_not_retry_skips_preparation() {
    for do_not_retry in [false, true] {
        let prepared = Arc::new(AtomicUsize::new(0));
        let calls = prepared.clone();
        let policy = ManagedPolicy::default()
            .with_prepare_body(move |_: &Parts, is_end_stream: bool, _: &SizeHint| {
                calls.fetch_add(1, Ordering::Relaxed);
                assert!(is_end_stream);
                None
            })
            .with_clone(|_: &Request<RetryBody>| -> Option<Request<RetryBody>> {
                panic!("declined empty request must not be cloned")
            });
        let req = Request::new(Body::empty());
        if do_not_retry {
            req.extensions().insert(managed::DoNotRetry::default());
        }
        let retry = Retry::new(
            policy,
            service_fn(async |req: Request<RetryBody>| {
                assert!(!req.body().is_replayable());
                assert!(req.body().is_end_stream());
                Ok::<_, BoxError>(Response::new(Body::empty()))
            }),
        );
        retry.serve(req).await.unwrap();
        assert_eq!(prepared.load(Ordering::Relaxed), usize::from(!do_not_retry));
    }
}

#[tokio::test]
async fn replay_preserves_data_and_trailers_even_with_zero_byte_hint() {
    for data in [Bytes::new(), Bytes::from_static(b"hello")] {
        let expected = data.clone();
        let calls = Arc::new(AtomicUsize::new(0));
        let service_calls = calls.clone();
        let policy =
            ManagedPolicy::default().with_prepare_body(|_: &Parts, _: bool, _: &SizeHint| {
                Some(CollectOptions::new().with_max_size(16))
            });
        let retry = Retry::new(
            policy,
            service_fn(move |req: Request<RetryBody>| {
                let expected = expected.clone();
                let attempt = service_calls.fetch_add(1, Ordering::Relaxed);
                async move {
                    assert!(req.body().is_replayable());
                    assert!(!req.body().is_end_stream());
                    // Byte extraction must not discard trailers on either attempt.
                    let body = req.into_body().into_bytes().unwrap_err();
                    let mut collected = body.collect().await.unwrap();
                    assert_eq!(collected.take_trailers(), Some(trailers()));
                    assert_eq!(collected.to_bytes(), expected);
                    Ok::<_, BoxError>(
                        Response::builder()
                            .status(if attempt == 0 { 500 } else { 200 })
                            .body(Body::empty())
                            .unwrap(),
                    )
                }
            }),
        );
        let body = Full::new(data).with_trailers(async { Some(Ok::<_, Infallible>(trailers())) });
        assert_eq!(
            retry.serve(Request::new(body)).await.unwrap().status(),
            StatusCode::OK
        );
        assert_eq!(calls.load(Ordering::Relaxed), 2);
    }
}

#[tokio::test]
async fn capped_collection_restores_the_prefix_remainder_and_trailers_once() {
    let body = Body::from_frame_stream(stream::iter([
        Ok::<_, Infallible>(Frame::data(Bytes::from_static(b"hello"))),
        Ok(Frame::data(Bytes::from_static(b"world"))),
        Ok(Frame::trailers(trailers())),
    ]));
    let policy = ManagedPolicy::default().with_prepare_body(|_: &Parts, _: bool, _: &SizeHint| {
        Some(CollectOptions::new().with_max_size(3))
    });
    let retry = Retry::new(
        policy,
        service_fn(async |req: Request<RetryBody>| {
            assert!(!req.body().is_replayable());
            req.extensions().insert(managed::DoNotRetry::default());
            let body = req.into_body().into_bytes().unwrap_err();
            let mut collected = body.collect().await.unwrap();
            assert_eq!(collected.take_trailers(), Some(trailers()));
            assert_eq!(collected.to_bytes(), "helloworld");
            Ok::<_, BoxError>(Response::builder().status(500).body(Body::empty()).unwrap())
        }),
    );
    let request = Request::new(body);
    let caller = request.extensions().clone();
    assert_eq!(
        retry.serve(request).await.unwrap().status(),
        StatusCode::INTERNAL_SERVER_ERROR
    );
    assert!(!caller.contains::<managed::DoNotRetry>());
}

#[tokio::test]
async fn timeout_restores_read_prefix_and_stalled_remainder_once() {
    let (tx, rx) = tokio::sync::oneshot::channel();
    let body = Body::from_frame_stream(
        stream::once(async { Ok::<_, Infallible>(Frame::data(Bytes::from_static(b"hello"))) })
            .chain(stream::once(async {
                rx.await.unwrap();
                Ok(Frame::data(Bytes::from_static(b"world")))
            }))
            .chain(stream::once(async { Ok(Frame::trailers(trailers())) })),
    );
    let sender = parking_lot::Mutex::new(Some(tx));
    let policy = ManagedPolicy::default().with_prepare_body(|_: &Parts, _: bool, _: &SizeHint| {
        Some(CollectOptions::new().with_timeout(Duration::from_millis(1)))
    });
    let retry = Retry::new(
        policy,
        service_fn(move |req: Request<RetryBody>| {
            sender.lock().take().unwrap().send(()).unwrap();
            async move {
                assert!(!req.body().is_replayable());
                let mut collected = req.into_body().collect().await.unwrap();
                assert_eq!(collected.take_trailers(), Some(trailers()));
                assert_eq!(collected.to_bytes(), "helloworld");
                Ok::<_, BoxError>(Response::builder().status(500).body(Body::empty()).unwrap())
            }
        }),
    );
    assert_eq!(
        retry.serve(Request::new(body)).await.unwrap().status(),
        StatusCode::INTERNAL_SERVER_ERROR
    );
}

#[tokio::test]
async fn body_source_error_is_not_forwarded_or_retried() {
    let body = Body::from_frame_stream(stream::iter([
        Ok(Frame::data(Bytes::from_static(b"hello"))),
        Err(BoxError::from_static_str("source failed")),
    ]));
    let retry = Retry::new(
        ManagedPolicy::default(),
        service_fn(
            async |_: Request<RetryBody>| -> Result<Response, BoxError> {
                panic!("a failed body cannot reach the service")
            },
        ),
    );
    assert!(matches!(
        retry.serve(Request::new(body)).await.unwrap_err().kind,
        RetryErrorKind::BodyConsume
    ));
}

#[tokio::test]
async fn canceling_preparation_releases_the_body_without_sending() {
    let polled = Arc::new(tokio::sync::Notify::new());
    let started = polled.clone();
    let dropped = Arc::new(AtomicUsize::new(0));
    let drop_count = dropped.clone();
    let body = Body::from_frame_stream(stream::poll_fn(move |_| {
        started.notify_one();
        std::task::Poll::<Option<Result<Frame<Bytes>, Infallible>>>::Pending
    }))
    .on_drop(move || {
        drop_count.fetch_add(1, Ordering::Relaxed);
    });
    async fn unexpected_service(_: Request<RetryBody>) -> Result<Response, BoxError> {
        panic!("canceled preparation cannot reach the service")
    }
    let retry = Retry::new(ManagedPolicy::default(), service_fn(unexpected_service));
    let mut future = Box::pin(retry.serve(Request::new(body)));
    assert!(rama_core::futures::poll!(future.as_mut()).is_pending());
    polled.notified().await;
    drop(future);
    assert_eq!(dropped.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn approved_empty_body_is_empty_on_every_attempt() {
    let calls = Arc::new(AtomicUsize::new(0));
    let service_calls = calls.clone();
    let retry = Retry::new(
        ManagedPolicy::default(),
        service_fn(move |req: Request<RetryBody>| {
            let count = service_calls.fetch_add(1, Ordering::Relaxed);
            async move {
                assert!(req.body().is_end_stream());
                assert_eq!(req.body().size_hint().exact(), Some(0));
                Ok::<_, BoxError>(
                    Response::builder()
                        .status(if count == 0 { 500 } else { 200 })
                        .body(Body::empty())
                        .unwrap(),
                )
            }
        }),
    );
    assert_eq!(
        retry
            .serve(Request::new(Body::empty()))
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
    assert_eq!(calls.load(Ordering::Relaxed), 2);
}

#[tokio::test]
async fn streaming_fallback_preserves_exact_length_through_body_conversion() {
    for cap in [None, Some(3)] {
        let policy =
            ManagedPolicy::default().with_prepare_body(move |_: &Parts, _: bool, _: &SizeHint| {
                cap.map(|cap| CollectOptions::new().with_max_size(cap))
            });
        let retry = Retry::new(
            policy,
            service_fn(async |req: Request<RetryBody>| {
                assert!(!req.body().is_replayable());
                assert_eq!(req.body().size_hint().exact(), Some(10));
                let mut body = Body::from(req.into_body());
                assert_eq!(body.size_hint().exact(), Some(10));
                let mut remaining = 10;
                while let Some(frame) = body.frame().await {
                    if let Ok(data) = frame.unwrap().into_data() {
                        remaining -= data.len() as u64;
                    }
                    assert_eq!(body.size_hint().exact(), Some(remaining));
                }
                assert_eq!(remaining, 0);
                Ok::<_, BoxError>(Response::new(Body::empty()))
            }),
        );
        retry
            .serve(Request::new(Body::from("helloworld")))
            .await
            .unwrap();
    }

    let request = Request::new(Body::from("hello"));
    request.extensions().insert(managed::DoNotRetry::default());
    Retry::new(
        ManagedPolicy::default(),
        service_fn(async |req: Request<RetryBody>| {
            assert!(!req.body().is_replayable());
            assert_eq!(Body::from(req.into_body()).size_hint().exact(), Some(5));
            Ok::<_, BoxError>(Response::new(Body::empty()))
        }),
    )
    .serve(request)
    .await
    .unwrap();
}
