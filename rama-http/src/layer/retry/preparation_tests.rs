use std::{
    cell::Cell,
    convert::Infallible,
    future::{pending, ready},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};

use parking_lot::Mutex;
use rama_core::{
    bytes::Bytes,
    error::BoxErrorExt as _,
    futures::{FutureExt as _, StreamExt as _, poll, stream},
    service::service_fn,
};
use storage::MemoryReplay;
use tokio::{
    sync::oneshot,
    time::{Instant, advance, sleep},
};

use super::{storage::ReplayStore as _, *};
use crate::{
    Body, HeaderMap, Response, StatusCode,
    body::{
        CollectOptions, Frame, SizeHint,
        util::{Full, StreamBody},
    },
    request::Parts,
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
                    assert_eq!(req.body().is_replayable(), attempt > 0);
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
async fn crossing_the_memory_cap_forwards_the_whole_frame_and_trailers_once() {
    let body = Body::from_frame_stream(stream::iter([
        Ok::<_, Infallible>(Frame::data(Bytes::from_static(b"hello"))),
        Ok(Frame::data(Bytes::from_static(b"world"))),
        Ok(Frame::trailers(trailers())),
    ]));
    let policy = ManagedPolicy::default().with_prepare_body(|_: &Parts, _: bool, _: &SizeHint| {
        Some(CollectOptions::new().with_max_size(3))
    });
    let calls = AtomicUsize::new(0);
    let retry = Retry::new(
        policy,
        service_fn(move |req: Request<RetryBody>| {
            assert_eq!(calls.fetch_add(1, Ordering::Relaxed), 0);
            async move {
                assert!(!req.body().is_replayable());
                let body = req.into_body().into_bytes().unwrap_err();
                let mut collected = body.collect().await.unwrap();
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

#[tokio::test(start_paused = true)]
async fn capture_timeout_while_uploading_preserves_later_frames() {
    let body = Body::from_frame_stream(
        stream::once(async { Ok::<_, Infallible>(Frame::data(Bytes::from_static(b"hello"))) })
            .chain(stream::once(async {
                tokio::time::sleep(Duration::from_secs(2)).await;
                Ok(Frame::data(Bytes::from_static(b"world")))
            }))
            .chain(stream::once(async { Ok(Frame::trailers(trailers())) })),
    );
    let calls = AtomicUsize::new(0);
    let policy = ManagedPolicy::default().with_prepare_body(|_: &Parts, _: bool, _: &SizeHint| {
        Some(CollectOptions::new().with_timeout(Duration::from_secs(1)))
    });
    let retry = Retry::new(
        policy,
        service_fn(move |req: Request<RetryBody>| {
            assert_eq!(calls.fetch_add(1, Ordering::Relaxed), 0);
            async move {
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
async fn source_errors_reach_the_first_reader_and_disable_replay() {
    let body = Body::from_frame_stream(stream::iter([
        Ok(Frame::data(Bytes::from_static(b"hello"))),
        Err(BoxError::from_static_str("source failed")),
    ]));
    let calls = AtomicUsize::new(0);
    let retry = Retry::new(
        ManagedPolicy::default(),
        service_fn(move |req: Request<RetryBody>| {
            assert_eq!(calls.fetch_add(1, Ordering::Relaxed), 0);
            async move {
                let mut body = req.into_body();
                assert_eq!(
                    body.frame().await.unwrap().unwrap().into_data().unwrap(),
                    "hello"
                );
                let error = body.frame().await.unwrap().unwrap_err();
                assert_eq!(error.to_string(), "source failed");
                Ok::<_, BoxError>(Response::builder().status(503).body(Body::empty()).unwrap())
            }
        }),
    );
    assert_eq!(
        retry.serve(Request::new(body)).await.unwrap().status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
}

#[tokio::test]
async fn canceling_the_drain_releases_the_source() {
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
    let calls = AtomicUsize::new(0);
    let retry = Retry::new(
        ManagedPolicy::default(),
        service_fn(move |_: Request<RetryBody>| {
            assert_eq!(calls.fetch_add(1, Ordering::Relaxed), 0);
            async {
                Ok::<_, BoxError>(Response::builder().status(503).body(Body::empty()).unwrap())
            }
        }),
    );
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

#[tokio::test]
async fn exact_memory_cap_includes_trailers_and_one_more_byte_suppresses_retry() {
    for (suffix, expected_attempts) in [("", 2), ("!", 1)] {
        let source = Body::from_frame_stream(stream::iter([
            Ok::<_, Infallible>(Frame::data(Bytes::from_static(b"hello"))),
            Ok(Frame::data(Bytes::from(suffix))),
            Ok(Frame::trailers(trailers())),
        ]));
        let calls = Arc::new(AtomicUsize::new(0));
        let service_calls = calls.clone();
        let retry = Retry::new(
            ManagedPolicy::default().with_replay_store(storage::MemoryReplay::new(5)),
            service_fn(move |req: Request<RetryBody>| {
                let attempt = service_calls.fetch_add(1, Ordering::Relaxed);
                async move {
                    if attempt == 0 {
                        // Leave every frame unread. The coordinator must find EOF
                        // for the exact-cap case, including the trailing headers.
                        return Ok::<_, BoxError>(
                            Response::builder().status(503).body(Body::empty()).unwrap(),
                        );
                    }
                    assert_eq!(attempt, 1);
                    assert_eq!(req.body().size_hint().exact(), Some(5));
                    let mut body = req.into_body().collect().await.unwrap();
                    assert_eq!(body.take_trailers(), Some(trailers()));
                    assert_eq!(body.to_bytes(), "hello");
                    Ok(Response::new(Body::empty()))
                }
            }),
        );
        let response = retry.serve(Request::new(source)).await.unwrap();
        assert_eq!(calls.load(Ordering::Relaxed), expected_attempts);
        assert_eq!(
            response.status(),
            if expected_attempts == 2 {
                StatusCode::OK
            } else {
                StatusCode::SERVICE_UNAVAILABLE
            }
        );
    }
}

#[tokio::test]
async fn default_replay_limit_applies_to_inline_and_fragmented_bodies() {
    let limit = rama_utils::octets::kib(64);
    for (len, expected_status) in [
        (limit, StatusCode::OK),
        (limit + 1, StatusCode::SERVICE_UNAVAILABLE),
    ] {
        for fragmented in [false, true] {
            let bytes = Bytes::from(vec![0x5a; len]);
            let source = if fragmented {
                Body::from_stream(stream::iter([
                    Ok::<_, Infallible>(bytes.slice(..limit / 2)),
                    Ok(bytes.slice(limit / 2..)),
                ]))
            } else {
                Body::from(bytes.clone())
            };
            let calls = AtomicUsize::new(0);
            let retry = Retry::new(
                ManagedPolicy::default(),
                service_fn(move |req: Request<RetryBody>| {
                    let attempt = calls.fetch_add(1, Ordering::Relaxed);
                    let expected = bytes.clone();
                    async move {
                        assert!(attempt < 2);
                        assert_eq!(
                            req.into_body().collect().await.unwrap().to_bytes(),
                            expected
                        );
                        Ok::<_, BoxError>(
                            Response::builder()
                                .status(if attempt == 0 { 503 } else { 200 })
                                .body(Body::empty())
                                .unwrap(),
                        )
                    }
                }),
            );
            let response = retry.serve(Request::new(source)).await.unwrap();
            assert_eq!(response.status(), expected_status);
        }
    }
}

#[tokio::test]
async fn terminal_response_never_polls_an_unread_source() {
    let source = Body::from_frame_stream(stream::poll_fn(
        |_| -> std::task::Poll<Option<Result<Frame<Bytes>, Infallible>>> {
            panic!("terminal response should not drain the body")
        },
    ));
    let retry = Retry::new(
        ManagedPolicy::default(),
        service_fn(async |_: Request<RetryBody>| {
            Ok::<_, BoxError>(Response::builder().status(413).body(Body::empty()).unwrap())
        }),
    );
    assert_eq!(
        retry.serve(Request::new(source)).await.unwrap().status(),
        StatusCode::PAYLOAD_TOO_LARGE
    );
}

#[tokio::test(start_paused = true)]
async fn stalled_drain_returns_the_first_response_at_the_deadline() {
    let retry = Retry::new(
        ManagedPolicy::default()
            .with_replay_store(storage::MemoryReplay::new(5).with_timeout(Duration::from_secs(1))),
        service_fn(async |_: Request<RetryBody>| {
            Ok::<_, BoxError>(
                Response::builder()
                    .status(503)
                    .body(Body::from("original"))
                    .unwrap(),
            )
        }),
    );
    let response = tokio::time::timeout(
        Duration::from_secs(2),
        retry.serve(Request::new(Body::from_frame_stream(stream::pending::<
            Result<Frame<Bytes>, Infallible>,
        >()))),
    )
    .await
    .expect("drain must observe its deadline")
    .unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        response.into_body().collect().await.unwrap().to_bytes(),
        "original"
    );
}

#[tokio::test]
async fn early_response_drops_partial_reader_and_replays_from_the_start_of_the_file() {
    let parent = rama_utils::fs::TempDir::new().await.unwrap();
    let store = storage::FsReplayStore::new(parent.path(), 2, 64, 10)
        .await
        .unwrap();
    let allow_tail = Arc::new(tokio::sync::Notify::new());
    let retry = Retry::new(
        ManagedPolicy::default().with_replay_store(store),
        service_fn({
            let allow_tail = allow_tail.clone();
            let calls = AtomicUsize::new(0);
            move |req: Request<RetryBody>| {
                let allow_tail = allow_tail.clone();
                let attempt = calls.fetch_add(1, Ordering::Relaxed) % 2;
                async move {
                    let mut body = req.into_body();
                    if attempt == 0 {
                        assert_eq!(
                            body.frame().await.unwrap().unwrap().into_data().unwrap(),
                            "hello"
                        );
                        allow_tail.notify_one();
                        // Release the first reader after spilling its prefix.
                        // The retry layer must finish the unread tail.
                        drop(body);
                        return Ok::<_, BoxError>(
                            Response::builder().status(503).body(Body::empty()).unwrap(),
                        );
                    }
                    assert_eq!(attempt, 1);
                    assert_eq!(body.size_hint().exact(), Some(10));
                    let mut received = Vec::new();
                    let mut received_trailers = None;
                    while let Some(frame) = body.frame().await {
                        match frame.unwrap().into_data() {
                            Ok(bytes) => received.extend_from_slice(&bytes),
                            Err(frame) => received_trailers = Some(frame.into_trailers().unwrap()),
                        }
                        assert_eq!(body.size_hint().exact(), Some(10 - received.len() as u64));
                    }
                    assert_eq!(received, b"helloworld");
                    assert_eq!(received_trailers, Some(trailers()));
                    Ok(Response::new(Body::empty()))
                }
            }
        }),
    );
    for _ in 0..2 {
        // The source cannot finish until the service sees the first frame,
        // which already exceeds the two-byte spill threshold.
        let source = Body::from_frame_stream(
            stream::once(async { Ok::<_, Infallible>(Frame::data(Bytes::from_static(b"hello"))) })
                .chain(stream::once({
                    let allow_tail = allow_tail.clone();
                    async move {
                        allow_tail.notified().await;
                        Ok(Frame::data(Bytes::from_static(b"world")))
                    }
                }))
                .chain(stream::once(async { Ok(Frame::trailers(trailers())) })),
        );
        // The store's entire disk budget is ten bytes. A second successful
        // replay requires release of the first request's reservation.
        let response =
            tokio::time::timeout(Duration::from_secs(5), retry.serve(Request::new(source)))
                .await
                .expect("draining the released reader should allow the retry to finish")
                .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }
}

#[tokio::test]
async fn a_missing_spool_directory_preserves_the_upload_and_the_first_response() {
    let parent = rama_utils::fs::TempDir::new().await.unwrap();
    let store = storage::FsReplayStore::new(parent.path(), 1, 8, 8)
        .await
        .unwrap();
    tokio::fs::remove_dir(store.directory()).await.unwrap();

    for read_upload in [true, false] {
        let attempts = Arc::new(AtomicUsize::new(0));
        let calls = attempts.clone();
        let retry = Retry::new(
            ManagedPolicy::default().with_replay_store(store.clone()),
            service_fn(move |req: Request<RetryBody>| {
                assert_eq!(calls.fetch_add(1, Ordering::Relaxed), 0);
                async move {
                    if read_upload {
                        let mut upload = req.into_body().collect().await.unwrap();
                        assert_eq!(upload.take_trailers(), Some(trailers()));
                        assert_eq!(upload.to_bytes(), "abcde");
                    }
                    Ok::<_, BoxError>(
                        Response::builder()
                            .status(503)
                            .body(Body::from("original response"))
                            .unwrap(),
                    )
                }
            }),
        );
        let crossed = Arc::new(AtomicBool::new(false));
        let observed = crossed.clone();
        let source = Body::from_frame_stream(stream::iter([
            Ok::<_, Infallible>(Frame::data(Bytes::from_static(b"a"))),
            Ok(Frame::data(Bytes::from_static(b"bc"))),
            Ok(Frame::data(Bytes::from_static(b"de"))),
            Ok(Frame::trailers(trailers())),
        ]))
        .inspect_frame(move |frame| {
            if frame.data_ref().is_some_and(|bytes| bytes == "bc") {
                observed.store(true, Ordering::Relaxed);
            }
        });
        let response = retry.serve(Request::new(source)).await.unwrap();
        assert!(
            crossed.load(Ordering::Relaxed),
            "capture must reach the spill threshold"
        );
        assert_eq!(attempts.load(Ordering::Relaxed), 1);
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            response.into_body().collect().await.unwrap().to_bytes(),
            "original response"
        );
    }
}

#[tokio::test]
async fn terminal_response_can_keep_streaming_the_original_request_body() {
    let body = Body::from_frame_stream(stream::iter([
        Ok::<_, Infallible>(Frame::data(Bytes::from_static(b"hello"))),
        Ok(Frame::trailers(trailers())),
    ]));
    let echo = Retry::new(
        ManagedPolicy::default(),
        service_fn(async |req: Request<RetryBody>| {
            Ok::<_, BoxError>(Response::new(Body::from(req.into_body())))
        }),
    );
    let response = echo.serve(Request::new(body)).await.unwrap();
    let mut echoed = response.into_body().collect().await.unwrap();
    assert_eq!(echoed.take_trailers(), Some(trailers()));
    assert_eq!(echoed.to_bytes(), "hello");
}

#[tokio::test(start_paused = true)]
async fn retryable_response_echoes_undelivered_frames_with_backoff_or_size_limits() {
    // The echoed reader lives inside the outcome, so a retry waits for it until
    // the handoff timeout and then returns that outcome unchanged.
    async fn assert_echo(
        policy: impl Policy<Response, BoxError>,
        consume_prefix: bool,
        expected_wait: Duration,
    ) {
        let started = Instant::now();
        let calls = Arc::new(AtomicUsize::new(0));
        let attempts = calls.clone();
        let retry = Retry::new(
            policy,
            service_fn(move |req: Request<RetryBody>| {
                assert_eq!(attempts.fetch_add(1, Ordering::Relaxed), 0);
                async move {
                    let mut body = req.into_body();
                    if consume_prefix {
                        assert_eq!(
                            body.frame().await.unwrap().unwrap().into_data().unwrap(),
                            "ab"
                        );
                    }
                    Ok::<_, BoxError>(
                        Response::builder()
                            .status(503)
                            .body(Body::from(body))
                            .unwrap(),
                    )
                }
            }),
        );
        let source = Body::from_frame_stream(stream::iter([
            Ok::<_, Infallible>(Frame::data(Bytes::from_static(b"ab"))),
            Ok(Frame::data(Bytes::from_static(b"cdef"))),
            Ok(Frame::data(Bytes::from_static(b"gh"))),
            Ok(Frame::trailers(trailers())),
        ]));
        let response = retry.serve(Request::new(source)).await.unwrap();
        assert_eq!(started.elapsed(), expected_wait);
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let mut echoed = response.into_body().collect().await.unwrap();
        assert_eq!(echoed.take_trailers(), Some(trailers()));
        assert_eq!(
            echoed.to_bytes(),
            if consume_prefix { "cdefgh" } else { "abcdefgh" }
        );
        assert_eq!(calls.load(Ordering::Relaxed), 1);
    }

    let policy = |cap| ManagedPolicy::default().with_replay_store(storage::MemoryReplay::new(cap));
    assert_echo(
        policy(20).with_backoff(()),
        false,
        storage::DEFAULT_HANDOFF_TIMEOUT,
    )
    .await;
    // The unread frames would exceed this limit, which only reading them reveals.
    assert_echo(policy(3), true, storage::DEFAULT_HANDOFF_TIMEOUT).await;
}

/// Request body reader kept by a task outside the attempt, like a connection
/// task that is still writing the upload when the response arrives.
struct HeldReader {
    release: Arc<Mutex<Option<oneshot::Sender<()>>>>,
    released: Arc<Mutex<Option<oneshot::Receiver<()>>>>,
}

impl HeldReader {
    fn new() -> Self {
        let (release, released) = oneshot::channel();
        Self {
            release: Arc::new(Mutex::new(Some(release))),
            released: Arc::new(Mutex::new(Some(released))),
        }
    }

    fn release(&self) {
        if let Some(release) = self.release.lock().take() {
            _ = release.send(());
        }
    }
}

fn held_reader_source() -> Body {
    Body::from_frame_stream(stream::iter([
        Ok::<_, Infallible>(Frame::data(Bytes::from_static(b"hello"))),
        Ok(Frame::data(Bytes::from_static(b"world"))),
        Ok(Frame::trailers(trailers())),
    ]))
}

#[tokio::test(start_paused = true)]
async fn policy_retry_waits_for_a_reader_held_after_the_attempt_returned() {
    for read_to_end in [false, true] {
        let holder = HeldReader::new();
        let consulted = Arc::new(AtomicUsize::new(0));
        let policy = ManagedPolicy::new({
            let release = holder.release.clone();
            let consulted = consulted.clone();
            move |req: Request<RetryBody>, result: Result<Response, BoxError>| {
                consulted.fetch_add(1, Ordering::Relaxed);
                let retry = matches!(&result, Ok(res) if res.status().is_server_error());
                if retry && let Some(release) = release.lock().take() {
                    // The reader is released only once the policy decided to retry.
                    _ = release.send(());
                }
                ready((req, result, retry))
            }
        });
        let attempts = Arc::new(AtomicUsize::new(0));
        let retry = Retry::new(
            policy,
            service_fn({
                let attempts = attempts.clone();
                let released = holder.released.clone();
                move |req: Request<RetryBody>| {
                    let attempt = attempts.fetch_add(1, Ordering::Relaxed);
                    let released = released.lock().take();
                    async move {
                        let mut body = req.into_body();
                        if attempt == 0 {
                            assert_eq!(
                                body.frame().await.unwrap().unwrap().into_data().unwrap(),
                                "hello"
                            );
                            let released = released.unwrap();
                            tokio::spawn(async move {
                                _ = released.await;
                                if read_to_end {
                                    while body.frame().await.is_some() {}
                                    // Keep the finished reader alive.
                                    pending::<()>().await;
                                }
                                drop(body);
                            });
                            return Ok::<_, BoxError>(
                                Response::builder().status(503).body(Body::empty()).unwrap(),
                            );
                        }
                        let mut replay = body.collect().await.unwrap();
                        assert_eq!(replay.take_trailers(), Some(trailers()));
                        assert_eq!(replay.to_bytes(), "helloworld");
                        Ok(Response::new(Body::empty()))
                    }
                }
            }),
        );
        let response = retry
            .serve(Request::new(held_reader_source()))
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            StatusCode::OK,
            "read_to_end: {read_to_end}"
        );
        assert_eq!(attempts.load(Ordering::Relaxed), 2);
        assert_eq!(consulted.load(Ordering::Relaxed), 2);
    }
}

#[tokio::test(start_paused = true)]
async fn reader_release_counts_only_before_the_handoff_deadline() {
    // The coordinator is polled again only at two seconds, after the one-second handoff.
    for (release_after, expected) in [
        (Duration::from_millis(500), StatusCode::OK),
        (Duration::from_millis(1500), StatusCode::SERVICE_UNAVAILABLE),
    ] {
        let held = Arc::new(Mutex::new(None));
        let attempts = Arc::new(AtomicUsize::new(0));
        let retry = Retry::new(
            ManagedPolicy::default().with_replay_store(
                MemoryReplay::new(64)
                    .with_timeout(Duration::from_secs(30))
                    .with_handoff_timeout(Duration::from_secs(1)),
            ),
            service_fn({
                let held = held.clone();
                let attempts = attempts.clone();
                move |req: Request<RetryBody>| {
                    let attempt = attempts.fetch_add(1, Ordering::Relaxed);
                    let held = held.clone();
                    async move {
                        if attempt == 0 {
                            *held.lock() = Some(req.into_body());
                            return Ok::<_, BoxError>(
                                Response::builder().status(503).body(Body::empty()).unwrap(),
                            );
                        }
                        let mut replay = req.into_body().collect().await.unwrap();
                        assert_eq!(replay.take_trailers(), Some(trailers()));
                        assert_eq!(replay.to_bytes(), "helloworld");
                        Ok(Response::new(Body::empty()))
                    }
                }
            }),
        );
        let mut serve = Box::pin(retry.serve(Request::new(held_reader_source())));
        assert!(poll!(serve.as_mut()).is_pending());
        advance(release_after).await;
        drop(held.lock().take().expect("first attempt keeps its reader"));
        advance(Duration::from_secs(2).saturating_sub(release_after)).await;
        let response = serve.await.unwrap();
        assert_eq!(response.status(), expected, "{release_after:?}");
        let expected_attempts = if expected == StatusCode::OK { 2 } else { 1 };
        assert_eq!(attempts.load(Ordering::Relaxed), expected_attempts);
    }
}

#[tokio::test(start_paused = true)]
async fn policy_still_classifies_when_the_replay_is_unavailable() {
    // An oversized capture and an expired capture both leave no replay.
    for expired in [false, true] {
        let store = if expired {
            MemoryReplay::new(64).with_timeout(Duration::from_secs(1))
        } else {
            MemoryReplay::new(3)
        };
        let consulted = Arc::new(AtomicUsize::new(0));
        let policy = ManagedPolicy::new({
            let consulted = consulted.clone();
            move |req: Request<RetryBody>, _: Result<Response, BoxError>| {
                consulted.fetch_add(1, Ordering::Relaxed);
                let transformed = Response::builder().status(502).body(Body::empty()).unwrap();
                ready((req, Ok(transformed), true))
            }
        })
        .with_replay_store(store);
        let attempts = Arc::new(AtomicUsize::new(0));
        let retry = Retry::new(
            policy,
            service_fn({
                let attempts = attempts.clone();
                move |req: Request<RetryBody>| {
                    attempts.fetch_add(1, Ordering::Relaxed);
                    async move {
                        if expired {
                            sleep(Duration::from_secs(2)).await;
                        } else {
                            req.into_body().collect().await.unwrap();
                        }
                        Ok::<_, BoxError>(
                            Response::builder().status(503).body(Body::empty()).unwrap(),
                        )
                    }
                }
            }),
        );
        let response = retry
            .serve(Request::new(held_reader_source()))
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            StatusCode::BAD_GATEWAY,
            "expired: {expired}"
        );
        assert_eq!(consulted.load(Ordering::Relaxed), 1);
        assert_eq!(attempts.load(Ordering::Relaxed), 1);
    }
}

/// A retry keeps waiting for a held reader for `expected`, then returns the
/// first outcome while the reader still streams the rest of the upload.
async fn assert_held_reader_wait_ends_after(store: storage::MemoryReplay, expected: Duration) {
    let holder = HeldReader::new();
    let consulted = Arc::new(AtomicUsize::new(0));
    let policy = ManagedPolicy::new({
        let consulted = consulted.clone();
        move |req: Request<RetryBody>, result: Result<Response, BoxError>| {
            consulted.fetch_add(1, Ordering::Relaxed);
            ready((req, result, true))
        }
    })
    .with_replay_store(store);
    let (forwarded_tx, forwarded) = oneshot::channel();
    let forwarded_tx = Mutex::new(Some(forwarded_tx));
    let attempts = AtomicUsize::new(0);
    let released = holder.released.clone();
    let retry = Retry::new(
        policy,
        service_fn(move |req: Request<RetryBody>| {
            assert_eq!(attempts.fetch_add(1, Ordering::Relaxed), 0);
            let released = released.lock().take().unwrap();
            let forwarded_tx = forwarded_tx.lock().take().unwrap();
            async move {
                let mut body = req.into_body();
                assert_eq!(
                    body.frame().await.unwrap().unwrap().into_data().unwrap(),
                    "hello"
                );
                tokio::spawn(async move {
                    _ = released.await;
                    // The reader keeps streaming after the retry was given up.
                    let mut rest = body.collect().await.unwrap();
                    _ = forwarded_tx.send((rest.take_trailers(), rest.to_bytes()));
                });
                Ok::<_, BoxError>(
                    Response::builder()
                        .status(503)
                        .body(Body::from("original"))
                        .unwrap(),
                )
            }
        }),
    );
    let started = Instant::now();
    let response = retry
        .serve(Request::new(held_reader_source()))
        .await
        .unwrap();
    assert_eq!(started.elapsed(), expected);
    assert_eq!(consulted.load(Ordering::Relaxed), 1);
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        response.into_body().collect().await.unwrap().to_bytes(),
        "original"
    );
    holder.release();
    let (rest_trailers, rest) = forwarded.await.unwrap();
    assert_eq!(rest, "world");
    assert_eq!(rest_trailers, Some(trailers()));
}

#[tokio::test(start_paused = true)]
async fn retry_wait_for_a_held_reader_ends_at_the_handoff_timeout() {
    let store = MemoryReplay::new(64)
        .with_timeout(Duration::from_secs(10))
        .with_handoff_timeout(Duration::from_secs(2));
    assert_held_reader_wait_ends_after(store, Duration::from_secs(2)).await;
}

#[tokio::test(start_paused = true)]
async fn retry_wait_for_a_held_reader_ends_at_an_earlier_capture_deadline() {
    let store = MemoryReplay::new(64)
        .with_timeout(Duration::from_secs(1))
        .with_handoff_timeout(Duration::from_secs(5));
    assert_held_reader_wait_ends_after(store, Duration::from_secs(1)).await;
}

#[tokio::test(start_paused = true)]
async fn completed_capture_remains_replayable_after_a_slow_response() {
    let calls = AtomicUsize::new(0);
    let retry = Retry::new(
        ManagedPolicy::default()
            .with_replay_store(storage::MemoryReplay::new(5).with_timeout(Duration::from_secs(1))),
        service_fn(move |req: Request<RetryBody>| {
            let attempt = calls.fetch_add(1, Ordering::Relaxed);
            async move {
                assert_eq!(req.into_body().collect().await.unwrap().to_bytes(), "hello");
                let mut response = Response::new(Body::empty());
                if attempt == 0 {
                    tokio::time::sleep(Duration::from_secs(2)).await;
                    *response.status_mut() = StatusCode::SERVICE_UNAVAILABLE;
                } else {
                    assert_eq!(attempt, 1);
                }
                Ok::<_, BoxError>(response)
            }
        }),
    );
    assert_eq!(
        retry
            .serve(Request::new(Body::from_frame_stream(stream::iter([Ok::<
                _,
                Infallible,
            >(
                Frame::data(Bytes::from_static(b"hello"))
            )]))))
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
}

/// Hold the first append across a yield, like a filesystem write. This lets the
/// service return while it has polled for a frame but has not received it yet.
struct YieldingStore;

impl storage::ReplayStore for YieldingStore {
    fn max_bytes(&self) -> u64 {
        5
    }

    fn timeout(&self) -> Duration {
        Duration::from_secs(5)
    }

    fn handoff_timeout(&self) -> Duration {
        storage::DEFAULT_HANDOFF_TIMEOUT
    }

    fn reuse_buffered_bytes(&self) -> bool {
        false
    }

    fn start(&self, size_hint: &SizeHint) -> Box<dyn storage::ReplayWriter> {
        Box::new(YieldingWriter {
            inner: MemoryReplay::new(5).start(size_hint),
            yield_before_append: true,
        })
    }
}

struct YieldingWriter {
    inner: Box<dyn storage::ReplayWriter>,
    yield_before_append: bool,
}

impl storage::ReplayWriter for YieldingWriter {
    fn poll_append(&mut self, cx: &mut Context<'_>, data: &Bytes) -> Poll<Result<(), BoxError>> {
        if self.yield_before_append {
            self.yield_before_append = false;
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        let result = self.inner.poll_append(cx, data);
        self.yield_before_append = result.is_ready();
        result
    }

    fn finish(
        self: Box<Self>,
        trailers: Option<HeaderMap>,
    ) -> rama_core::futures::future::BoxFuture<
        'static,
        Result<Arc<dyn storage::ReplaySource>, BoxError>,
    > {
        self.inner.finish(trailers)
    }
}

#[tokio::test(start_paused = true)]
async fn in_flight_write_survives_returning_the_body_or_handing_it_to_a_retry() {
    // A retryable outcome that carries the live reader waits out the handoff timeout.
    for (first_status, return_reader, expected_attempts, expected_wait) in [
        (StatusCode::OK, true, 1, Duration::ZERO),
        (
            StatusCode::SERVICE_UNAVAILABLE,
            true,
            1,
            YieldingStore.handoff_timeout(),
        ),
        (StatusCode::SERVICE_UNAVAILABLE, false, 2, Duration::ZERO),
    ] {
        let started = Instant::now();
        let attempts = Arc::new(AtomicUsize::new(0));
        let calls = attempts.clone();
        let retry = Retry::new(
            ManagedPolicy::default().with_replay_store(YieldingStore),
            service_fn(move |req: Request<RetryBody>| {
                let attempt = calls.fetch_add(1, Ordering::Relaxed);
                async move {
                    let mut body = req.into_body();
                    let (status, body) = if attempt == 0 {
                        assert!(rama_core::futures::poll!(Box::pin(body.frame())).is_pending());
                        (
                            first_status,
                            if return_reader {
                                Body::from(body)
                            } else {
                                Body::empty()
                            },
                        )
                    } else {
                        assert_eq!(attempt, 1);
                        (StatusCode::OK, Body::from(body))
                    };
                    Ok::<_, BoxError>(Response::builder().status(status).body(body).unwrap())
                }
            }),
        );
        let response = retry
            .serve(Request::new(Body::from("hello")))
            .await
            .unwrap();
        assert_eq!(started.elapsed(), expected_wait);
        assert_eq!(
            response.status(),
            if expected_attempts == 1 {
                first_status
            } else {
                StatusCode::OK
            }
        );
        assert_eq!(attempts.load(Ordering::Relaxed), expected_attempts);
        assert_eq!(
            response.into_body().collect().await.unwrap().to_bytes(),
            "hello"
        );
    }
}

#[tokio::test]
async fn a_source_error_while_draining_preserves_the_first_outcome() {
    let source = Body::from_frame_stream(stream::iter([
        Ok(Frame::data(Bytes::from_static(b"prefix"))),
        Err(BoxError::from_static_str("upload interrupted")),
    ]));
    let calls = AtomicUsize::new(0);
    let retry = Retry::new(
        ManagedPolicy::default(),
        service_fn(move |req: Request<RetryBody>| {
            assert_eq!(calls.fetch_add(1, Ordering::Relaxed), 0);
            async move {
                assert_eq!(
                    req.into_body()
                        .frame()
                        .await
                        .unwrap()
                        .unwrap()
                        .into_data()
                        .unwrap(),
                    "prefix"
                );
                Ok::<_, BoxError>(
                    Response::builder()
                        .status(503)
                        .body(Body::from("upstream outcome"))
                        .unwrap(),
                )
            }
        }),
    );
    let result = retry.serve(Request::new(source)).await.unwrap();
    assert_eq!(result.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        result.into_body().collect().await.unwrap().to_bytes(),
        "upstream outcome"
    );
}

#[tokio::test]
async fn policy_polling_a_failed_capture_cannot_retry_with_an_empty_body() {
    let source = Body::from_frame_stream(stream::iter([Ok::<_, Infallible>(Frame::data(
        Bytes::from_static(b"larger than the limit"),
    ))]));
    let policy = ManagedPolicy::new(
        async |mut req: Request<RetryBody>, result: Result<Response, BoxError>| {
            // A user policy can inspect its candidate body. The failed read
            // must leave the candidate permanently unavailable for replay.
            let error = req.body_mut().frame().await.unwrap().unwrap_err();
            assert_eq!(error.to_string(), "request body unavailable for replay");
            (req, result, true)
        },
    )
    .with_replay_store(storage::MemoryReplay::new(1));
    let attempts = AtomicUsize::new(0);
    let retry = Retry::new(
        policy,
        service_fn(move |_: Request<RetryBody>| {
            assert_eq!(attempts.fetch_add(1, Ordering::Relaxed), 0);
            async {
                Ok::<_, BoxError>(Response::builder().status(503).body(Body::empty()).unwrap())
            }
        }),
    );
    assert_eq!(
        retry.serve(Request::new(source)).await.unwrap().status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
}

#[tokio::test]
async fn frames_after_trailers_are_forwarded_in_order_without_replay() {
    let source = Body::from_frame_stream(stream::iter([
        Ok::<_, Infallible>(Frame::data(Bytes::from_static(b"first"))),
        Ok(Frame::trailers(trailers())),
        Ok(Frame::data(Bytes::from_static(b"last"))),
    ]));
    let calls = AtomicUsize::new(0);
    let retry = Retry::new(
        ManagedPolicy::default(),
        service_fn(move |req: Request<RetryBody>| {
            assert_eq!(calls.fetch_add(1, Ordering::Relaxed), 0);
            async move {
                let mut body = req.into_body();
                assert_eq!(
                    body.frame().await.unwrap().unwrap().into_data().unwrap(),
                    "first"
                );
                assert_eq!(
                    body.frame()
                        .await
                        .unwrap()
                        .unwrap()
                        .into_trailers()
                        .unwrap(),
                    trailers()
                );
                assert_eq!(
                    body.frame().await.unwrap().unwrap().into_data().unwrap(),
                    "last"
                );
                assert!(body.frame().await.is_none());
                Ok::<_, BoxError>(Response::builder().status(503).body(Body::empty()).unwrap())
            }
        }),
    );
    assert_eq!(
        retry.serve(Request::new(source)).await.unwrap().status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
}

#[tokio::test(start_paused = true)]
async fn last_data_frame_can_finish_capture_without_an_extra_eof_poll() {
    // Full signals is_end_stream as soon as it emits its final data frame.
    // A transport can consult that signal and stop without polling for None.
    let source = Full::new(std::io::Cursor::new(b"hello".to_vec()));
    let attempts = AtomicUsize::new(0);
    let retry = Retry::new(
        ManagedPolicy::default()
            .with_replay_store(storage::MemoryReplay::new(5).with_timeout(Duration::from_secs(1))),
        service_fn(move |req: Request<RetryBody>| {
            let attempt = attempts.fetch_add(1, Ordering::Relaxed);
            async move {
                let mut body = req.into_body();
                assert_eq!(
                    body.frame().await.unwrap().unwrap().into_data().unwrap(),
                    "hello"
                );
                assert!(body.is_end_stream());
                if attempt == 0 {
                    tokio::time::sleep(Duration::from_secs(2)).await;
                }
                assert!(attempt < 2);
                Ok::<_, BoxError>(
                    Response::builder()
                        .status(if attempt == 0 { 503 } else { 200 })
                        .body(Body::from(body))
                        .unwrap(),
                )
            }
        }),
    );
    assert_eq!(
        retry.serve(Request::new(source)).await.unwrap().status(),
        StatusCode::OK
    );
}

#[tokio::test]
async fn cloning_hook_cannot_steal_the_live_source_before_the_first_attempt() {
    let first_clone = AtomicUsize::new(0);
    let policy = ManagedPolicy::default().with_clone(move |req: &Request<RetryBody>| {
        assert!(
            req.body().is_replayable(),
            "clone hooks can select replay candidates"
        );
        if first_clone.fetch_add(1, Ordering::Relaxed) == 0 {
            let mut reader = req.body().try_clone().unwrap();
            assert!(reader.frame().now_or_never().is_none());
        }
        Some(Request::from_parts(
            req.clone_parts(),
            req.body().try_clone()?,
        ))
    });
    let attempts = AtomicUsize::new(0);
    let retry = Retry::new(
        policy,
        service_fn(move |req: Request<RetryBody>| {
            let attempt = attempts.fetch_add(1, Ordering::Relaxed);
            async move {
                assert!(attempt < 2);
                assert_eq!(req.into_body().collect().await.unwrap().to_bytes(), "hello");
                Ok::<_, BoxError>(
                    Response::builder()
                        .status(if attempt == 0 { 503 } else { 200 })
                        .body(Body::empty())
                        .unwrap(),
                )
            }
        }),
    );
    let source = Body::from_frame_stream(stream::iter([Ok::<_, Infallible>(Frame::data(
        Bytes::from_static(b"hello"),
    ))]));
    assert_eq!(
        retry.serve(Request::new(source)).await.unwrap().status(),
        StatusCode::OK
    );
}

#[tokio::test]
async fn send_only_source_reports_end_after_its_trailer_frame() {
    for (capture, expected_status) in [
        (false, StatusCode::SERVICE_UNAVAILABLE),
        (true, StatusCode::OK),
    ] {
        for payload in ["", "hello"] {
            let sent_trailers = Cell::new(false);
            let source = Body::from(payload)
                .with_trailer_headers(trailers())
                .collect()
                .await
                .unwrap()
                .inspect_frame(move |frame| assert!(!sent_trailers.replace(frame.is_trailers())));
            let req = Request::new(source);
            if !capture {
                req.extensions().insert(managed::DoNotRetry);
            }
            let attempts = AtomicUsize::new(0);
            let retry = Retry::new(
                ManagedPolicy::default(),
                service_fn(move |req: Request<RetryBody>| {
                    let attempt = attempts.fetch_add(1, Ordering::Relaxed);
                    async move {
                        assert!(attempt < 2);
                        let mut body = req.into_body();
                        if !payload.is_empty() {
                            assert_eq!(
                                body.frame().await.unwrap().unwrap().into_data().unwrap(),
                                payload
                            );
                        }
                        assert_eq!(body.size_hint().exact(), Some(0));
                        assert!(!body.is_end_stream());
                        assert_eq!(
                            body.frame()
                                .await
                                .unwrap()
                                .unwrap()
                                .into_trailers()
                                .unwrap(),
                            trailers()
                        );
                        assert!(body.is_end_stream());
                        // Return the live reader after the terminal trailer without polling EOF.
                        Ok::<_, BoxError>(
                            Response::builder()
                                .status(if attempt == 0 { 503 } else { 200 })
                                .body(body)
                                .unwrap(),
                        )
                    }
                }),
            );
            assert_eq!(retry.serve(req).await.unwrap().status(), expected_status);
        }
    }
}
