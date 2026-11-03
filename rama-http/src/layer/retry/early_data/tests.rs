use super::*;
use crate::{
    Body, BodyExtractExt, Method,
    layer::retry::{ManagedPolicy, Retry},
};
use rama_core::{
    Service,
    error::{BoxError, ErrorExt, extra::OpaqueError},
    layer::MapInput,
    service::service_fn,
};
use std::sync::atomic::{AtomicUsize, Ordering};

fn classify(error: &BoxError) -> bool {
    is_early_data_rejected(error.as_ref())
}

fn response(request: &Request<RetryBody>, status: StatusCode) -> Response {
    let response = Response::builder()
        .status(status)
        .body(Body::empty())
        .unwrap();
    if request.extensions().contains::<EarlyDataPermit>()
        && !request.extensions().contains::<ForbidEarlyData>()
    {
        response
            .extensions()
            .insert(EarlyDataAttempt::sent_early(request));
    }
    response
}

#[tokio::test]
async fn repeated_425_is_terminal_even_with_retry_every_4xx_rule() {
    let calls = Arc::new(AtomicUsize::new(0));
    let early = Arc::new(AtomicUsize::new(0));
    let application = Arc::new(AtomicUsize::new(0));
    let policy_calls = application.clone();
    let rule = with_recovery(
        move |req, result: Result<Response, BoxError>| {
            policy_calls.fetch_add(1, Ordering::Relaxed);
            async move { (req, result, true) }
        },
        classify,
    );
    let service_calls = calls.clone();
    let early_calls = early.clone();
    let retry = Retry::new(
        ManagedPolicy::new(rule).with_prepare_body(prepare_bodyless),
        MapInput::new(
            service_fn(move |req: Request<RetryBody>| {
                service_calls.fetch_add(1, Ordering::Relaxed);
                early_calls.fetch_add(
                    usize::from(req.extensions().contains::<EarlyDataPermit>()),
                    Ordering::Relaxed,
                );
                async move { Ok::<_, BoxError>(response(&req, StatusCode::TOO_EARLY)) }
            }),
            permit_attempt,
        ),
    );
    let request = Request::new(Body::empty());
    let caller = request.extensions().clone();
    assert_eq!(
        retry.serve(request).await.unwrap().status(),
        StatusCode::TOO_EARLY
    );
    assert_eq!(calls.load(Ordering::Relaxed), 2);
    assert_eq!(early.load(Ordering::Relaxed), 1);
    assert_eq!(application.load(Ordering::Relaxed), 0);
    assert!(caller.contains::<ForbidEarlyData>());
    assert!(!caller.contains::<EarlyDataPermit>());
}

#[tokio::test]
async fn absent_evidence_and_forwarded_425_never_reach_application_rule() {
    // Header before the policy clone, added inside the attempt, or no transport fact.
    for scenario in 0..3 {
        let calls = Arc::new(AtomicUsize::new(0));
        let service_calls = calls.clone();
        let rule = with_recovery(
            async |_, _: Result<Response, BoxError>| panic!("an ineligible 425 must be terminal"),
            classify,
        );
        let retry = Retry::new(
            ManagedPolicy::new(rule).with_prepare_body(prepare_bodyless),
            MapInput::new(
                service_fn(move |mut req: Request<RetryBody>| {
                    service_calls.fetch_add(1, Ordering::Relaxed);
                    async move {
                        if scenario == 1 {
                            req.headers_mut()
                                .insert(header::EARLY_DATA, "anything".parse().unwrap());
                        }
                        if scenario == 2 {
                            Ok::<_, BoxError>(
                                Response::builder().status(425).body(Body::empty()).unwrap(),
                            )
                        } else {
                            Ok(response(&req, StatusCode::TOO_EARLY))
                        }
                    }
                }),
                permit_attempt,
            ),
        );
        let mut request = Request::new(Body::empty());
        if scenario == 0 {
            request
                .headers_mut()
                .insert(header::EARLY_DATA, "1".parse().unwrap());
        }
        let caller = request.extensions().clone();
        assert_eq!(
            retry.serve(request).await.unwrap().status(),
            StatusCode::TOO_EARLY
        );
        assert_eq!(calls.load(Ordering::Relaxed), 1);
        assert!(!caller.contains::<ForbidEarlyData>());
    }
}

#[tokio::test]
async fn tls_rejection_recovers_forwarded_request_and_survives_error_wrappers() {
    let calls = Arc::new(AtomicUsize::new(0));
    let service_calls = calls.clone();
    let rule = with_recovery(
        async |request, result: Result<Response, OpaqueError>| {
            assert!(
                result.is_ok(),
                "recognized rejection must not reach the application rule"
            );
            (request, result, false)
        },
        |error: &OpaqueError| is_early_data_rejected(error),
    );
    let retry = Retry::new(
        ManagedPolicy::new(rule).with_prepare_body(prepare_bodyless),
        MapInput::new(
            service_fn(move |req: Request<RetryBody>| {
                let attempt = service_calls.fetch_add(1, Ordering::Relaxed);
                async move {
                    if attempt == 0 {
                        assert!(req.extensions().contains::<EarlyDataPermit>());
                        Err(
                            EarlyDataRejected::new(std::io::Error::other("TLS early rejection"))
                                .context("HTTP send")
                                .into_opaque_error(),
                        )
                    } else {
                        assert!(req.extensions().contains::<ForbidEarlyData>());
                        assert!(!req.extensions().contains::<EarlyDataPermit>());
                        Ok(response(&req, StatusCode::OK))
                    }
                }
            }),
            permit_attempt,
        ),
    );
    let mut request = Request::new(Body::empty());
    request
        .headers_mut()
        .insert(header::EARLY_DATA, "1".parse().unwrap());
    assert_eq!(retry.serve(request).await.unwrap().status(), StatusCode::OK);
    assert_eq!(calls.load(Ordering::Relaxed), 2);
}

#[tokio::test]
async fn confirmed_recovery_errors_still_use_application_budget_without_early_data() {
    let calls = Arc::new(AtomicUsize::new(0));
    let early = Arc::new(AtomicUsize::new(0));
    let service_calls = calls.clone();
    let early_calls = early.clone();
    let application = Arc::new(AtomicUsize::new(0));
    let application_calls = application.clone();
    let rule = with_recovery(
        move |req, result: Result<Response, BoxError>| {
            application_calls.fetch_add(1, Ordering::Relaxed);
            async move {
                let retry = result.is_err();
                (req, result, retry)
            }
        },
        classify,
    );
    let retry = Retry::new(
        ManagedPolicy::new(rule).with_prepare_body(prepare_bodyless),
        MapInput::new(
            service_fn(move |req: Request<RetryBody>| {
                let attempt = service_calls.fetch_add(1, Ordering::Relaxed);
                early_calls.fetch_add(
                    usize::from(req.extensions().contains::<EarlyDataPermit>()),
                    Ordering::Relaxed,
                );
                async move {
                    match attempt {
                        0 => Ok(response(&req, StatusCode::TOO_EARLY)),
                        1 => {
                            Err(std::io::Error::other("confirmed connection lost").into_box_error())
                        }
                        2 => Ok(response(&req, StatusCode::OK)),
                        _ => panic!("unexpected extra retry"),
                    }
                }
            }),
            permit_attempt,
        ),
    );
    assert_eq!(
        retry
            .serve(Request::new(Body::empty()))
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
    assert_eq!(calls.load(Ordering::Relaxed), 3);
    assert_eq!(early.load(Ordering::Relaxed), 1);
    assert_eq!(application.load(Ordering::Relaxed), 2);
}

#[tokio::test]
async fn declined_unsafe_and_do_not_retry_requests_stream_once_without_permit() {
    for (method, body, do_not_retry) in [
        (Method::POST, Body::empty(), false),
        (Method::GET, Body::from("payload"), false),
        (Method::GET, Body::empty(), true),
    ] {
        let rule = with_recovery(
            async |_, _: Result<Response, BoxError>| {
                panic!("one-shot requests must not reach policy")
            },
            classify,
        );
        let retry = Retry::new(
            ManagedPolicy::new(rule).with_prepare_body(prepare_bodyless),
            MapInput::new(
                service_fn(async |req: Request<RetryBody>| {
                    assert!(!req.extensions().contains::<EarlyDataPermit>());
                    assert!(!req.body().is_replayable());
                    req.try_into_string().await.unwrap();
                    Ok::<_, BoxError>(Response::builder().status(425).body(Body::empty()).unwrap())
                }),
                permit_attempt,
            ),
        );
        let request = Request::builder().method(method).body(body).unwrap();
        if do_not_retry {
            request.extensions().insert(DoNotRetry::default());
        }
        assert_eq!(
            retry.serve(request).await.unwrap().status(),
            StatusCode::TOO_EARLY
        );
    }
}

#[test]
fn typed_rejection_is_distinct_from_an_ordinary_connection_error() {
    assert!(!is_early_data_rejected(&std::io::Error::other(
        "connection rejected early data"
    )));
    let error = EarlyDataRejected::new(std::io::Error::other("rejected")).context("send");
    assert!(is_early_data_rejected(error.as_ref()));
}

#[test]
fn permits_stay_with_eligible_origins_or_already_exposed_forwarded_requests() {
    let request = Request::new(RetryBody::empty());
    assert!(
        permit_attempt(request)
            .extensions()
            .contains::<EarlyDataPermit>()
    );

    let mut request = Request::new(RetryBody::empty());
    request.extensions().insert(Ingress(Extensions::new()));
    request = permit_attempt(request);
    assert!(!request.extensions().contains::<EarlyDataPermit>());
    request
        .headers_mut()
        .insert(header::EARLY_DATA, "1".parse().unwrap());
    assert!(
        permit_attempt(request)
            .extensions()
            .contains::<EarlyDataPermit>()
    );

    let request = Request::new(RetryBody::empty());
    request.extensions().insert(ForbidEarlyData::default());
    assert!(
        !permit_attempt(request)
            .extensions()
            .contains::<EarlyDataPermit>()
    );
}

#[tokio::test]
async fn repeated_typed_rejection_is_terminal_and_the_returned_error_keeps_its_cause() {
    let calls = Arc::new(AtomicUsize::new(0));
    let service_calls = calls.clone();
    let rule = with_recovery(
        async |_, _: Result<Response, BoxError>| {
            panic!("typed rejection must never fall through to generic error retry")
        },
        classify,
    );
    let retry = Retry::new(
        ManagedPolicy::new(rule).with_prepare_body(prepare_bodyless),
        MapInput::new(
            service_fn(move |req: Request<RetryBody>| {
                let attempt = service_calls.fetch_add(1, Ordering::Relaxed);
                async move {
                    assert_eq!(req.extensions().contains::<ForbidEarlyData>(), attempt == 1);
                    Err::<Response, BoxError>(
                        EarlyDataRejected::new(std::io::Error::other("rejected")).into(),
                    )
                }
            }),
            permit_attempt,
        ),
    );
    let error = retry.serve(Request::new(Body::empty())).await.unwrap_err();
    assert!(is_early_data_rejected(&error));
    assert_eq!(calls.load(Ordering::Relaxed), 2);
}
