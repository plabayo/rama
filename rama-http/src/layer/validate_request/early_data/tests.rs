use super::*;
use rama_core::{Layer as _, Service as _, error::BoxError, service::service_fn};
use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{sync::watch, time::timeout};

fn receipt(receiver: watch::Receiver<bool>) -> EarlyDataReceived {
    EarlyDataReceived::new(move || {
        let mut receiver = receiver.clone();
        async move {
            receiver
                .wait_for(|ready| *ready)
                .await
                .map(|_| ())
                .map_err(Into::into)
        }
    })
}

#[tokio::test]
async fn incapable_origin_waits_and_forwards_unmarked_once() {
    let (confirmed, receiver) = watch::channel(false);
    let calls = Arc::new(AtomicUsize::new(0));
    let observed = calls.clone();
    let service =
        forward_to(|_: &Request| false).into_layer(service_fn(move |request: Request| {
            observed.fetch_add(1, Ordering::Relaxed);
            assert!(!request.headers().contains_key(header::EARLY_DATA));
            assert!(request.extensions().contains::<ForbidEarlyData>());
            async { Ok::<_, BoxError>(Response::new(Body::empty())) }
        }));
    let request = Request::new(Body::empty());
    request.extensions().insert(receipt(receiver));
    let mut pending = Box::pin(service.serve(request));
    timeout(Duration::from_millis(20), &mut pending)
        .await
        .unwrap_err();
    assert_eq!(calls.load(Ordering::Relaxed), 0);
    confirmed.send(true).unwrap();
    assert_eq!(pending.await.unwrap().status(), StatusCode::OK);
    assert_eq!(calls.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn inherited_exposure_is_rejected_without_waiting_or_calling_incapable_origin() {
    let (_confirmed, receiver) = watch::channel(false);
    let service = forward_to(|_: &Request| false).into_layer(service_fn(|_: Request| async {
        Err::<Response, BoxError>("incapable origin was called".into())
    }));
    for value in ["1", "", "garbage"] {
        let request = Request::builder()
            .header(header::EARLY_DATA, value)
            .body(Body::empty())
            .unwrap();
        request.extensions().insert(receipt(receiver.clone()));
        assert_eq!(
            timeout(Duration::from_millis(100), service.serve(request))
                .await
                .unwrap()
                .unwrap()
                .status(),
            StatusCode::TOO_EARLY
        );
    }
}

#[tokio::test]
async fn capable_origin_receives_exposure_before_confirmation_and_425_passes_back() {
    let (_confirmed, receiver) = watch::channel(false);
    let service =
        forward_to(|_: &Request| true).into_layer(service_fn(|request: Request| async move {
            assert!(request.headers().contains_key(header::EARLY_DATA));
            assert!(!request.extensions().contains::<ForbidEarlyData>());
            let mut response = too_early();
            response
                .headers_mut()
                .insert("origin", "kept".parse().unwrap());
            Ok::<_, BoxError>(response)
        }));
    for inherited in [false, true] {
        let mut request = Request::new(Body::empty());
        request.extensions().insert(receipt(receiver.clone()));
        if inherited {
            request
                .headers_mut()
                .insert(header::EARLY_DATA, "inherited".parse().unwrap());
        }
        let response = timeout(Duration::from_millis(100), service.serve(request))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(response.status(), StatusCode::TOO_EARLY);
        assert_eq!(response.headers()["origin"], "kept");
    }
}

#[tokio::test]
async fn cancelled_or_failed_confirmation_never_calls_the_origin() {
    let (confirmed, receiver) = watch::channel(false);
    let service = forward_to(|_: &Request| false).into_layer(service_fn(|_: Request| async {
        Err::<Response, BoxError>("origin must not be called".into())
    }));
    let request = Request::new(Body::empty());
    request.extensions().insert(receipt(receiver.clone()));
    timeout(Duration::from_millis(20), service.serve(request))
        .await
        .unwrap_err();
    drop(confirmed);
    let request = Request::new(Body::empty());
    request.extensions().insert(receipt(receiver));
    assert_eq!(
        service.serve(request).await.unwrap().status(),
        StatusCode::TOO_EARLY
    );
}

#[tokio::test]
async fn ordinary_ingress_stays_unmarked_and_origin_validation_is_composable() {
    for capable in [false, true] {
        let service = forward_to(move |_: &Request| capable).into_layer(
            ValidateRequestHeaderLayer::custom_fn(require_confirmed).into_layer(service_fn(
                |request: Request| async move {
                    assert!(!is_exposed(&request));
                    Ok::<_, BoxError>(Response::new(Body::empty()))
                },
            )),
        );
        assert_eq!(
            service
                .serve(Request::new(Body::empty()))
                .await
                .unwrap()
                .status(),
            StatusCode::OK
        );
    }
    let request = Request::new(Body::empty());
    request
        .extensions()
        .insert(EarlyDataReceived::new(|| async { Ok(()) }));
    require_confirmed(request).await.unwrap();
}

#[derive(Clone, Copy, Debug)]
enum Confirmation {
    Inherited,
    Pending,
    Confirmed,
    Failed,
}

#[tokio::test]
async fn route_confirmation_waits_only_for_current_hop_and_never_calls_on_rejection() {
    for state in [
        Confirmation::Inherited,
        Confirmation::Pending,
        Confirmation::Confirmed,
        Confirmation::Failed,
    ] {
        let (confirmed, receiver) = watch::channel(matches!(state, Confirmation::Confirmed));
        let mut confirmed = Some(confirmed);
        if matches!(state, Confirmation::Failed) {
            drop(confirmed.take());
        }
        let calls = Arc::new(AtomicUsize::new(0));
        let observed = calls.clone();
        let service = ValidateRequestHeaderLayer::custom_fn(require_confirmed).into_layer(
            service_fn(move |_: Request| {
                observed.fetch_add(1, Ordering::Relaxed);
                async { Ok::<_, BoxError>(Response::new(Body::empty())) }
            }),
        );
        let mut request = Request::new(Body::empty());
        request.extensions().insert(receipt(receiver));
        if matches!(state, Confirmation::Inherited) {
            request
                .headers_mut()
                .insert(header::EARLY_DATA, "1".parse().unwrap());
        }
        let mut pending = Box::pin(service.serve(request));
        if matches!(state, Confirmation::Pending) {
            timeout(Duration::from_millis(20), &mut pending)
                .await
                .unwrap_err();
            assert_eq!(calls.load(Ordering::Relaxed), 0);
            confirmed.as_ref().unwrap().send(true).unwrap();
        }
        let response = timeout(Duration::from_millis(100), pending)
            .await
            .unwrap()
            .unwrap();
        let allowed = matches!(state, Confirmation::Pending | Confirmation::Confirmed);
        assert_eq!(
            response.status(),
            if allowed {
                StatusCode::OK
            } else {
                StatusCode::TOO_EARLY
            },
            "{state:?}"
        );
        assert_eq!(
            calls.load(Ordering::Relaxed),
            usize::from(allowed),
            "{state:?}"
        );
    }
}

#[tokio::test]
async fn capable_forwarding_does_not_create_exposure_after_confirmation() {
    let service =
        forward_to(|_: &Request| true).into_layer(service_fn(|request: Request| async move {
            assert!(!request.headers().contains_key(header::EARLY_DATA));
            assert!(request.extensions().contains::<ForbidEarlyData>());
            Ok::<_, BoxError>(Response::new(Body::empty()))
        }));
    let request = Request::new(Body::empty());
    request
        .extensions()
        .insert(EarlyDataReceived::new(|| async { Ok(()) }));
    assert_eq!(
        service.serve(request).await.unwrap().status(),
        StatusCode::OK
    );
    let request = Request::new(Body::empty());
    request
        .extensions()
        .insert(EarlyDataReceived::new(|| async {
            Err("handshake failed".into())
        }));
    assert_eq!(
        service.serve(request).await.unwrap().status(),
        StatusCode::TOO_EARLY
    );
}
