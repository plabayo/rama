use std::{
    convert::Infallible,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
};

use rama_core::{Layer as _, Service as _, matcher::match_fn, service::service_fn};

use super::*;
use crate::{HeaderValue, Version, layer::validate_request::ValidateRequestHeaderLayer};

#[tokio::test]
async fn every_http_version_rechecks_authority_and_policy_before_upstream() {
    for version in [Version::HTTP_11, Version::HTTP_2, Version::HTTP_3] {
        let allowed = Arc::new(AtomicBool::new(true));
        let count = Arc::new(AtomicUsize::new(0));
        let policy_allowed = allowed.clone();
        let policy = match_fn(move |_: &Request| policy_allowed.load(Ordering::SeqCst));
        let upstream_count = count.clone();
        let upstream = service_fn(move |_: Request| {
            upstream_count.fetch_add(1, Ordering::SeqCst);
            async { Ok::<_, Infallible>(Response::new(Body::empty())) }
        });
        let service = ValidateRequestHeaderLayer::custom(BoundAuthority::https(
            "example.com:443".parse().unwrap(),
            policy,
        ))
        .into_layer(upstream);
        for (uri, host, status) in [
            ("https://example.com/", "example.com", StatusCode::OK),
            (
                "https://elsewhere.example/",
                "example.com",
                StatusCode::MISDIRECTED_REQUEST,
            ),
            (
                "https://example.com/",
                "elsewhere.example",
                StatusCode::MISDIRECTED_REQUEST,
            ),
            (
                "https://example.com:444/",
                "example.com",
                StatusCode::MISDIRECTED_REQUEST,
            ),
            (
                "https://example.com/",
                "example.com:444",
                StatusCode::MISDIRECTED_REQUEST,
            ),
            (
                "http://example.com/",
                "example.com",
                StatusCode::MISDIRECTED_REQUEST,
            ),
            (
                "https://example.com/",
                "name@example.com",
                StatusCode::MISDIRECTED_REQUEST,
            ),
            (
                "https://example.com/",
                "example.com/path",
                StatusCode::MISDIRECTED_REQUEST,
            ),
            (
                "https://EXAMPLE.com:443/",
                "EXAMPLE.com:443",
                StatusCode::OK,
            ),
        ] {
            let req = Request::builder()
                .version(version)
                .uri(uri)
                .header(HOST, host)
                .body(Body::empty())
                .unwrap();
            let response = service.serve(req).await.unwrap();
            assert_eq!(response.status(), status, "{version:?} {uri} {host}");
            if status == StatusCode::MISDIRECTED_REQUEST {
                assert_eq!(response.version(), version);
            }
        }
        assert_eq!(count.load(Ordering::SeqCst), 2);

        // The same connection can outlive its policy decision.
        allowed.store(false, Ordering::SeqCst);
        let req = Request::builder()
            .version(version)
            .uri("https://example.com/")
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            service.serve(req).await.unwrap().status(),
            StatusCode::MISDIRECTED_REQUEST
        );
        assert_eq!(count.load(Ordering::SeqCst), 2);
    }
}

#[tokio::test]
async fn bound_authority_handles_origin_form_ipv6_and_duplicate_host() {
    let validator = BoundAuthority::https("[::1]:8443".parse().unwrap(), true);
    let req = Request::builder()
        .uri("/")
        .header(HOST, "[::1]:8443")
        .body(())
        .unwrap();
    validator.validate(req).await.unwrap();
    let req = Request::builder()
        .uri("/")
        .header(HOST, "[::1]")
        .body(())
        .unwrap();
    assert_eq!(
        validator.validate(req).await.unwrap_err().status(),
        StatusCode::MISDIRECTED_REQUEST
    );
    let req = Request::builder().uri("/").body(()).unwrap();
    assert_eq!(
        validator.validate(req).await.unwrap_err().status(),
        StatusCode::MISDIRECTED_REQUEST
    );
    let mut req = Request::builder()
        .uri("https://[::1]:8443/")
        .header(HOST, "[::1]:8443")
        .body(())
        .unwrap();
    req.headers_mut()
        .append(HOST, HeaderValue::from_static("[::1]:8443"));
    assert_eq!(
        validator.validate(req).await.unwrap_err().status(),
        StatusCode::MISDIRECTED_REQUEST
    );
    let validator = BoundAuthority::http("example.com:80".parse().unwrap(), true);
    let req = Request::builder()
        .uri("/")
        .header(HOST, "example.com")
        .body(())
        .unwrap();
    validator.validate(req).await.unwrap();
}
