#![expect(
    clippy::allow_attributes,
    reason = "macro-generated `#[allow]` attributes whose underlying lints fire only for some expansions"
)]

use crate::headers::Vary;
use crate::layer::cors::CorsLayer;
use crate::{Body, HeaderValue, Request, Response, header};
use rama_core::service::service_fn;
use rama_core::{Layer, Service};
use rama_utils::collections::non_empty_vec;
use std::convert::Infallible;

#[tokio::test]
#[allow(
    clippy::declare_interior_mutable_const,
    clippy::borrow_interior_mutable_const
)]
async fn vary_set_by_inner_service() {
    const CUSTOM_VARY_HEADERS: HeaderValue = HeaderValue::from_static("accept, accept-encoding");
    const PERMISSIVE_CORS_VARY_HEADERS: HeaderValue = HeaderValue::from_static(
        "origin, access-control-request-method, access-control-request-headers",
    );

    async fn inner_svc(_: Request) -> Result<Response, Infallible> {
        Ok(Response::builder()
            .header(header::VARY, CUSTOM_VARY_HEADERS)
            .body(Body::empty())
            .unwrap())
    }

    let svc = CorsLayer::permissive().into_layer(service_fn(inner_svc));
    let res = svc.serve(Request::new(Body::empty())).await.unwrap();
    let mut vary_headers = res.headers().get_all(header::VARY).into_iter();
    assert_eq!(vary_headers.next(), Some(&CUSTOM_VARY_HEADERS));
    assert_eq!(vary_headers.next(), Some(&PERMISSIVE_CORS_VARY_HEADERS));
    assert_eq!(vary_headers.next(), None);
}

/// When the layer's user-supplied `Vary` omits `Origin` but the configured
/// `Access-Control-Allow-Origin` is derived from the request's `Origin`
/// (here: `very_permissive` → `MirrorRequest`), the CORS layer must
/// inject an additional `Vary: origin` so shared caches don't serve one
/// origin's response to another.
#[tokio::test]
async fn vary_origin_injected_when_origin_is_request_dependent() {
    async fn inner_svc(_: Request) -> Result<Response, Infallible> {
        Ok(Response::new(Body::empty()))
    }

    let svc = CorsLayer::very_permissive()
        .with_vary(Vary::headers(non_empty_vec![header::ACCEPT_ENCODING]))
        .into_layer(service_fn(inner_svc));
    let res = svc
        .serve(
            Request::builder()
                .header(header::ORIGIN, "https://example.test")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let vary_values: Vec<_> = res
        .headers()
        .get_all(header::VARY)
        .into_iter()
        .cloned()
        .collect();
    assert!(
        vary_values
            .iter()
            .any(|v| v.as_bytes().eq_ignore_ascii_case(b"origin")),
        "expected `Vary: origin` to be present alongside the user-set Vary; got {vary_values:?}",
    );
}

/// When the layer's `Vary` already names `Origin`, no extra `Vary: origin`
/// header value is appended (no redundant duplication).
#[tokio::test]
async fn vary_origin_not_duplicated_when_already_present() {
    async fn inner_svc(_: Request) -> Result<Response, Infallible> {
        Ok(Response::new(Body::empty()))
    }

    let svc = CorsLayer::very_permissive().into_layer(service_fn(inner_svc));
    let res = svc
        .serve(
            Request::builder()
                .header(header::ORIGIN, "https://example.test")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let origin_count = res
        .headers()
        .get_all(header::VARY)
        .into_iter()
        .filter(|v| {
            v.to_str()
                .map(|s| {
                    s.split(',')
                        .any(|tok| tok.trim().eq_ignore_ascii_case("origin"))
                })
                .unwrap_or(false)
        })
        .count();
    assert_eq!(
        origin_count, 1,
        "expected exactly one Vary entry that names Origin"
    );
}

/// The inner handler's `Access-Control-Allow-Origin` must override the
/// layer's default. Without preservation the CORS layer would clobber
/// per-route overrides.
#[tokio::test]
async fn inner_handler_overrides_access_control_allow_origin() {
    const OVERRIDDEN: HeaderValue = HeaderValue::from_static("https://override.test");

    async fn inner_svc(_: Request) -> Result<Response, Infallible> {
        Ok(Response::builder()
            .header(header::ACCESS_CONTROL_ALLOW_ORIGIN, OVERRIDDEN)
            .body(Body::empty())
            .unwrap())
    }

    let svc = CorsLayer::permissive().into_layer(service_fn(inner_svc));
    let res = svc
        .serve(
            Request::builder()
                .header(header::ORIGIN, "https://client.test")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        res.headers().get(header::ACCESS_CONTROL_ALLOW_ORIGIN),
        Some(&OVERRIDDEN),
    );
}

/// Reverse case: when the inner handler does NOT set `Access-Control-*`,
/// the layer's default must still apply.
#[tokio::test]
async fn layer_default_access_control_allow_origin_when_inner_silent() {
    async fn inner_svc(_: Request) -> Result<Response, Infallible> {
        Ok(Response::new(Body::empty()))
    }

    let svc = CorsLayer::permissive().into_layer(service_fn(inner_svc));
    let res = svc.serve(Request::new(Body::empty())).await.unwrap();
    assert_eq!(
        res.headers().get(header::ACCESS_CONTROL_ALLOW_ORIGIN),
        Some(&HeaderValue::from_static("*")),
    );
}
