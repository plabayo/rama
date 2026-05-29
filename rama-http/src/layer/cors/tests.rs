#![expect(
    clippy::allow_attributes,
    reason = "macro-generated `#[allow]` attributes whose underlying lints fire only for some expansions"
)]

use crate::headers::Vary;
use crate::layer::cors::CorsLayer;
use crate::{Body, HeaderValue, Method, Request, Response, header};
use rama_core::service::service_fn;
use rama_core::{Layer, Service};
use rama_http_headers::{AccessControlAllowHeaders, AccessControlAllowMethods};
use rama_utils::collections::non_empty_vec;
use std::convert::Infallible;

/// `permissive` configures every allow_* as a fixed `Any`/`Const` value,
/// so no `Vary` header should be added (no field of the response varies
/// with the request).
#[tokio::test]
async fn permissive_emits_no_vary_header() {
    let svc = CorsLayer::permissive().into_layer(service_fn(|_: Request| async {
        Ok::<_, Infallible>(Response::new(Body::empty()))
    }));

    let res = svc.serve(Request::new(Body::empty())).await.unwrap();
    assert!(
        res.headers().get(header::VARY).is_none(),
        "expected no Vary header for `permissive`; got {:?}",
        res.headers().get(header::VARY),
    );
}

/// `very_permissive` mirrors every request value, so the derived `Vary`
/// must advertise `Origin`, `Access-Control-Request-Method`, and
/// `Access-Control-Request-Headers`.
#[tokio::test]
async fn very_permissive_derives_full_vary_header() {
    let svc = CorsLayer::very_permissive().into_layer(service_fn(|_: Request| async {
        Ok::<_, Infallible>(Response::new(Body::empty()))
    }));

    let req = Request::builder()
        .method(Method::OPTIONS)
        .header(header::ORIGIN, "https://example.com")
        .header(header::ACCESS_CONTROL_REQUEST_METHOD, "GET")
        .header(header::ACCESS_CONTROL_REQUEST_HEADERS, "content-type")
        .body(Body::empty())
        .unwrap();

    let res = svc.serve(req).await.unwrap();
    assert_eq!(
        res.headers().get(header::VARY),
        Some(&HeaderValue::from_static(
            "origin, access-control-request-method, access-control-request-headers",
        )),
    );
}

/// When only `allow_origin` is request-dependent (e.g. `MirrorRequest`)
/// but methods and headers are fixed `Any`/`Const`, the derived `Vary`
/// must contain only `Origin`.
#[tokio::test]
async fn derived_vary_only_lists_request_dependent_axes() {
    let svc = CorsLayer::new()
        .try_with_allow_origin_any()
        .unwrap()
        .with_allow_methods_mirror_request()
        .with_allow_headers_mirror_request()
        .into_layer(service_fn(|_: Request| async {
            Ok::<_, Infallible>(Response::new(Body::empty()))
        }));

    let req = Request::builder()
        .method(Method::OPTIONS)
        .header(header::ORIGIN, "https://example.com")
        .header(header::ACCESS_CONTROL_REQUEST_METHOD, "GET")
        .header(header::ACCESS_CONTROL_REQUEST_HEADERS, "content-type")
        .body(Body::empty())
        .unwrap();

    let res = svc.serve(req).await.unwrap();
    assert_eq!(
        res.headers().get(header::VARY),
        Some(&HeaderValue::from_static(
            "access-control-request-method, access-control-request-headers",
        )),
    );
}

/// `permissive` adds no `Vary` of its own, but if the inner handler set
/// one we preserve it (this is a regression test for header clobbering).
#[tokio::test]
#[allow(
    clippy::declare_interior_mutable_const,
    clippy::borrow_interior_mutable_const
)]
async fn vary_set_by_inner_service_is_preserved() {
    const INNER_VARY: HeaderValue = HeaderValue::from_static("accept, accept-encoding");

    async fn inner_svc(_: Request) -> Result<Response, Infallible> {
        Ok(Response::builder()
            .header(header::VARY, INNER_VARY)
            .body(Body::empty())
            .unwrap())
    }

    let svc = CorsLayer::permissive().into_layer(service_fn(inner_svc));
    let res = svc.serve(Request::new(Body::empty())).await.unwrap();
    let mut vary_headers = res.headers().get_all(header::VARY).into_iter();
    assert_eq!(vary_headers.next(), Some(&INNER_VARY));
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

/// Pinning `Vary` explicitly to a single name overrides the derived value
/// — including the case where the derived value would have been empty.
#[tokio::test]
async fn custom_vary_overrides_derived_default() {
    let svc = CorsLayer::permissive()
        .with_vary(Vary::headers(non_empty_vec![
            rama_http_types::HeaderName::from_static("x-foo")
        ]))
        .into_layer(service_fn(|_: Request| async {
            Ok::<_, Infallible>(Response::new(Body::empty()))
        }));

    let res = svc.serve(Request::new(Body::empty())).await.unwrap();
    assert_eq!(
        res.headers().get(header::VARY),
        Some(&HeaderValue::from_static("x-foo")),
    );
}

/// When a fixed `Access-Control-Allow-Origin` is set (no `Origin` is
/// mirrored back) the derived `Vary` must NOT advertise `Origin`.
#[tokio::test]
async fn fixed_allow_origin_does_not_emit_origin_vary() {
    let svc = CorsLayer::new()
        .try_with_allow_origin_any()
        .unwrap()
        .try_with_allow_methods(AccessControlAllowMethods::new(Method::GET))
        .unwrap()
        .try_with_allow_headers(AccessControlAllowHeaders::new_values(non_empty_vec![
            rama_http_types::HeaderName::from_static("content-type")
        ]))
        .unwrap()
        .into_layer(service_fn(|_: Request| async {
            Ok::<_, Infallible>(Response::new(Body::empty()))
        }));

    let res = svc
        .serve(
            Request::builder()
                .header(header::ORIGIN, "http://example.com")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(res.headers().get(header::VARY).is_none());
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
