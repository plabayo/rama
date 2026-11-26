#![expect(
    clippy::allow_attributes,
    reason = "macro-generated `#[allow]` attributes whose underlying lints fire only for some expansions"
)]

use std::convert::Infallible;

use rama_core::{Layer, Service, bytes::Bytes, service::service_fn};
use rama_http_headers::{AccessControlAllowHeaders, AccessControlAllowMethods};
use rama_utils::collections::non_empty_vec;

use crate::{
    Body, HeaderMap, HeaderName, HeaderValue, Method, Request, Response, StatusCode,
    body::{OptionalBody, util::BodyExt},
    header,
    headers::Vary,
    layer::cors::{CorsLayer, merge_cors_headers},
};

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

/// One `Origin` is reflected; several lines name no origin, so none is allowed or reflected.
#[tokio::test]
async fn several_origin_lines_are_never_reflected() {
    for (origins, reflected) in [
        (&["https://client.test"][..], Some("https://client.test")),
        (&["https://client.test", "https://attacker.test"], None),
    ] {
        let svc = CorsLayer::very_permissive().into_layer(service_fn(|_: Request| async {
            Ok::<_, Infallible>(Response::new(Body::empty()))
        }));
        let mut req = Request::builder();
        for origin in origins {
            req = req.header(header::ORIGIN, *origin);
        }
        let res = svc.serve(req.body(Body::empty()).unwrap()).await.unwrap();
        assert_eq!(
            res.headers()
                .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
                .map(|value| value.to_str().unwrap()),
            reflected,
            "{origins:?}"
        );
    }
}

fn forwarding_cors()
-> impl Service<Request, Output = Response<OptionalBody<Body>>, Error = Infallible> {
    CorsLayer::new()
        .with_allow_origin_if(|origin, _| origin == "https://allowed.example")
        .with_allow_methods_mirror_request()
        .with_allow_headers_mirror_request()
        .with_forward_disallowed_preflights(true)
        .into_layer(service_fn(|_: Request| async {
            Ok::<_, Infallible>(Response::new(Body::from("inner")))
        }))
}

fn preflight(origin: Option<&'static str>) -> Request {
    let mut builder = Request::builder()
        .method(Method::OPTIONS)
        .header(header::ACCESS_CONTROL_REQUEST_METHOD, "POST")
        .header(header::ACCESS_CONTROL_REQUEST_HEADERS, "x-custom");
    if let Some(origin) = origin {
        builder = builder.header(header::ORIGIN, origin);
    }
    builder.body(Body::empty()).unwrap()
}

async fn body_bytes(res: Response<OptionalBody<Body>>) -> Bytes {
    res.into_body().collect().await.unwrap().to_bytes()
}

#[tokio::test]
async fn forwarded_disallowed_preflight_reaches_the_inner_service_without_cors_headers() {
    for origin in [Some("https://other.example"), None] {
        let res = forwarding_cors().serve(preflight(origin)).await.unwrap();
        for name in [
            header::ACCESS_CONTROL_ALLOW_ORIGIN,
            header::ACCESS_CONTROL_ALLOW_METHODS,
            header::ACCESS_CONTROL_ALLOW_HEADERS,
        ] {
            assert!(!res.headers().contains_key(&name), "{origin:?} {name}");
        }
        assert_eq!(
            res.headers()[header::VARY],
            "origin, access-control-request-method, access-control-request-headers"
        );
        assert_eq!(body_bytes(res).await, "inner", "{origin:?}");
    }
}

#[tokio::test]
async fn allowed_preflight_is_answered_even_when_forwarding_disallowed_ones() {
    let res = forwarding_cors()
        .serve(preflight(Some("https://allowed.example")))
        .await
        .unwrap();
    assert_eq!(
        res.headers()[header::ACCESS_CONTROL_ALLOW_ORIGIN],
        "https://allowed.example"
    );
    assert_eq!(res.headers()[header::ACCESS_CONTROL_ALLOW_METHODS], "POST");
    assert_eq!(
        res.headers()[header::ACCESS_CONTROL_ALLOW_HEADERS],
        "x-custom"
    );
    assert!(body_bytes(res).await.is_empty());
}

#[tokio::test]
async fn disallowed_preflight_is_answered_by_default() {
    let svc = CorsLayer::new()
        .with_allow_origin_if(|origin, _| origin == "https://allowed.example")
        .into_layer(service_fn(|_: Request| async {
            Ok::<_, Infallible>(Response::new(Body::from("inner")))
        }));
    let res = svc
        .serve(preflight(Some("https://other.example")))
        .await
        .unwrap();
    assert!(body_bytes(res).await.is_empty());
}

/// Every line of a multi-valued CORS header reaches the response, in order and with its
/// casing, while a header the handler set keeps the handler's value.
#[test]
fn merge_keeps_every_line_of_a_multi_valued_header() {
    let mut response = HeaderMap::new();
    response.insert(named("X-Handler"), HeaderValue::from_static("h"));
    response.insert(
        named("Access-Control-Allow-Origin"),
        HeaderValue::from_static("https://handler.example"),
    );

    let mut cors = HeaderMap::new();
    cors.insert(
        named("Access-Control-Allow-Origin"),
        HeaderValue::from_static("*"),
    );
    cors.insert(
        named("Access-Control-Expose-Headers"),
        HeaderValue::from_static("x-a"),
    );
    cors.append(
        named("ACCESS-CONTROL-EXPOSE-HEADERS"),
        HeaderValue::from_static("x-b"),
    );
    cors.insert(header::VARY, HeaderValue::from_static("origin"));

    assert!(merge_cors_headers(&mut response, cors));

    assert_eq!(
        ordered_lines(&response),
        [
            ("X-Handler", "h"),
            ("Access-Control-Allow-Origin", "https://handler.example"),
            ("Access-Control-Expose-Headers", "x-a"),
            ("ACCESS-CONTROL-EXPOSE-HEADERS", "x-b"),
            ("vary", "origin"),
        ]
        .map(|(name, value)| (name.into(), value.into()))
    );
}

#[test]
fn merge_keeps_credentials_before_vary_and_preserves_reservations() {
    let mut cors = HeaderMap::new();
    cors.append(
        header::ACCESS_CONTROL_ALLOW_CREDENTIALS,
        HeaderValue::from_static("true"),
    );
    cors.reserve_position(named("X-Later"));
    cors.append(named("Vary"), HeaderValue::from_static("origin"));
    let mut response = HeaderMap::new();
    assert!(merge_cors_headers(&mut response, cors));
    response.insert("x-later", HeaderValue::from_static("later"));
    assert_eq!(
        ordered_lines(&response),
        [
            ("access-control-allow-credentials", "true"),
            ("x-later", "later"),
            ("Vary", "origin")
        ]
        .map(|(name, value)| (name.into(), value.into()))
    );
}

#[test]
fn full_response_with_existing_vary_keeps_its_origin_variation() {
    let mut response = full_header_map();
    response.remove("x-fill-0");
    response.insert(named("Vary"), HeaderValue::from_static("accept-encoding"));
    let mut cors = HeaderMap::new();
    cors.append(header::VARY, HeaderValue::from_static("origin"));
    assert!(merge_cors_headers(&mut response, cors));
    let vary: Vec<_> = response
        .get_all(header::VARY)
        .iter()
        .map(|value| value.to_str().unwrap())
        .collect();
    assert_eq!(vary, ["accept-encoding", "origin"]);
}

fn ordered_lines(headers: &HeaderMap) -> Vec<(Box<str>, Box<str>)> {
    headers
        .ordered_iter()
        .map(|(name, value)| {
            (
                name.as_original_str().into(),
                value.to_str().unwrap().into(),
            )
        })
        .collect()
}

/// A response map that cannot hold one more header name.
fn full_header_map() -> HeaderMap {
    let mut headers = HeaderMap::new();
    let mut n = 0_usize;
    loop {
        let name = HeaderName::from_bytes(format!("x-fill-{n}").as_bytes()).unwrap();
        if headers
            .try_insert(name, HeaderValue::from_static("1"))
            .is_err()
        {
            return headers;
        }
        n += 1;
    }
}

#[tokio::test]
async fn full_response_map_returns_an_uncacheable_error() {
    let svc = CorsLayer::new()
        .with_allow_origin_mirror_request()
        .into_layer(service_fn(|_: Request| async {
            let mut response = Response::new(Body::from("inner"));
            *response.headers_mut() = full_header_map();
            response.headers_mut().remove("x-fill-0");
            response.headers_mut().insert(
                header::ACCESS_CONTROL_ALLOW_ORIGIN,
                HeaderValue::from_static("https://example.test"),
            );
            Ok::<_, Infallible>(response)
        }));
    let res = svc
        .serve(
            Request::builder()
                .header(header::ORIGIN, "https://example.test")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(res.headers()[header::CACHE_CONTROL], "no-store");
    assert!(body_bytes(res).await.is_empty());
}

#[tokio::test]
async fn forwarded_preflight_with_a_full_response_map_returns_an_uncacheable_error() {
    let svc = CorsLayer::new()
        .with_allow_origin_if(|origin, _| origin == "https://allowed.example")
        .with_forward_disallowed_preflights(true)
        .into_layer(service_fn(|_: Request| async {
            let mut response = Response::new(Body::from("inner"));
            *response.headers_mut() = full_header_map();
            Ok::<_, Infallible>(response)
        }));
    let res = svc
        .serve(preflight(Some("https://other.example")))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(res.headers()[header::CACHE_CONTROL], "no-store");
    assert!(body_bytes(res).await.is_empty());
}

#[tokio::test]
async fn forwarded_preflight_appends_vary_after_the_inner_headers() {
    let svc = CorsLayer::new()
        .with_allow_origin_if(|origin, _| origin == "https://allowed.example")
        .with_allow_methods_mirror_request()
        .with_forward_disallowed_preflights(true)
        .into_layer(service_fn(|_: Request| async {
            let mut response = Response::new(Body::from("inner"));
            let headers = response.headers_mut();
            headers.insert(named("X-First"), HeaderValue::from_static("1"));
            headers.insert(named("Vary"), HeaderValue::from_static("accept-encoding"));
            headers.insert(named("x-LAST"), HeaderValue::from_static("2"));
            Ok::<_, Infallible>(response)
        }));
    let res = svc
        .serve(preflight(Some("https://other.example")))
        .await
        .unwrap();
    assert_eq!(
        ordered_lines(res.headers()),
        [
            ("X-First", "1"),
            ("Vary", "accept-encoding"),
            ("x-LAST", "2"),
            ("vary", "origin, access-control-request-method"),
        ]
        .map(|(name, value)| (name.into(), value.into()))
    );
}

fn named(name: &str) -> HeaderName {
    HeaderName::from_bytes(name.as_bytes()).unwrap()
}
