use crate::layer::cors::{AllowOrigin, CorsLayer};
use crate::{Body, HeaderValue, Request, Response, header};
use rama_core::service::service_fn;
use rama_core::{Context, Layer, Service};
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
    let res = svc
        .serve(Context::default(), Request::new(Body::empty()))
        .await
        .unwrap();
    let mut vary_headers = res.headers().get_all(header::VARY).into_iter();
    assert_eq!(vary_headers.next(), Some(&CUSTOM_VARY_HEADERS));
    assert_eq!(vary_headers.next(), Some(&PERMISSIVE_CORS_VARY_HEADERS));
    assert_eq!(vary_headers.next(), None);
}

#[tokio::test]
async fn test_allow_origin_async_predicate() {
    #[derive(Clone)]
    struct Client;

    impl Client {
        async fn fetch_allowed_origins_for_path(&self, _path: String) -> Vec<HeaderValue> {
            vec![HeaderValue::from_static("http://example.com")]
        }
    }

    let client = Client;

    let allow_origin = AllowOrigin::async_predicate(move |origin, parts| {
        let client = client.clone();
        let path = parts.uri.path().to_owned();

        async move {
            let origins = client.fetch_allowed_origins_for_path(path).await;

            origins.contains(&origin)
        }
    });

    let valid_origin = HeaderValue::from_static("http://example.com");
    let parts = rama_http_types::Request::new("hello world").into_parts().0;

    let header = allow_origin
        .to_future(Some(&valid_origin), &parts)
        .await
        .unwrap();
    assert_eq!(header.0, header::ACCESS_CONTROL_ALLOW_ORIGIN);
    assert_eq!(header.1, valid_origin);

    let invalid_origin = HeaderValue::from_static("http://example.org");
    let parts = rama_http_types::Request::new("hello world").into_parts().0;

    let res = allow_origin.to_future(Some(&invalid_origin), &parts).await;
    assert!(res.is_none());
}
