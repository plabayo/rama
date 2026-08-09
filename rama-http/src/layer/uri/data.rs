//! Serve `data:` request URIs from the URI itself (RFC 2397).
//!
//! A client stack layered with [`DataUriLayer`] answers `data:` requests
//! itself and passes every other scheme to the inner service.
//!
//! Place this layer *outside* any
//! [`FollowRedirectLayer`][crate::layer::follow_redirect::FollowRedirectLayer],
//! so a remote response cannot redirect into it.

use rama_core::{
    Layer, Service,
    error::{BoxError, BoxErrorExt, ErrorContext},
};
use rama_net::{Protocol, uri::DataUri};
use rama_utils::macros::define_inner_service_accessors;

use crate::{
    Body, Method, Request, Response, StatusCode,
    headers::{ContentType, HttpResponseBuilderExt as _},
};

/// Serve `data:` request URIs from the URI itself.
///
/// See the [module docs](crate::layer::uri::data) for an example.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct DataUriLayer;

impl DataUriLayer {
    /// Create a new [`DataUriLayer`].
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl<S> Layer<S> for DataUriLayer {
    type Service = DataUriService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        DataUriService::new(inner)
    }
}

/// Serve `data:` request URIs from the URI itself.
///
/// See the [module docs](crate::layer::uri::data) for an example.
#[derive(Debug, Clone)]
pub struct DataUriService<S> {
    inner: S,
}

impl<S> DataUriService<S> {
    /// Create a new [`DataUriService`].
    pub const fn new(inner: S) -> Self {
        Self { inner }
    }

    define_inner_service_accessors!();
}

impl<S, ReqBody> Service<Request<ReqBody>> for DataUriService<S>
where
    S: Service<Request<ReqBody>, Output = Response, Error: Into<BoxError>>,
    ReqBody: Send + 'static,
{
    type Output = Response;
    type Error = BoxError;

    async fn serve(&self, req: Request<ReqBody>) -> Result<Self::Output, Self::Error> {
        if req.uri().scheme() != Some(&Protocol::DATA) {
            return self.inner.serve(req).await.map_err(Into::into);
        }

        if !matches!(req.method(), &Method::GET | &Method::HEAD) {
            return Err(BoxError::from_static_str(
                "data: URIs support GET and HEAD only",
            ));
        }

        let data = DataUri::try_from_uri(req.uri()).context("decode data: uri")?;
        let media_type = data.media_type().clone();

        let body = if req.method() == Method::HEAD {
            Body::empty()
        } else {
            Body::from(data.into_data())
        };
        Response::builder()
            .status(StatusCode::OK)
            .typed_header(ContentType::new(media_type))
            .body(body)
            .context("build data: response")
    }
}

#[cfg(test)]
mod tests {
    use std::convert::Infallible;

    use rama_core::service::service_fn;

    use super::*;
    use crate::{BodyExtractExt as _, headers::HeaderMapExt as _};
    use rama_net::uri::{DEFAULT_DATA_MEDIA_TYPE, Uri};

    fn service() -> DataUriService<impl Service<Request, Output = Response, Error = Infallible>> {
        DataUriService::new(service_fn(async |_: Request| {
            Ok::<_, Infallible>(Response::new(Body::from("remote")))
        }))
    }

    async fn get(uri: &str) -> Result<Response, BoxError> {
        let uri: Uri = uri.parse().unwrap();
        service()
            .serve(Request::get(uri).body(Body::empty()).unwrap())
            .await
    }

    fn content_type(resp: &Response) -> crate::mime::Mime {
        resp.headers()
            .typed_get::<ContentType>()
            .unwrap()
            .into_mime()
    }

    #[tokio::test]
    async fn non_data_scheme_passes_through() {
        let resp = get("http://example.com/x").await.unwrap();
        assert_eq!(resp.try_into_string().await.unwrap(), "remote");
    }

    #[tokio::test]
    async fn plain_payload() {
        let resp = get("data:,hello%20world").await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            content_type(&resp),
            DEFAULT_DATA_MEDIA_TYPE
                .parse::<crate::mime::Mime>()
                .unwrap()
        );
        assert_eq!(resp.try_into_string().await.unwrap(), "hello world");
    }

    #[tokio::test]
    async fn base64_payload_with_media_type() {
        let resp = get("data:text/javascript;base64,RElSRUNU").await.unwrap();
        assert_eq!(content_type(&resp), crate::mime::TEXT_JAVASCRIPT);
        assert_eq!(resp.try_into_string().await.unwrap(), "DIRECT");
    }

    #[tokio::test]
    async fn media_type_is_preserved() {
        let resp = get("data:application/x-ns-proxy-autoconfig,DIRECT")
            .await
            .unwrap();
        assert_eq!(
            content_type(&resp).as_ref(),
            "application/x-ns-proxy-autoconfig"
        );
    }

    #[tokio::test]
    async fn payload_keeps_query_and_drops_fragment() {
        // `?` is part of the payload, not a query: a PAC ternary must survive
        let resp = get("data:application/x-ns-proxy-autoconfig,return h==host?DIRECT:PROXY")
            .await
            .unwrap();
        assert_eq!(
            resp.try_into_string().await.unwrap(),
            "return h==host?DIRECT:PROXY"
        );

        let resp = get("data:,a?b#c").await.unwrap();
        assert_eq!(resp.try_into_string().await.unwrap(), "a?b");
    }

    #[tokio::test]
    async fn head_has_no_body() {
        let resp = service()
            .serve(
                Request::builder()
                    .method(Method::HEAD)
                    .uri("data:,hello")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.try_into_string().await.unwrap(), "");
    }

    #[tokio::test]
    async fn missing_comma_errors() {
        let _err = get("data:text/plain").await.unwrap_err();
    }

    #[tokio::test]
    async fn invalid_media_type_errors() {
        let _err = get("data:not a mime,payload").await.unwrap_err();
    }

    #[tokio::test]
    async fn invalid_base64_errors() {
        let _err = get("data:text/plain;base64,!!!not-base64!!!")
            .await
            .unwrap_err();
    }

    #[tokio::test]
    async fn rejects_non_get_methods() {
        let err = service()
            .serve(
                Request::builder()
                    .method(Method::POST)
                    .uri("data:,x")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap_err();
        assert!(err.to_string().contains("GET and HEAD"), "{err}");
    }
}
