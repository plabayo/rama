use super::is_length_limit_error;
use crate::body::util::BodyExt;
use crate::service::web::endpoint::IntoResponse;
use crate::service::web::extract::{FromRequest, FromRequestBody};
use crate::{Request, Response, StatusCode};
use rama_core::error::BoxError;
use rama_utils::macros::impl_deref;
use std::fmt;

/// Extractor to get the response body, collected as [`Bytes`].
///
/// [`Bytes`]: https://docs.rs/bytes/latest/bytes/struct.Bytes.html
#[derive(Debug, Clone)]
pub struct Bytes(pub rama_core::bytes::Bytes);

impl_deref!(Bytes: rama_core::bytes::Bytes);

/// Rejection type used when the [`Bytes`] extractor fails to collect the request body.
#[derive(Debug)]
pub struct BytesRejection(BoxError);

impl BytesRejection {
    pub(crate) fn from_err(error: impl Into<BoxError>) -> Self {
        Self(error.into())
    }

    /// Get the response body text used for this rejection.
    #[must_use]
    pub fn body_text(&self) -> String {
        if is_length_limit_error(self.0.as_ref()) {
            "Request payload is too large".to_owned()
        } else {
            format!("Request Body failed to be collected as Bytes: {}", self.0)
        }
    }

    /// Get the status code used for this rejection.
    #[must_use]
    pub fn status(&self) -> StatusCode {
        if is_length_limit_error(self.0.as_ref()) {
            StatusCode::PAYLOAD_TOO_LARGE
        } else {
            StatusCode::BAD_REQUEST
        }
    }
}

impl IntoResponse for BytesRejection {
    fn into_response(self) -> Response {
        crate::utils::macros::log_http_rejection!(
            rejection_type = BytesRejection,
            body_text = self.body_text(),
            status = self.status(),
        );
        (self.status(), self.body_text()).into_response()
    }
}

impl fmt::Display for BytesRejection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Request Body failed to be collected as Bytes")
    }
}

impl std::error::Error for BytesRejection {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.0.as_ref())
    }
}

impl FromRequest for Bytes {
    type Rejection = BytesRejection;

    async fn from_request(req: Request) -> Result<Self, Self::Rejection> {
        let (parts, body) = req.into_parts();
        let future = Self::from_request_body(&parts, body);
        future.await
    }
}

impl FromRequestBody for Bytes {
    fn from_request_body(
        _parts: &crate::request::Parts,
        body: crate::Body,
    ) -> impl Future<Output = Result<Self, Self::Rejection>> + Send + 'static {
        collect_body(body)
    }
}

async fn collect_body(body: crate::Body) -> Result<Bytes, BytesRejection> {
    body.collect()
        .await
        .map_err(BytesRejection::from_err)
        .map(|body| Bytes(body.to_bytes()))
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::layer::body_limit::BodyLimitLayer;
    use crate::service::web::WebService;
    use crate::{Method, Request, StatusCode};
    use rama_core::{Layer, Service, extensions::Extension};
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };

    #[tokio::test]
    async fn test_bytes() {
        let service = WebService::default().with_get("/", async |Bytes(body): Bytes| {
            assert_eq!(body, "test");
        });

        let req = Request::builder()
            .method(Method::GET)
            .body("test".into())
            .unwrap();
        let resp = service.serve(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn body_limit_returns_payload_too_large() {
        let service = BodyLimitLayer::new(4)
            .layer(WebService::default().with_post("/", async |_: Bytes| StatusCode::NO_CONTENT));

        let req = Request::builder()
            .method(Method::POST)
            .body(crate::Body::from("too large"))
            .unwrap();
        let resp = service.serve(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(
            resp.into_body().collect().await.unwrap().to_bytes(),
            "Request payload is too large"
        );
    }

    #[test]
    fn ordinary_collection_error_retains_public_text() {
        let rejection = BytesRejection::from_err(std::io::Error::other("body read failed"));
        assert_eq!(rejection.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            rejection.body_text(),
            "Request Body failed to be collected as Bytes: body read failed"
        );
        assert_eq!(
            rejection.to_string(),
            "Request Body failed to be collected as Bytes"
        );
    }

    #[tokio::test]
    async fn terminal_extractor_keeps_request_parts_alive_while_reading_body() {
        #[derive(Debug)]
        struct PartsGuard(Arc<AtomicBool>);

        impl Extension for PartsGuard {}

        impl Drop for PartsGuard {
            fn drop(&mut self) {
                self.0.store(false, Ordering::SeqCst);
            }
        }

        let parts_are_alive = Arc::new(AtomicBool::new(true));
        let body_observer = Arc::clone(&parts_are_alive);
        let body = crate::Body::from_stream(rama_core::futures::stream::once(async move {
            assert!(body_observer.load(Ordering::SeqCst));
            Ok::<_, std::convert::Infallible>(rama_core::bytes::Bytes::from_static(b"payload"))
        }));
        let request = Request::builder()
            .extension(PartsGuard(Arc::clone(&parts_are_alive)))
            .body(body)
            .unwrap();

        let Bytes(body) = Bytes::from_request(request).await.unwrap();

        assert_eq!(body, "payload");
        assert!(!parts_are_alive.load(Ordering::SeqCst));
    }
}
