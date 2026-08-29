//! module in function of extractors for `Request` bodies

use super::{FromRequest, FromRequestBody};
use rama_http_types as http;
use rama_utils::macros::impl_deref;
use std::convert::Infallible;

fn is_length_limit_error(error: &(dyn std::error::Error + 'static)) -> bool {
    let mut current = Some(error);
    while let Some(error) = current {
        if error
            .downcast_ref::<rama_http_types::body::util::LengthLimitError>()
            .is_some()
        {
            return true;
        }
        current = error.source();
    }
    false
}

mod bytes;
#[doc(inline)]
pub use bytes::*;

mod text;
#[doc(inline)]
pub use text::*;

mod json;
#[doc(inline)]
pub use json::*;

mod json_lines;
#[doc(inline)]
pub use json_lines::*;

mod csv;
#[doc(inline)]
pub use csv::*;

mod form;
#[doc(inline)]
pub use form::*;

mod octet_stream;
#[doc(inline)]
pub use octet_stream::*;

#[cfg(feature = "multipart")]
pub mod multipart;

/// Extractor to get the response body.
#[derive(Debug)]
pub struct Body(pub crate::Body);

impl_deref!(Body: crate::Body);

impl FromRequest for Body {
    type Rejection = Infallible;

    async fn from_request(req: http::Request) -> Result<Self, Self::Rejection> {
        let (parts, body) = req.into_parts();
        let future = Self::from_request_body(&parts, body);
        future.await
    }
}

impl FromRequestBody for Body {
    fn from_request_body(
        _parts: &http::request::Parts,
        body: crate::Body,
    ) -> impl Future<Output = Result<Self, Self::Rejection>> + Send + 'static {
        std::future::ready(Ok(Self(body)))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::service::web::WebService;
    use crate::{Method, Request, StatusCode, body::util::BodyExt, header};
    use rama_core::Service;

    #[derive(Debug)]
    struct WrappedLimitError(rama_core::error::BoxError);

    impl std::fmt::Display for WrappedLimitError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("wrapped limit")
        }
    }

    impl std::error::Error for WrappedLimitError {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            Some(self.0.as_ref())
        }
    }

    #[tokio::test]
    async fn identifies_length_limits_anywhere_in_error_chain() {
        let error = crate::Body::new(rama_http_types::body::util::Limited::new(
            crate::Body::from("too large"),
            1,
        ))
        .collect()
        .await
        .unwrap_err();
        assert!(is_length_limit_error(&WrappedLimitError(Box::new(error))));
        assert!(!is_length_limit_error(&std::io::Error::other("other")));
    }

    fn limited_request(content_type: Option<&'static str>) -> Request {
        let mut builder = Request::builder().method(Method::POST);
        if let Some(content_type) = content_type {
            builder = builder.header(header::CONTENT_TYPE, content_type);
        }
        builder
            .body(crate::Body::new(rama_http_types::body::util::Limited::new(
                crate::Body::from("payload larger than one byte"),
                1,
            )))
            .unwrap()
    }

    #[tokio::test]
    async fn all_collecting_extractors_report_payload_too_large() {
        assert_eq!(
            Bytes::from_request(limited_request(None))
                .await
                .unwrap_err()
                .status(),
            StatusCode::PAYLOAD_TOO_LARGE
        );
        assert_eq!(
            Text::from_request(limited_request(Some("text/plain")))
                .await
                .unwrap_err()
                .status(),
            StatusCode::PAYLOAD_TOO_LARGE
        );
        assert_eq!(
            Json::<serde_json::Value>::from_request(limited_request(Some("application/json")))
                .await
                .unwrap_err()
                .status(),
            StatusCode::PAYLOAD_TOO_LARGE
        );
        assert_eq!(
            Form::<serde_json::Value>::from_request(limited_request(Some(
                "application/x-www-form-urlencoded",
            )))
            .await
            .unwrap_err()
            .status(),
            StatusCode::PAYLOAD_TOO_LARGE
        );
        assert_eq!(
            Csv::<Vec<serde_json::Value>>::from_request(limited_request(Some("text/csv"),))
                .await
                .unwrap_err()
                .status(),
            StatusCode::PAYLOAD_TOO_LARGE
        );
        assert_eq!(
            OctetStream::from_request(limited_request(Some("application/octet-stream")))
                .await
                .unwrap_err()
                .status(),
            StatusCode::PAYLOAD_TOO_LARGE
        );
    }

    #[tokio::test]
    async fn test_body() {
        let service = WebService::default().with_get("/", async |Body(body): Body| {
            let body = body.collect().await.unwrap().to_bytes();
            assert_eq!(body, "test");
        });

        let req = Request::builder()
            .method(Method::GET)
            .body("test".into())
            .unwrap();
        let resp = service.serve(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }
}
