//! module in function of extractors for `Request` bodies

use super::{FromRequest, FromRequestBody};
use rama_http_types as http;
use rama_utils::macros::impl_deref;
use std::convert::Infallible;

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
    use crate::{Method, Request, StatusCode, body::util::BodyExt};
    use rama_core::Service;

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
