use super::FromRequest;
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

mod csv;
#[doc(inline)]
pub use csv::*;

mod form;
#[doc(inline)]
pub use form::*;

/// Extractor to get the response body.
#[derive(Debug)]
pub struct Body(pub http::Body);

impl_deref!(Body: http::Body);

impl FromRequest for Body {
    type Rejection = Infallible;

    async fn from_request(req: http::Request) -> Result<Self, Self::Rejection> {
        Ok(Self(req.into_body()))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::dep::http_body_util::BodyExt;
    use crate::service::web::WebService;
    use crate::{Method, Request, StatusCode};
    use rama_core::{Context, Service};

    #[tokio::test]
    async fn test_body() {
        let service = WebService::default().get("/", |Body(body): Body| async move {
            let body = body.collect().await.unwrap().to_bytes();
            assert_eq!(body, "test");
        });

        let req = Request::builder()
            .method(Method::GET)
            .body("test".into())
            .unwrap();
        let resp = service.serve(Context::default(), req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }
}
