use super::FromRequest;
use crate::http;
use crate::service::Context;
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

mod form;
#[doc(inline)]
pub use form::*;

/// Extractor to get the response body.
#[derive(Debug)]
pub struct Body(pub http::Body);

impl_deref!(Body: http::Body);

impl<S> FromRequest<S> for Body
where
    S: Send + Sync + 'static,
{
    type Rejection = Infallible;

    async fn from_request(_ctx: Context<S>, req: http::Request) -> Result<Self, Self::Rejection> {
        Ok(Self(req.into_body()))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::http::dep::http_body_util::BodyExt;
    use crate::http::{self, StatusCode};
    use crate::{http::service::web::WebService, service::Service};

    #[tokio::test]
    async fn test_body() {
        let service = WebService::default().get("/", |Body(body): Body| async move {
            let body = body.collect().await.unwrap().to_bytes();
            assert_eq!(body, "test");
        });

        let req = http::Request::builder()
            .method(http::Method::GET)
            .body("test".into())
            .unwrap();
        let resp = service.serve(Context::default(), req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }
}
