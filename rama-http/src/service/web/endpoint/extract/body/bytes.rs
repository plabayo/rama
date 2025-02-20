use crate::Request;
use crate::dep::http_body_util::BodyExt;
use crate::service::web::extract::FromRequest;
use crate::utils::macros::define_http_rejection;
use rama_utils::macros::impl_deref;

/// Extractor to get the response body, collected as [`Bytes`].
///
/// [`Bytes`]: https://docs.rs/bytes/latest/bytes/struct.Bytes.html
#[derive(Debug, Clone)]
pub struct Bytes(pub bytes::Bytes);

impl_deref!(Bytes: bytes::Bytes);

define_http_rejection! {
    #[status = BAD_REQUEST]
    #[body = "Request Body failed to be collected as Bytes"]
    /// Rejection type used when the [`Bytes`] extractor fails to collect the request body.
    pub struct BytesRejection(Error);
}

impl FromRequest for Bytes {
    type Rejection = BytesRejection;

    async fn from_request(req: Request) -> Result<Self, Self::Rejection> {
        req.into_body()
            .collect()
            .await
            .map_err(BytesRejection::from_err)
            .map(|c| Bytes(c.to_bytes()))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::service::web::WebService;
    use crate::{Method, Request, StatusCode};
    use rama_core::{Context, Service};

    #[tokio::test]
    async fn test_bytes() {
        let service = WebService::default().get("/", |Bytes(body): Bytes| async move {
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
