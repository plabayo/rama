use crate::http::dep::http_body_util::BodyExt;
use crate::http::service::web::extract::FromRequest;
use crate::http::Request;
use crate::service::Context;
use std::ops::{Deref, DerefMut};

/// Extractor to get the response body, collected as [`Bytes`].
///
/// [`Bytes`]: https://docs.rs/bytes/latest/bytes/struct.Bytes.html
#[derive(Debug, Clone)]
pub struct Bytes(pub bytes::Bytes);

crate::__define_http_rejection! {
    #[status = BAD_REQUEST]
    #[body = "Request Body failed to be collected as Bytes"]
    /// Rejection type used when the [`Bytes`] extractor fails to collect the request body.
    pub struct BytesRejection(Error);
}

impl<S> FromRequest<S> for Bytes
where
    S: Send + Sync + 'static,
{
    type Rejection = BytesRejection;

    async fn from_request(_ctx: Context<S>, req: Request) -> Result<Self, Self::Rejection> {
        req.into_body()
            .collect()
            .await
            .map_err(BytesRejection::from_err)
            .map(|c| Bytes(c.to_bytes()))
    }
}

impl Deref for Bytes {
    type Target = bytes::Bytes;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for Bytes {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::http::{self, StatusCode};
    use crate::{http::service::web::WebService, service::Service};

    #[tokio::test]
    async fn test_bytes() {
        let service = WebService::default().get("/", |Bytes(body): Bytes| async move {
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
