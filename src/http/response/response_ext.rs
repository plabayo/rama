use crate::error::Error;
use crate::http::dep::http_body_util::BodyExt;
use std::future::Future;

/// An extension trait for [`http::Response`] that provides additional auxiliry methods.
pub trait ResponseExt: private::Sealed {
    /// Try to get the response body as a JSON object.
    fn into_body_json<T: serde::de::DeserializeOwned + Send + 'static>(
        self,
    ) -> impl Future<Output = Result<T, Error>> + Send;

    /// Try to get the response body as a string.
    fn into_body_string(self) -> impl Future<Output = Result<String, Error>> + Send;
}

impl<Body> ResponseExt for crate::http::Response<Body>
where
    Body: crate::http::dep::http_body::Body + Send + 'static,
    Body::Data: Send + 'static,
    Body::Error: std::error::Error + Send + Sync + 'static,
{
    async fn into_body_json<T: serde::de::DeserializeOwned + Send + 'static>(
        self,
    ) -> Result<T, Error> {
        let body = self.into_body().collect().await?;
        Ok(serde_json::from_slice(body.to_bytes().as_ref())?)
    }

    async fn into_body_string(self) -> Result<String, Error> {
        let body = self.into_body().collect().await?;
        let bytes = body.to_bytes();
        Ok(String::from_utf8(bytes.to_vec())?)
    }
}

mod private {
    pub trait Sealed {}

    impl<Body> Sealed for crate::http::Response<Body> {}
}
