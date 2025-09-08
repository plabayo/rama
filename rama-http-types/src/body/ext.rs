use super::StreamingBody;
use super::util::BodyExt;
use rama_error::{BoxError, ErrorContext, OpaqueError};

/// An extension trait for [`StreamingBody`] that provides methods to extract data from it.
pub trait BodyExtractExt: private::Sealed {
    /// Try to deserialize the (contained) body as a JSON object.
    fn try_into_json<T: serde::de::DeserializeOwned + Send + 'static>(
        self,
    ) -> impl Future<Output = Result<T, OpaqueError>> + Send;

    /// Try to turn the (contained) body in an utf-8 string.
    fn try_into_string(self) -> impl Future<Output = Result<String, OpaqueError>> + Send;
}

impl<Body> BodyExtractExt for crate::Response<Body>
where
    Body: StreamingBody<Data: Send + 'static, Error: Into<BoxError>> + Send + 'static,
{
    async fn try_into_json<T: serde::de::DeserializeOwned + Send + 'static>(
        self,
    ) -> Result<T, OpaqueError> {
        let body = self
            .into_body()
            .collect()
            .await
            .map_err(|err| OpaqueError::from_boxed(err.into()))?;
        serde_json::from_slice(body.to_bytes().as_ref())
            .context("deserialize response body as JSON")
    }

    async fn try_into_string(self) -> Result<String, OpaqueError> {
        let body = self
            .into_body()
            .collect()
            .await
            .map_err(|err| OpaqueError::from_boxed(err.into()))?;
        let bytes = body.to_bytes();
        String::from_utf8(bytes.to_vec()).context("parse body as utf-8 string")
    }
}

impl<Body> BodyExtractExt for crate::Request<Body>
where
    Body: StreamingBody<Data: Send + 'static, Error: Into<BoxError>> + Send + 'static,
{
    async fn try_into_json<T: serde::de::DeserializeOwned + Send + 'static>(
        self,
    ) -> Result<T, OpaqueError> {
        let body = self
            .into_body()
            .collect()
            .await
            .map_err(|err| OpaqueError::from_boxed(err.into()))?;
        serde_json::from_slice(body.to_bytes().as_ref()).context("deserialize request body as JSON")
    }

    async fn try_into_string(self) -> Result<String, OpaqueError> {
        let body = self
            .into_body()
            .collect()
            .await
            .map_err(|err| OpaqueError::from_boxed(err.into()))?;
        let bytes = body.to_bytes();
        String::from_utf8(bytes.to_vec()).context("parse request body as utf-8 string")
    }
}

impl<B: Into<crate::Body> + Send + 'static> BodyExtractExt for B {
    async fn try_into_json<T: serde::de::DeserializeOwned + Send + 'static>(
        self,
    ) -> Result<T, OpaqueError> {
        let body = self.into().collect().await.context("collect body")?;
        serde_json::from_slice(body.to_bytes().as_ref()).context("deserialize body as JSON")
    }

    async fn try_into_string(self) -> Result<String, OpaqueError> {
        let body = self.into().collect().await.context("collect body")?;
        let bytes = body.to_bytes();
        String::from_utf8(bytes.to_vec()).context("parse body as utf-8 string")
    }
}

mod private {
    pub trait Sealed {}

    impl<Body> Sealed for crate::Response<Body> {}
    impl<Body> Sealed for crate::Request<Body> {}
    impl<B: Into<crate::Body> + Send + 'static> Sealed for B {}
}
