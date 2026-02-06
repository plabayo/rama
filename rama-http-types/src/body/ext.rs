use super::StreamingBody;
use super::util::BodyExt;
use rama_core::error::{BoxError, ErrorContext};

/// An extension trait for [`StreamingBody`] that provides methods to extract data from it.
pub trait BodyExtractExt: private::Sealed {
    /// Try to deserialize the (contained) body as a JSON object.
    fn try_into_json<T: serde::de::DeserializeOwned + Send + 'static>(
        self,
    ) -> impl Future<Output = Result<T, BoxError>> + Send;

    /// Try to turn the (contained) body in an utf-8 string.
    fn try_into_string(self) -> impl Future<Output = Result<String, BoxError>> + Send;
}

impl<Body> BodyExtractExt for crate::Response<Body>
where
    Body: StreamingBody<Data: Send + 'static, Error: Into<BoxError>> + Send + 'static,
{
    async fn try_into_json<T: serde::de::DeserializeOwned + Send + 'static>(
        self,
    ) -> Result<T, BoxError> {
        let body = self.into_body().collect().await.into_box_error()?;
        serde_json::from_slice(body.to_bytes().as_ref())
            .context("deserialize response body as JSON")
    }

    async fn try_into_string(self) -> Result<String, BoxError> {
        let body = self.into_body().collect().await.into_box_error()?;
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
    ) -> Result<T, BoxError> {
        let body = self.into_body().collect().await.into_box_error()?;
        serde_json::from_slice(body.to_bytes().as_ref()).context("deserialize request body as JSON")
    }

    async fn try_into_string(self) -> Result<String, BoxError> {
        let body = self.into_body().collect().await.into_box_error()?;
        let bytes = body.to_bytes();
        String::from_utf8(bytes.to_vec()).context("parse request body as utf-8 string")
    }
}

impl<B: Into<crate::Body> + Send + 'static> BodyExtractExt for B {
    async fn try_into_json<T: serde::de::DeserializeOwned + Send + 'static>(
        self,
    ) -> Result<T, BoxError> {
        let body = self.into();
        let collected_body = body.collect().await.context("collect body")?;
        serde_json::from_slice(collected_body.to_bytes().as_ref())
            .context("deserialize body as JSON")
    }

    async fn try_into_string(self) -> Result<String, BoxError> {
        let body = self.into();
        let collected_body = body.collect().await.context("collect body")?;
        let bytes = collected_body.to_bytes();
        String::from_utf8(bytes.to_vec()).context("parse body as utf-8 string")
    }
}

mod private {
    pub trait Sealed {}

    impl<Body> Sealed for crate::Response<Body> {}
    impl<Body> Sealed for crate::Request<Body> {}
    impl<B: Into<crate::Body> + Send + 'static> Sealed for B {}
}
