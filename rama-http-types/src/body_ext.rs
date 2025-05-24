use crate::dep::http_body_util::BodyExt;
use bytes::Bytes;
use futures_core::Stream;
use rama_error::{BoxError, ErrorContext, OpaqueError};

/// An extension trait for [`Body`] that provides methods to extract data from it.
///
/// [`Body`]: crate::Body
pub trait BodyExtractExt: private::Sealed {
    type StreamData;
    type StreamError;

    /// Try to deserialize the (contained) body as a JSON object.
    fn try_into_json<T: serde::de::DeserializeOwned + Send + 'static>(
        self,
    ) -> impl Future<Output = Result<T, OpaqueError>> + Send;

    /// Try to turn the (contained) body in an utf-8 string.
    fn try_into_string(self) -> impl Future<Output = Result<String, OpaqueError>> + Send;

    /// Turn the (contained) body into a stream of data.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use bytes::Bytes;
    /// # use futures_lite::StreamExt;
    /// # use rama_http_types::{Request, BodyExtractExt};
    /// # use rama_error::BoxError;
    /// # use rama_http_types::dep::{http_body::Body, http_body_util::BodyExt};
    /// async fn example<B>(req: Request<B>) -> Result<(), BoxError>
    /// where
    ///     B: Body + Send + 'static,
    /// {
    ///     let mut stream = req.into_data_stream();
    ///     while let Some(chunk_result) = stream.next().await {
    ///         let chunk: Bytes = chunk_result?;
    ///         println!("got {} bytes", chunk.len());
    ///     }
    ///     Ok(())
    /// }
    /// ```
    fn into_data_stream(
        self,
    ) -> impl Stream<Item = Result<Self::StreamData, Self::StreamError>> + Send;
}

impl<Body> BodyExtractExt for crate::Response<Body>
where
    Body: crate::dep::http_body::Body<Data: Send + 'static, Error: Into<BoxError>> + Send + 'static,
{
    type StreamData = Body::Data;
    type StreamError = Body::Error;

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

    fn into_data_stream(
        self,
    ) -> impl Stream<Item = Result<Self::StreamData, Self::StreamError>> + Send {
        self.into_body().into_data_stream()
    }
}

impl<Body> BodyExtractExt for crate::Request<Body>
where
    Body: crate::dep::http_body::Body<Data: Send + 'static, Error: Into<BoxError>> + Send + 'static,
{
    type StreamData = Body::Data;
    type StreamError = Body::Error;

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

    fn into_data_stream(
        self,
    ) -> impl Stream<Item = Result<Self::StreamData, Self::StreamError>> + Send {
        self.into_body().into_data_stream()
    }
}

impl<B: Into<crate::Body> + Send + 'static> BodyExtractExt for B {
    type StreamData = Bytes;
    type StreamError = BoxError;

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

    fn into_data_stream(
        self,
    ) -> impl Stream<Item = Result<Self::StreamData, Self::StreamError>> + Send {
        let body: crate::Body = self.into();
        body.into_data_stream()
    }
}

mod private {
    pub trait Sealed {}

    impl<Body> Sealed for crate::Response<Body> {}
    impl<Body> Sealed for crate::Request<Body> {}
    impl<B: Into<crate::Body> + Send + 'static> Sealed for B {}
}
