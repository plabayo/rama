use super::StreamingBody;
use super::util::BodyExt;
use rama_core::error::{BoxError, ErrorContext};

/// An extension trait for [`StreamingBody`] that provides methods to extract data from it.
pub trait BodyExtractExt: private::Sealed {
    /// Try to deserialize the (contained) body as a JSON object.
    ///
    /// Buffers the entire body in memory before deserializing. For large bodies prefer
    /// [`BodyExtractExt::try_into_json_streaming`].
    fn try_into_json<T: serde::de::DeserializeOwned + Send + 'static>(
        self,
    ) -> impl Future<Output = Result<T, BoxError>> + Send;

    /// Try to deserialize the (contained) body as a JSON object, streaming bytes
    /// from the body directly into the JSON parser instead of buffering the whole
    /// body first.
    ///
    /// Preferable to [`BodyExtractExt::try_into_json`] for large bodies where peak
    /// memory matters.
    ///
    /// # Note
    ///
    /// Internally this runs `serde_json::from_reader` inside a
    /// [`tokio::task::spawn_blocking`] task using [`SyncIoBridge`] to bridge the
    /// async body to serde's synchronous `io::Read` interface. The thread hop is
    /// unavoidable today because [`serde::Deserialize`] is a pull-based,
    /// synchronous trait and no production-ready async-first JSON crate currently
    /// ships a drop-in `serde::Deserialize` integration. Contributions that
    /// remove this hop — e.g. by building a `serde::Deserializer` on top of an
    /// async event-based JSON parser — are welcome.
    ///
    /// [`SyncIoBridge`]: rama_core::stream::io::SyncIoBridge
    fn try_into_json_streaming<T: serde::de::DeserializeOwned + Send + 'static>(
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

    async fn try_into_json_streaming<T: serde::de::DeserializeOwned + Send + 'static>(
        self,
    ) -> Result<T, BoxError> {
        body_into_json_streaming(self.into_body())
            .await
            .context("streaming-deserialize response body as JSON")
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

    async fn try_into_json_streaming<T: serde::de::DeserializeOwned + Send + 'static>(
        self,
    ) -> Result<T, BoxError> {
        body_into_json_streaming(self.into_body())
            .await
            .context("streaming-deserialize request body as JSON")
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

    async fn try_into_json_streaming<T: serde::de::DeserializeOwned + Send + 'static>(
        self,
    ) -> Result<T, BoxError> {
        body_into_json_streaming(self.into())
            .await
            .context("streaming-deserialize body as JSON")
    }

    async fn try_into_string(self) -> Result<String, BoxError> {
        let body = self.into();
        let collected_body = body.collect().await.context("collect body")?;
        let bytes = collected_body.to_bytes();
        String::from_utf8(bytes.to_vec()).context("parse body as utf-8 string")
    }
}

/// Drive a body's data frames through an `AsyncRead` and into
/// `serde_json::from_reader`, running the sync deserializer on a blocking
/// task. See [`BodyExtractExt::try_into_json_streaming`] for rationale.
async fn body_into_json_streaming<B, T>(body: B) -> Result<T, BoxError>
where
    B: StreamingBody<Data: Send + 'static, Error: Into<BoxError>> + Send + 'static,
    T: serde::de::DeserializeOwned + Send + 'static,
{
    use rama_core::futures::TryStreamExt;
    use rama_core::stream::io::{StreamReader, SyncIoBridge};

    // `http_body::Body::Data: Buf` is a supertrait bound, so the data-frame
    // stream items implement `Buf` and can feed `StreamReader` directly.
    let data_stream =
        crate::body::util::BodyDataStream::new(body).map_err(|e| std::io::Error::other(e.into()));
    let async_reader = StreamReader::new(Box::pin(data_stream));

    tokio::task::spawn_blocking(move || {
        let reader = SyncIoBridge::new(async_reader);
        serde_json::from_reader::<_, T>(reader).map_err(BoxError::from)
    })
    .await
    .map_err(BoxError::from)?
}

mod private {
    pub trait Sealed {}

    impl<Body> Sealed for crate::Response<Body> {}
    impl<Body> Sealed for crate::Request<Body> {}
    impl<B: Into<crate::Body> + Send + 'static> Sealed for B {}
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Body;
    use rama_core::bytes::Bytes;
    use rama_core::futures::stream;

    #[derive(Debug, serde::Deserialize, PartialEq, Eq)]
    struct Foo {
        name: String,
        age: u8,
    }

    /// Build a body from multiple `Bytes` chunks so we actually exercise the
    /// streaming path (split-across-frames JSON).
    ///
    /// Uses the multi_thread flavor because `SyncIoBridge` calls
    /// `Handle::block_on` on the blocking task — that needs runtime workers
    /// to be available on another thread.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn streaming_json_across_frames() {
        let chunks: Vec<Result<Bytes, std::io::Error>> = vec![
            Ok(Bytes::from_static(b"{\"name\":")),
            Ok(Bytes::from_static(b"\"alice\",\"age\"")),
            Ok(Bytes::from_static(b":42}")),
        ];
        let body = Body::from_stream(stream::iter(chunks));

        let foo: Foo = body.try_into_json_streaming().await.unwrap();
        assert_eq!(
            foo,
            Foo {
                name: "alice".to_owned(),
                age: 42,
            }
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn streaming_json_invalid_payload() {
        let body = Body::from("not actually json");
        let result: Result<serde_json::Value, _> = body.try_into_json_streaming().await;
        result.unwrap_err();
    }
}
