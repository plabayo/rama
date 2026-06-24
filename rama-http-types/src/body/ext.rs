use super::StreamingBody;
use super::util::{BodyExt, CollectError, CollectOptions};
use rama_core::bytes::Bytes;
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

    /// Like [`try_into_json`](Self::try_into_json), but bounded by `opts` (a size
    /// cap and/or timeout).
    ///
    /// On success returns the decoded value. Otherwise a [`CollectError`] tells
    /// you why — cap reached, timed out, stream failure, or decode failure — and
    /// for everything but a stream failure [`CollectError::into_full_body`] hands
    /// the body back so it can be forwarded on untouched (handy for proxies).
    ///
    /// Unlike wrapping the body in [`Limited`], hitting the cap here does not
    /// destroy the body.
    ///
    /// [`Limited`]: crate::body::util::Limited
    /// [`CollectError::into_full_body`]: crate::body::util::CollectError::into_full_body
    fn try_into_json_with<T: serde::de::DeserializeOwned + Send + 'static>(
        self,
        opts: CollectOptions,
    ) -> impl Future<Output = Result<T, CollectError>> + Send;

    /// Like [`try_into_string`](Self::try_into_string), but bounded by `opts`.
    /// See [`try_into_json_with`](Self::try_into_json_with) for the error semantics.
    fn try_into_string_with(
        self,
        opts: CollectOptions,
    ) -> impl Future<Output = Result<String, CollectError>> + Send;
}

impl<Body> BodyExtractExt for crate::Response<Body>
where
    Body: StreamingBody<Data = Bytes, Error: Into<BoxError>> + Send + Sync + 'static,
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

    async fn try_into_json_with<T: serde::de::DeserializeOwned + Send + 'static>(
        self,
        opts: CollectOptions,
    ) -> Result<T, CollectError> {
        body_into_json_with(crate::Body::new(self.into_body()), opts).await
    }

    async fn try_into_string_with(self, opts: CollectOptions) -> Result<String, CollectError> {
        body_into_string_with(crate::Body::new(self.into_body()), opts).await
    }
}

impl<Body> BodyExtractExt for crate::Request<Body>
where
    Body: StreamingBody<Data = Bytes, Error: Into<BoxError>> + Send + Sync + 'static,
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

    async fn try_into_json_with<T: serde::de::DeserializeOwned + Send + 'static>(
        self,
        opts: CollectOptions,
    ) -> Result<T, CollectError> {
        body_into_json_with(crate::Body::new(self.into_body()), opts).await
    }

    async fn try_into_string_with(self, opts: CollectOptions) -> Result<String, CollectError> {
        body_into_string_with(crate::Body::new(self.into_body()), opts).await
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

    async fn try_into_json_with<T: serde::de::DeserializeOwned + Send + 'static>(
        self,
        opts: CollectOptions,
    ) -> Result<T, CollectError> {
        body_into_json_with(self.into(), opts).await
    }

    async fn try_into_string_with(self, opts: CollectOptions) -> Result<String, CollectError> {
        body_into_string_with(self.into(), opts).await
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

/// Collect `body` within `opts`, then JSON-decode the buffered bytes. A decode
/// failure surfaces as a [`CollectError`] with the full body still recoverable.
async fn body_into_json_with<T: serde::de::DeserializeOwned + Send + 'static>(
    body: crate::Body,
    opts: CollectOptions,
) -> Result<T, CollectError> {
    let bytes = body.collect_with(opts).await?.to_bytes();
    match serde_json::from_slice::<T>(bytes.as_ref()) {
        Ok(value) => Ok(value),
        Err(err) => Err(CollectError::decode(bytes, err.into())),
    }
}

/// Collect `body` within `opts`, then UTF-8 decode the buffered bytes. A decode
/// failure surfaces as a [`CollectError`] with the full body still recoverable.
async fn body_into_string_with(
    body: crate::Body,
    opts: CollectOptions,
) -> Result<String, CollectError> {
    let bytes = body.collect_with(opts).await?.to_bytes();
    match std::str::from_utf8(bytes.as_ref()) {
        Ok(s) => Ok(s.to_owned()),
        Err(err) => Err(CollectError::decode(bytes, err.into())),
    }
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

    #[tokio::test]
    async fn try_into_string_with_complete() {
        let body = Body::from("hello");
        let s = body
            .try_into_string_with(CollectOptions::new().with_max_size(100))
            .await
            .unwrap();
        assert_eq!(s, "hello");
    }

    #[tokio::test]
    async fn try_into_string_with_cap_returns_passthrough_body() {
        let body = Body::from("hello world");
        let err = body
            .try_into_string_with(CollectOptions::new().with_max_size(5))
            .await
            .unwrap_err();
        assert!(err.is_cap_reached());
        let full = err.into_full_body().unwrap();
        assert_eq!(full.try_into_string().await.unwrap(), "hello world");
    }

    #[tokio::test]
    async fn try_into_string_with_invalid_utf8_is_decode_error() {
        let body = Body::from(vec![0xff_u8, 0xfe, 0xfd]);
        let err = body
            .try_into_string_with(CollectOptions::new().with_max_size(1024))
            .await
            .unwrap_err();
        assert!(err.is_decode_error());
        assert_eq!(err.bytes_read().to_vec(), vec![0xff, 0xfe, 0xfd]);
    }

    #[tokio::test]
    async fn try_into_json_with_complete() {
        let body = Body::from(r#"{"name":"alice","age":42}"#);
        let foo: Foo = body
            .try_into_json_with(CollectOptions::new().with_max_size(1024))
            .await
            .unwrap();
        assert_eq!(
            foo,
            Foo {
                name: "alice".to_owned(),
                age: 42,
            }
        );
    }

    #[tokio::test]
    async fn try_into_json_with_cap_returns_passthrough_body() {
        let body = Body::from(r#"{"name":"alice","age":42}"#);
        let err = body
            .try_into_json_with::<Foo>(CollectOptions::new().with_max_size(5))
            .await
            .unwrap_err();
        assert!(err.is_cap_reached());
        let recovered = err
            .into_full_body()
            .unwrap()
            .try_into_string()
            .await
            .unwrap();
        assert_eq!(recovered, r#"{"name":"alice","age":42}"#);
    }

    #[tokio::test]
    async fn try_into_json_with_decode_error_recovers_full_body() {
        let body = Body::from("not json");
        let err = body
            .try_into_json_with::<Foo>(CollectOptions::new().with_max_size(1024))
            .await
            .unwrap_err();
        assert!(err.is_decode_error());
        let recovered = err
            .into_full_body()
            .unwrap()
            .try_into_string()
            .await
            .unwrap();
        assert_eq!(recovered, "not json");
    }
}
