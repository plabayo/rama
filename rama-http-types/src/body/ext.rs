use std::{io, pin::pin};

use super::StreamingBody;
use super::util::{BodyDataStream, BodyExt, BufList, CollectError, CollectOptions};
use rama_core::{
    bytes::{Buf, Bytes},
    error::{BoxError, ErrorContext},
    futures::{
        FutureExt, Stream, StreamExt, TryStreamExt,
        future::{Either, select},
    },
};
use rama_json::capture::{
    CaptureHandler, CaptureResult, CapturedValue, JsonCapturer, OwnedCapturedValue,
};
use rama_json::path::JsonPath;
use rama_utils::octets::kib;
use tokio::sync::mpsc;

/// An extension trait for [`StreamingBody`] that provides methods to extract data from it.
pub trait BodyExtractExt: private::Sealed {
    /// Try to deserialize the (contained) body as a JSON object.
    ///
    /// Buffers the entire body in memory before deserializing. For large bodies prefer
    /// [`BodyExtractExt::try_into_json_streaming`].
    fn try_into_json<T: serde::de::DeserializeOwned + Send + 'static>(
        self,
    ) -> impl Future<Output = Result<T, BoxError>> + Send;

    /// Try to deserialize the (contained) body as a JSON value without first
    /// buffering a large body.
    ///
    /// Bodies up to 16 KiB are parsed in the calling task. Larger bodies are
    /// parsed on a blocking thread while the calling task feeds it frames, so
    /// peak memory stays a few frames. Dropping the returned future stops the
    /// blocking parser at its next read.
    fn try_into_json_streaming<T: serde::de::DeserializeOwned + Send + 'static>(
        self,
    ) -> impl Future<Output = Result<T, BoxError>> + Send;

    /// Capture JSON values matching `selectors` while streaming over the body.
    ///
    /// Unlike [`try_into_json`](Self::try_into_json), this does not buffer the
    /// whole body. Only selected values are copied, and each selected scalar or
    /// object/array subtree is bounded by `max_capture_bytes`.
    fn try_capture_json(
        self,
        selectors: impl IntoIterator<Item = JsonPath> + Send,
        max_capture_bytes: usize,
    ) -> impl Future<Output = Result<Vec<OwnedCapturedValue>, BoxError>> + Send;

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
        String::from_utf8(body.to_vec()).context("parse body as utf-8 string")
    }

    async fn try_capture_json(
        self,
        selectors: impl IntoIterator<Item = JsonPath> + Send,
        max_capture_bytes: usize,
    ) -> Result<Vec<OwnedCapturedValue>, BoxError> {
        let capturer = JsonCapturer::new(selectors, max_capture_bytes, CaptureCollector::default());
        body_capture_json(self.into_body(), capturer)
            .await
            .context("capture selected JSON values from response body")
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
        String::from_utf8(body.to_vec()).context("parse request body as utf-8 string")
    }

    async fn try_capture_json(
        self,
        selectors: impl IntoIterator<Item = JsonPath> + Send,
        max_capture_bytes: usize,
    ) -> Result<Vec<OwnedCapturedValue>, BoxError> {
        let capturer = JsonCapturer::new(selectors, max_capture_bytes, CaptureCollector::default());
        body_capture_json(self.into_body(), capturer)
            .await
            .context("capture selected JSON values from request body")
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
        String::from_utf8(collected_body.to_vec()).context("parse body as utf-8 string")
    }

    async fn try_capture_json(
        self,
        selectors: impl IntoIterator<Item = JsonPath> + Send,
        max_capture_bytes: usize,
    ) -> Result<Vec<OwnedCapturedValue>, BoxError> {
        let capturer = JsonCapturer::new(selectors, max_capture_bytes, CaptureCollector::default());
        body_capture_json(self.into(), capturer)
            .await
            .context("capture selected JSON values from body")
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

#[derive(Debug, Default)]
struct CaptureCollector {
    values: Vec<OwnedCapturedValue>,
}

impl CaptureHandler for CaptureCollector {
    fn handle_capture(&mut self, value: CapturedValue<'_>) -> CaptureResult {
        self.values.push(value.into_owned());
        Ok(())
    }
}

async fn body_capture_json<B>(
    body: B,
    mut capturer: JsonCapturer<CaptureCollector>,
) -> Result<Vec<OwnedCapturedValue>, BoxError>
where
    B: StreamingBody<Data: Send + 'static, Error: Into<BoxError>> + Send + 'static,
{
    let data_stream = crate::body::util::BodyDataStream::new(body);
    let mut data_stream = std::pin::pin!(data_stream);
    while let Some(mut data) = data_stream
        .as_mut()
        .try_next()
        .await
        .map_err(|err| err.into())?
    {
        while data.has_remaining() {
            let chunk = data.chunk();
            let len = chunk.len();
            capturer.write(chunk)?;
            data.advance(len);
        }
    }
    capturer.end()?;
    Ok(capturer.into_handler().values)
}

const JSON_STREAMING_PROBE_LIMIT: usize = kib(16);
const JSON_STREAMING_QUEUED_BATCHES: usize = 2;
const JSON_STREAMING_BATCH_BYTES: usize = kib(64);
const JSON_STREAMING_READ_BUFFER: usize = kib(16);

async fn body_into_json_streaming<B, T>(body: B) -> Result<T, BoxError>
where
    B: StreamingBody<Data = Bytes, Error: Into<BoxError>> + Send + 'static,
    T: serde::de::DeserializeOwned + Send + 'static,
{
    let mut frames = pin!(BodyDataStream::new(body).map_err(|e| io::Error::other(e.into())));
    let mut prefix = BufList::new();
    let mut size = 0usize;
    while size <= JSON_STREAMING_PROBE_LIMIT {
        let Some(frame) = frames.try_next().await.map_err(serde_json::Error::io)? else {
            return Ok(serde_json::from_slice(&prefix.copy_to_bytes(size))?);
        };
        size = size.saturating_add(frame.len());
        prefix.push(frame);
    }
    parse_on_blocking_thread(prefix, frames).await
}

/// Parse on a blocking thread fed by this task, so dropping the future ends the parse.
async fn parse_on_blocking_thread<T>(
    prefix: BufList<Bytes>,
    mut frames: impl Stream<Item = io::Result<Bytes>> + Unpin,
) -> Result<T, BoxError>
where
    T: serde::de::DeserializeOwned + Send + 'static,
{
    let (sender, receiver) = mpsc::channel(JSON_STREAMING_QUEUED_BATCHES);
    let parser = tokio::task::spawn_blocking(move || {
        let frames = FrameReader {
            batches: receiver,
            batch: BufList::new(),
        };
        // serde_json reads byte by byte, and std only has a fast path for that on a BufReader.
        let reader = io::BufReader::with_capacity(JSON_STREAMING_READ_BUFFER, frames);
        serde_json::from_reader::<_, T>(reader)
    });
    // Dropping `forward` drops the sender, so the parser reads end of input and returns.
    let forward = async move {
        let mut batch = prefix;
        let mut batched = batch.remaining();
        loop {
            // Frames already available share one batch, so small frames cost one thread wake.
            let mut end = None;
            while batched < JSON_STREAMING_BATCH_BYTES && end.is_none() {
                match frames.next().now_or_never() {
                    Some(Some(Ok(frame))) => {
                        batched += frame.len();
                        batch.push(frame);
                    }
                    Some(Some(Err(err))) => end = Some(Err(err)),
                    Some(None) => end = Some(Ok(())),
                    None => break,
                }
            }
            if batched == 0 && end.is_none() {
                match frames.next().await {
                    Some(Ok(frame)) => {
                        batched = frame.len();
                        batch.push(frame);
                        continue;
                    }
                    Some(Err(err)) => end = Some(Err(err)),
                    None => return,
                }
            }
            if batched > 0 {
                let full = std::mem::replace(&mut batch, BufList::new());
                batched = 0;
                if sender.send(Ok(full)).await.is_err() {
                    return;
                }
            }
            match end {
                Some(Err(err)) => {
                    _ = sender.send(Err(err)).await;
                    return;
                }
                Some(Ok(())) => return,
                None => (),
            }
        }
    };
    // The parser can finish before the body ends, e.g. on a syntax error.
    let joined = match select(pin!(forward), parser).await {
        Either::Left(((), parser)) => parser.await,
        Either::Right((joined, _)) => joined,
    };
    joined
        .context("join blocking JSON parser")?
        .map_err(BoxError::from)
}

/// Blocking reader over frame batches sent by the task that polls the body.
struct FrameReader {
    batches: mpsc::Receiver<io::Result<BufList<Bytes>>>,
    batch: BufList<Bytes>,
}

impl io::Read for FrameReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        while !self.batch.has_remaining() {
            match self.batches.blocking_recv() {
                Some(batch) => self.batch = batch?,
                None => return Ok(0),
            }
        }
        let len = buf.len().min(self.batch.remaining());
        self.batch.copy_to_slice(&mut buf[..len]);
        Ok(len)
    }
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

    fn streamed(frames: Vec<std::io::Result<Bytes>>) -> Body {
        Body::from_stream(stream::iter(frames))
    }

    #[test]
    fn streaming_json_threshold_with_occupied_blocking_pool() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .max_blocking_threads(1)
            .enable_time()
            .build()
            .unwrap();
        runtime.block_on(async {
            let (release, wait) = std::sync::mpsc::channel::<()>();
            let (started, ready) = tokio::sync::oneshot::channel();
            let occupied = tokio::task::spawn_blocking(move || {
                started.send(()).unwrap();
                wait.recv().unwrap_err();
            });
            ready.await.unwrap();
            let mut prefix = vec![b' '; JSON_STREAMING_PROBE_LIMIT - 1];
            prefix.push(b'1');
            let prefix = Bytes::from(prefix);
            let timeout = std::time::Duration::from_secs(1);
            let small = streamed(vec![Ok(prefix.clone())]).try_into_json_streaming::<u8>();
            assert_eq!(
                tokio::time::timeout(timeout, small).await.unwrap().unwrap(),
                1
            );
            let mut items =
                crate::Response::new(Body::from("[1,2]")).into_json_array_stream::<u8>();
            let read = async {
                assert_eq!(items.next().await.unwrap().unwrap(), 1);
                assert_eq!(items.next().await.unwrap().unwrap(), 2);
                assert!(items.next().await.is_none());
            };
            tokio::time::timeout(timeout, read).await.unwrap();
            let large = streamed(vec![Ok(prefix), Ok(Bytes::from_static(b"2"))])
                .try_into_json_streaming::<u8>();
            let mut large = std::pin::pin!(large);
            tokio::time::timeout(timeout, &mut large).await.unwrap_err();
            drop(release);
            assert_eq!(large.await.unwrap(), 12);
            occupied.await.unwrap();
        });
    }

    #[tokio::test]
    async fn streaming_json_small_frames_preserve_order_on_both_paths() {
        for (len, frame) in [(128, 1), (20_000, 7)] {
            let expected = (0..len).collect::<Vec<u16>>();
            let bytes = Bytes::from(serde_json::to_vec(&expected).unwrap());
            let frames = (0..bytes.len())
                .step_by(frame)
                .map(|i| Ok(bytes.slice(i..(i + frame).min(bytes.len()))))
                .collect();
            assert_eq!(
                streamed(frames)
                    .try_into_json_streaming::<Vec<u16>>()
                    .await
                    .unwrap(),
                expected
            );
        }
    }

    #[test]
    fn streaming_json_reads_a_bounded_amount_ahead_of_a_waiting_parser() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .max_blocking_threads(1)
            .enable_time()
            .build()
            .unwrap();
        runtime.block_on(async {
            // Occupy the only blocking thread so the parser stays queued.
            let (release, wait) = std::sync::mpsc::channel::<()>();
            let (started, ready) = tokio::sync::oneshot::channel();
            let occupied = tokio::task::spawn_blocking(move || {
                started.send(()).unwrap();
                wait.recv().unwrap_err();
            });
            ready.await.unwrap();

            let frame_len = kib(1);
            let frames = 1000;
            let yielded = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let counter = yielded.clone();
            let mut doc = vec![b' '; frames * frame_len - 2];
            doc.extend_from_slice(b"42");
            let doc = Bytes::from(doc);
            let body = Body::from_stream(stream::iter(0..frames).map(move |index| {
                counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                Ok::<_, std::io::Error>(doc.slice(index * frame_len..(index + 1) * frame_len))
            }));
            let read = tokio::spawn(body.try_into_json_streaming::<u8>());
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;

            // Probe prefix, two queued batches and one batch waiting to be sent.
            let ahead = yielded.load(std::sync::atomic::Ordering::Relaxed) * frame_len;
            let bound = JSON_STREAMING_PROBE_LIMIT
                + (JSON_STREAMING_QUEUED_BATCHES + 1) * (JSON_STREAMING_BATCH_BYTES + frame_len);
            assert!(ahead <= bound, "read {ahead} bytes ahead, bound {bound}");
            assert!(
                ahead > JSON_STREAMING_PROBE_LIMIT + JSON_STREAMING_BATCH_BYTES,
                "read only {ahead} bytes ahead, so frames were not batched"
            );

            drop(release);
            occupied.await.unwrap();
            assert_eq!(read.await.unwrap().unwrap(), 42);
        });
    }

    #[tokio::test]
    async fn streaming_json_large_body_with_pauses_between_frames() {
        // Every third frame is pending first, so batches mix ready and awaited frames.
        let expected = (0..20_000).collect::<Vec<u16>>();
        let bytes = Bytes::from(serde_json::to_vec(&expected).unwrap());
        let frames = (0..bytes.len())
            .step_by(500)
            .enumerate()
            .map(move |(n, i)| {
                let frame = bytes.slice(i..(i + 500).min(bytes.len()));
                (n, frame)
            });
        let paced = stream::iter(frames).then(|(n, frame)| async move {
            if n % 3 == 0 {
                tokio::task::yield_now().await;
            }
            Ok::<_, std::io::Error>(frame)
        });
        let decoded = Body::from_stream(paced)
            .try_into_json_streaming::<Vec<u16>>()
            .await
            .unwrap();
        assert_eq!(decoded, expected);
    }

    fn stalled_after(frames: Vec<Bytes>) -> Body {
        Body::from_stream(
            stream::iter(frames.into_iter().map(Ok::<_, std::io::Error>)).chain(stream::pending()),
        )
    }

    #[test]
    fn streaming_json_dropped_large_read_releases_blocking_thread() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .max_blocking_threads(1)
            .enable_time()
            .build()
            .unwrap();
        let released = runtime.block_on(async {
            let large = vec![b' '; JSON_STREAMING_PROBE_LIMIT + 1];
            let read = stalled_after(vec![Bytes::from(large)]).try_into_json_streaming::<u8>();
            let short = std::time::Duration::from_millis(50);
            tokio::time::timeout(short, read).await.unwrap_err();
            let next = tokio::task::spawn_blocking(|| 7);
            let timeout = std::time::Duration::from_secs(5);
            matches!(tokio::time::timeout(timeout, next).await, Ok(Ok(7)))
        });
        // A parser still pinned to the thread would make a normal drop wait forever.
        runtime.shutdown_background();
        assert!(released, "dropped read kept the only blocking thread");
    }

    #[tokio::test]
    async fn streaming_json_stops_polling_body_after_error() {
        let frames = stream::iter([
            Ok(Bytes::from(vec![b' '; JSON_STREAMING_PROBE_LIMIT + 1])),
            Err(std::io::Error::other("body interrupted")),
        ])
        .chain(stream::poll_fn(|_| -> std::task::Poll<Option<_>> {
            panic!("body polled after its error")
        }));
        let err = Body::from_stream(frames)
            .try_into_json_streaming::<u8>()
            .await
            .unwrap_err();
        assert!(format!("{err:?}").contains("body interrupted"));
    }

    #[tokio::test]
    async fn streaming_json_parse_error_does_not_wait_for_stalled_body() {
        let frames = vec![
            Bytes::from(vec![b' '; JSON_STREAMING_PROBE_LIMIT + 1]),
            Bytes::from_static(b"?"),
        ];
        let read = stalled_after(frames).try_into_json_streaming::<u8>();
        let timeout = std::time::Duration::from_secs(5);
        tokio::time::timeout(timeout, read)
            .await
            .unwrap()
            .unwrap_err();
    }

    #[tokio::test]
    async fn streaming_json_large_first_frame() {
        let frames = vec![
            Ok(Bytes::from(vec![b' '; JSON_STREAMING_PROBE_LIMIT + 1])),
            Ok(Bytes::from_static(b"42")),
        ];
        assert_eq!(
            streamed(frames)
                .try_into_json_streaming::<u8>()
                .await
                .unwrap(),
            42
        );
    }

    #[tokio::test]
    async fn streaming_json_errors_on_both_paths() {
        for padding in [0, JSON_STREAMING_PROBE_LIMIT + 1] {
            let prefix = Bytes::from(vec![b' '; padding]);
            for invalid in [b"".as_slice(), b"?", b"1 x"] {
                let body = streamed(vec![Ok(prefix.clone()), Ok(Bytes::from_static(invalid))]);
                body.try_into_json_streaming::<u8>().await.unwrap_err();
            }
            let body = streamed(vec![
                Ok(prefix),
                Err(std::io::Error::other("body interrupted")),
            ]);
            let err = body.try_into_json_streaming::<u8>().await.unwrap_err();
            assert!(format!("{err:?}").contains("body interrupted"));
        }
    }

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
    async fn capture_json_selected_values_across_frames() {
        let chunks: Vec<Result<Bytes, std::io::Error>> = vec![
            Ok(Bytes::from_static(br#"{"items":[{"id":"#)),
            Ok(Bytes::from_static(br#"1},{"id":2}],"ok":true}"#)),
        ];
        let body = Body::from_stream(stream::iter(chunks));
        let selectors = [JsonPath::builder()
            .member("items")
            .wildcard()
            .member("id")
            .build()];

        let values = body.try_capture_json(selectors, 32).await.unwrap();
        assert_eq!(values.len(), 2);
        assert_eq!(values[0].path().to_string(), "$.items[0].id");
        assert_eq!(values[0].as_u8(), Some(1));
        assert_eq!(values[1].path().to_string(), "$.items[1].id");
        assert_eq!(values[1].deserialize::<u8>().unwrap(), 2);
    }

    #[tokio::test]
    async fn request_capture_json_selected_values() {
        let req = crate::Request::new(Body::from(br#"{"name":"Ada"}"#.as_slice()));
        let selectors = [JsonPath::builder().member("name").build()];

        let values = req.try_capture_json(selectors, 32).await.unwrap();
        assert_eq!(values.len(), 1);
        assert_eq!(values[0].path().to_string(), "$.name");
        assert_eq!(values[0].as_str().as_deref(), Some("Ada"));
    }

    #[tokio::test]
    async fn response_capture_json_selected_values() {
        let res = crate::Response::new(Body::from(br#"{"name":"Ada"}"#.as_slice()));
        let selectors = [JsonPath::builder().member("name").build()];

        let values = res.try_capture_json(selectors, 32).await.unwrap();
        assert_eq!(values.len(), 1);
        assert_eq!(values[0].path().to_string(), "$.name");
        assert_eq!(values[0].as_str().as_deref(), Some("Ada"));
    }

    #[tokio::test]
    async fn capture_json_reports_capture_limit() {
        let body = Body::from(br#"{"item":{"name":"Ada"}}"#.as_slice());
        let selectors = [JsonPath::builder().member("item").build()];

        let err = body.try_capture_json(selectors, 8).await.unwrap_err();
        assert!(err.to_string().contains("capture limit"));
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
