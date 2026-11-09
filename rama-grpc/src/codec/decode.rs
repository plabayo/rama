use std::{
    fmt, future,
    pin::Pin,
    task::ready,
    task::{Context, Poll},
};

use sync_wrapper::SyncWrapper;

use rama_core::{
    bytes::{Buf, BufMut, Bytes, BytesMut},
    error::BoxError,
    futures::Stream,
    telemetry::tracing::{debug, trace},
};
use rama_http_types::{Body, HeaderMap, StatusCode, StreamingBody, body::util::BodyExt as _};

use super::compression::{CompressionEncoding, CompressionSettings, decompress};
use super::{BufferSettings, DEFAULT_MAX_RECV_MESSAGE_SIZE, DecodeBuf, Decoder, HEADER_SIZE};
use crate::{Code, Status, metadata::MetadataMap};

/// Streaming requests and responses.
///
/// This will wrap some inner [`Body`] and [`Decoder`] and provide an interface
/// to fetch the message stream and trailing metadata
pub struct Streaming<T> {
    decoder: SyncWrapper<Box<dyn Decoder<Item = T, Error = Status> + Send + 'static>>,
    inner: StreamingInner,
}

struct StreamingInner {
    body: SyncWrapper<Body>,
    state: State,
    direction: Direction,
    /// Unread bytes of the last received data frame; whole messages are split off it.
    chunk: Bytes,
    /// The current message, split off `chunk` without copying.
    message: Option<Bytes>,
    /// Assembles a header or message received across data frames.
    buf: BytesMut,
    buffer_size: usize,
    trailers: Option<HeaderMap>,
    decompress_buf: BytesMut,
    encoding: Option<CompressionEncoding>,
    max_message_size: Option<usize>,
}

impl<T> Unpin for Streaming<T> {}

#[derive(Debug, Clone)]
enum State {
    ReadHeader,
    ReadBody {
        compression: Option<CompressionEncoding>,
        len: usize,
    },
    Error(Option<Status>),
}

#[derive(Debug, PartialEq, Eq)]
enum Direction {
    Request,
    Response(StatusCode),
    EmptyResponse,
}

impl<T> Streaming<T> {
    /// Create a new streaming response in the grpc response format for decoding a response [Body]
    /// into message of type T
    pub fn new_response<B, D>(
        decoder: D,
        body: B,
        status_code: StatusCode,
        encoding: Option<CompressionEncoding>,
        max_message_size: Option<usize>,
    ) -> Self
    where
        B: StreamingBody<Error: Into<BoxError>> + Send + Sync + 'static,
        D: Decoder<Item = T, Error = Status> + Send + 'static,
    {
        Self::new(
            decoder,
            body,
            Direction::Response(status_code),
            encoding,
            max_message_size,
        )
    }

    /// Create empty response. For creating responses that have no content (headers + trailers only)
    pub fn new_empty<B, D>(decoder: D, body: B) -> Self
    where
        B: StreamingBody<Error: Into<BoxError>> + Send + Sync + 'static,
        D: Decoder<Item = T, Error = Status> + Send + 'static,
    {
        Self::new(decoder, body, Direction::EmptyResponse, None, None)
    }

    /// Create a new streaming request in the grpc response format for decoding a request [Body]
    /// into message of type T
    pub fn new_request<B, D>(
        decoder: D,
        body: B,
        encoding: Option<CompressionEncoding>,
        max_message_size: Option<usize>,
    ) -> Self
    where
        B: StreamingBody<Error: Into<BoxError>> + Send + Sync + 'static,
        D: Decoder<Item = T, Error = Status> + Send + 'static,
    {
        Self::new(
            decoder,
            body,
            Direction::Request,
            encoding,
            max_message_size,
        )
    }

    fn new<B, D>(
        decoder: D,
        body: B,
        direction: Direction,
        encoding: Option<CompressionEncoding>,
        max_message_size: Option<usize>,
    ) -> Self
    where
        B: StreamingBody<Error: Into<BoxError>> + Send + Sync + 'static,
        D: Decoder<Item = T, Error = Status> + Send + 'static,
    {
        let buffer_size = decoder.buffer_settings().buffer_size;
        Self {
            decoder: SyncWrapper::new(Box::new(decoder)),
            inner: StreamingInner {
                body: SyncWrapper::new(Body::new(
                    body.map_frame(|frame| {
                        frame.map_data(|mut buf| buf.copy_to_bytes(buf.remaining()))
                    })
                    .map_err(|err| Status::map_error(err.into())),
                )),
                state: State::ReadHeader,
                direction,
                chunk: Bytes::new(),
                message: None,
                buf: BytesMut::new(),
                buffer_size,
                trailers: None,
                decompress_buf: BytesMut::new(),
                encoding,
                max_message_size,
            },
        }
    }
}

impl StreamingInner {
    fn decode_chunk(
        &mut self,
        buffer_settings: BufferSettings,
    ) -> Result<Option<DecodeBuf<'_>>, Status> {
        if matches!(self.state, State::ReadHeader) {
            let mut header = [0; HEADER_SIZE];
            if self.buf.is_empty() && self.chunk.len() >= HEADER_SIZE {
                self.chunk.copy_to_slice(&mut header);
            } else {
                self.assemble(HEADER_SIZE);
                if self.buf.len() < HEADER_SIZE {
                    return Ok(None);
                }
                self.buf.copy_to_slice(&mut header);
            }
            let [compression_flag, len @ ..] = header;
            let len = u32::from_be_bytes(len) as usize;

            let compression_encoding = match compression_flag {
                0 => None,
                1 => {
                    {
                        if self.encoding.is_some() {
                            self.encoding
                        } else {
                            // https://grpc.github.io/grpc/core/md_doc_compression.html
                            // An ill-constructed message with its Compressed-Flag bit set but lacking a grpc-encoding
                            // entry different from identity in its metadata MUST fail with INTERNAL status,
                            // its associated description indicating the invalid Compressed-Flag condition.
                            return Err(Status::internal(
                                "protocol error: received message with compressed-flag but no grpc-encoding was specified",
                            ));
                        }
                    }
                }
                f => {
                    trace!("unexpected compression flag");
                    let message = if let Direction::Response(status) = self.direction {
                        format!(
                            "protocol error: received message with invalid compression flag: {f} (valid flags are 0 and 1) while receiving response with status: {status}"
                        )
                    } else {
                        format!(
                            "protocol error: received message with invalid compression flag: {f} (valid flags are 0 and 1), while sending request"
                        )
                    };
                    return Err(Status::internal(message));
                }
            };

            let limit = self
                .max_message_size
                .unwrap_or(DEFAULT_MAX_RECV_MESSAGE_SIZE);
            if len > limit {
                return Err(Status::out_of_range(format!(
                    "Error, decoded message length too large: found {len} bytes, the limit is: {limit} bytes"
                )));
            }

            self.state = State::ReadBody {
                compression: compression_encoding,
                len,
            }
        }

        if let State::ReadBody { len, compression } = self.state {
            if self.message.is_none() {
                if self.buf.is_empty() && self.chunk.len() >= len {
                    self.message = Some(self.chunk.split_to(len));
                } else {
                    self.assemble(len);
                    // if we haven't read enough of the message then return and keep
                    // reading
                    if self.buf.len() < len {
                        return Ok(None);
                    }
                    // Handing over the whole buffer spares a shared copy of its allocation.
                    if self.buf.len() == len {
                        self.message = Some(std::mem::take(&mut self.buf).freeze());
                    }
                }
            }

            let decode_buf = if let Some(encoding) = compression {
                self.decompress_buf.clear();
                let limit = self
                    .max_message_size
                    .unwrap_or(DEFAULT_MAX_RECV_MESSAGE_SIZE);
                let limited_out_buf = (&mut self.decompress_buf).limit(limit);

                let compressed = match &self.message {
                    Some(message) => message.as_ref(),
                    None => &self.buf[..len],
                };
                let decompressed = decompress(
                    CompressionSettings {
                        encoding,
                        buffer_growth_interval: buffer_settings.buffer_size,
                    },
                    compressed,
                    limited_out_buf,
                );
                if self.message.take().is_none() {
                    self.buf.advance(len);
                }
                if let Err(err) = decompressed {
                    if matches!(err.kind(), std::io::ErrorKind::WriteZero) {
                        return Err(Status::resource_exhausted(format!(
                            "Error decompressing: size limit, of {limit} bytes, exceeded while decompressing message"
                        )));
                    }
                    let message = if let Direction::Response(status) = self.direction {
                        format!(
                            "Error decompressing: {err}, while receiving response with status: {status}"
                        )
                    } else {
                        format!("Error decompressing: {err}, while sending request")
                    };
                    return Err(Status::internal(message));
                }
                let decompressed_len = self.decompress_buf.len();
                DecodeBuf::new(&mut self.decompress_buf, decompressed_len)
            } else if let Some(message) = &mut self.message {
                DecodeBuf::from_bytes(message, len)
            } else {
                DecodeBuf::new(&mut self.buf, len)
            };

            return Ok(Some(decode_buf));
        }

        Ok(None)
    }

    /// Moves bytes from `chunk` into `buf` until it holds `len` bytes or `chunk` runs out;
    /// only a header or message received across data frames is copied.
    fn assemble(&mut self, len: usize) {
        let missing = len.saturating_sub(self.buf.len());
        let needed = missing.min(self.chunk.len());
        if needed == 0 {
            return;
        }
        // The buffer grows with what arrives: a declared length alone never sizes it.
        self.buf.reserve(needed.max(missing.min(self.buffer_size)));
        self.buf.extend_from_slice(&self.chunk[..needed]);
        self.chunk.advance(needed);
    }

    // Returns Some(()) if data was found or None if the loop in `poll_next` should break
    fn poll_frame(&mut self, cx: &mut Context<'_>) -> Poll<Result<Option<()>, Status>> {
        let frame = match ready!(Pin::new(self.body.get_mut()).poll_frame(cx)) {
            Some(Ok(frame)) => frame,
            Some(Err(err)) => {
                let status = Status::from_error(err);

                if self.direction == Direction::Request && status.code() == Code::Cancelled {
                    return Poll::Ready(Ok(None));
                }

                _ = std::mem::replace(&mut self.state, State::Error(Some(status.clone())));
                debug!("decoder inner stream error: {:?}", status);
                return Poll::Ready(Err(status));
            }
            None => {
                // FIXME: improve buf usage.
                return Poll::Ready(if self.buf.has_remaining() || self.chunk.has_remaining() {
                    trace!("unexpected EOF decoding stream, state: {:?}", self.state);
                    Err(Status::internal("Unexpected EOF decoding stream."))
                } else {
                    Ok(None)
                });
            }
        };

        Poll::Ready(match frame.into_data() {
            Ok(data) => {
                // Bytes left in `chunk` belong before the new frame.
                if self.chunk.has_remaining() {
                    let rest = std::mem::take(&mut self.chunk);
                    self.buf.put(rest);
                }
                self.chunk = data;
                Ok(Some(()))
            }
            Err(frame) => match frame.into_trailers() {
                Ok(frame_trailers) => {
                    if let Some(trailers) = &mut self.trailers {
                        trailers.extend(frame_trailers);
                    } else {
                        self.trailers = Some(frame_trailers);
                    }
                    Ok(None)
                }
                Err(frame) => {
                    trace!("unexpected frame: {frame:?}");
                    Err(Status::internal("decode: unexpected frame"))
                }
            },
        })
    }

    fn response(&mut self) -> Result<(), Status> {
        if let Direction::Response(status) = self.direction
            && let Err(Some(e)) = crate::status::infer_grpc_status(self.trailers.as_ref(), status)
        {
            // If the trailers contain a grpc-status, then we should return that as the error
            // and otherwise stop the stream (by taking the error state)
            self.trailers.take();
            return Err(e);
        }
        Ok(())
    }
}

impl<T> Streaming<T> {
    /// Fetch the next message from this stream.
    ///
    /// # Return value
    ///
    /// - `Result::Err(val)` means a gRPC error was sent by the sender instead
    ///   of a valid response message. Refer to [`Status::code`] and
    ///   [`Status::message`] to examine possible error causes.
    ///
    /// - `Result::Ok(None)` means the stream was closed by the sender and no
    ///   more messages will be delivered. Further attempts to call
    ///   [`Streaming::message`] will result in the same return value.
    ///
    /// - `Result::Ok(Some(val))` means the sender streamed a valid response
    ///   message `val`.
    ///
    /// ```rust
    /// # use rama_grpc::{Streaming, Status, codec::Decoder};
    /// # use std::fmt::Debug;
    /// # async fn next_message_ex<T, D>(mut request: Streaming<T>) -> Result<(), Status>
    /// # where T: Debug,
    /// # D: Decoder<Item = T, Error = Status> + Send  + 'static,
    /// # {
    /// if let Some(next_message) = request.message().await? {
    ///     println!("{:?}", next_message);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub async fn message(&mut self) -> Result<Option<T>, Status> {
        match future::poll_fn(|cx| Pin::new(&mut *self).poll_next(cx)).await {
            Some(Ok(m)) => Ok(Some(m)),
            Some(Err(e)) => Err(e),
            None => Ok(None),
        }
    }

    /// Fetch the trailing metadata.
    ///
    /// This will drain the stream of all its messages to receive the trailing
    /// metadata. If [`Streaming::message`] returns `None` then this function
    /// will not need to poll for trailers since the body was totally consumed.
    ///
    /// ```rust
    /// # use rama_grpc::{Streaming, Status};
    /// # async fn trailers_ex<T>(mut request: Streaming<T>) -> Result<(), Status> {
    /// if let Some(metadata) = request.trailers().await? {
    ///     println!("{:?}", metadata);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub async fn trailers(&mut self) -> Result<Option<MetadataMap>, Status> {
        // Shortcut to see if we already pulled the trailers in the stream step
        // we need to do that so that the stream can error on trailing grpc-status
        if let Some(trailers) = self.inner.trailers.take() {
            return Ok(Some(MetadataMap::from_headers(trailers)));
        }

        // To fetch the trailers we must clear the body and drop it.
        while self.message().await?.is_some() {}

        // Since we call poll_trailers internally on poll_next we need to
        // check if it got cached again.
        if let Some(trailers) = self.inner.trailers.take() {
            return Ok(Some(MetadataMap::from_headers(trailers)));
        }

        // We've polled through all the frames, and still no trailers, return None
        Ok(None)
    }

    fn decode_chunk(&mut self) -> Result<Option<T>, Status> {
        match self
            .inner
            .decode_chunk(self.decoder.get_mut().buffer_settings())?
        {
            Some(mut decode_buf) => match self.decoder.get_mut().decode(&mut decode_buf)? {
                Some(msg) => {
                    self.inner.state = State::ReadHeader;
                    self.inner.message = None;
                    Ok(Some(msg))
                }
                None => Ok(None),
            },
            None => Ok(None),
        }
    }
}

impl<T> Stream for Streaming<T> {
    type Item = Result<T, Status>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        loop {
            // When the stream encounters an error yield that error once and then on subsequent
            // calls to poll_next return Poll::Ready(None) indicating that the stream has been
            // fully exhausted.
            if let State::Error(status) = &mut self.inner.state {
                return Poll::Ready(status.take().map(Err));
            }

            if let Some(item) = self.decode_chunk()? {
                return Poll::Ready(Some(Ok(item)));
            }

            if ready!(self.inner.poll_frame(cx))?.is_none() {
                match self.inner.response() {
                    Ok(()) => return Poll::Ready(None),
                    Err(err) => self.inner.state = State::Error(Some(err)),
                }
            }
        }
    }
}

impl<T> fmt::Debug for Streaming<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Streaming").finish()
    }
}

#[cfg(test)]
static_assertions::assert_impl_all!(Streaming<()>: Send, Sync);

#[cfg(test)]
mod tests {
    use quickcheck_macros::quickcheck;
    use rama_core::futures::stream;

    #[cfg(feature = "compression")]
    use super::super::compression::compress;
    use super::*;

    /// Hands out each message as received.
    struct Raw;

    impl Decoder for Raw {
        type Item = Bytes;
        type Error = Status;

        fn decode(&mut self, src: &mut DecodeBuf<'_>) -> Result<Option<Bytes>, Status> {
            Ok(Some(src.copy_to_bytes(src.remaining())))
        }
    }

    fn frame(flag: u8, message: &[u8]) -> Vec<u8> {
        let mut frame = vec![flag];
        frame.extend_from_slice(&(message.len() as u32).to_be_bytes());
        frame.extend_from_slice(message);
        frame
    }

    fn streaming(chunks: Vec<Bytes>, encoding: Option<CompressionEncoding>) -> Streaming<Bytes> {
        let body = Body::from_stream(stream::iter(chunks.into_iter().map(Ok::<_, BoxError>)));
        Streaming::new_request(Raw, body, encoding, None)
    }

    async fn collect(mut streaming: Streaming<Bytes>) -> Result<Vec<Bytes>, Status> {
        let mut messages = Vec::new();
        while let Some(message) = streaming.message().await? {
            messages.push(message);
        }
        Ok(messages)
    }

    /// Splits `wire` into chunks of the given sizes, the rest going into a last chunk.
    fn split(wire: &[u8], sizes: &[u8]) -> Vec<Bytes> {
        let mut wire = Bytes::copy_from_slice(wire);
        let mut chunks = Vec::new();
        for &size in sizes {
            let size = usize::from(size).max(1).min(wire.len());
            if size == 0 {
                break;
            }
            chunks.push(wire.split_to(size));
        }
        if !wire.is_empty() {
            chunks.push(wire);
        }
        chunks
    }

    #[quickcheck]
    #[expect(
        clippy::needless_pass_by_value,
        reason = "quickcheck generates owned inputs"
    )]
    fn messages_survive_any_chunking(messages: Vec<Vec<u8>>, sizes: Vec<u8>) -> bool {
        let wire: Vec<u8> = messages.iter().flat_map(|m| frame(0, m)).collect();
        let decoded = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap()
            .block_on(collect(streaming(split(&wire, &sizes), None)));
        decoded.unwrap() == messages
    }

    #[tokio::test]
    async fn messages_received_whole_share_the_received_bytes() {
        let wire = Bytes::from([frame(0, b"first"), frame(0, b"second")].concat());
        let messages = collect(streaming(vec![wire.clone()], None)).await.unwrap();
        assert_eq!(messages, [&b"first"[..], &b"second"[..]]);
        assert_eq!(messages[0].as_ptr(), wire[HEADER_SIZE..].as_ptr());
        assert_eq!(messages[1].as_ptr(), wire[2 * HEADER_SIZE + 5..].as_ptr());
    }

    #[tokio::test]
    async fn header_and_message_across_frames() {
        let wire = [frame(0, b"split"), frame(0, b"whole")].concat();
        // the first header spans two frames, its message a third
        let chunks = split(&wire, &[2, 6]);
        let messages = collect(streaming(chunks, None)).await.unwrap();
        assert_eq!(messages, [&b"split"[..], &b"whole"[..]]);
    }

    #[tokio::test]
    async fn truncated_message_is_an_error() {
        let wire = frame(0, b"truncated");
        let chunks = vec![Bytes::copy_from_slice(&wire[..wire.len() - 1])];
        let status = collect(streaming(chunks, None)).await.unwrap_err();
        assert_eq!(status.code(), Code::Internal);
    }

    #[tokio::test]
    async fn message_above_the_limit_is_refused() {
        let mut wire = vec![0];
        wire.extend_from_slice(&u32::MAX.to_be_bytes());
        let status = collect(streaming(vec![Bytes::from(wire)], None))
            .await
            .unwrap_err();
        assert_eq!(status.code(), Code::OutOfRange);
    }

    #[cfg(feature = "compression")]
    #[tokio::test]
    async fn compressed_messages_whole_or_across_frames() {
        let mut compressed = BytesMut::new();
        let mut plain = BytesMut::from(&b"compressed message"[..]);
        let len = plain.len();
        compress(
            CompressionSettings {
                encoding: CompressionEncoding::Gzip,
                buffer_growth_interval: 64,
            },
            &mut plain,
            &mut compressed,
            len,
        )
        .unwrap();
        let wire = [frame(1, &compressed), frame(1, &compressed)].concat();
        for chunks in [vec![Bytes::from(wire.clone())], split(&wire, &[3, 7, 11])] {
            let messages = collect(streaming(chunks, Some(CompressionEncoding::Gzip)))
                .await
                .unwrap();
            assert_eq!(messages, [&b"compressed message"[..]; 2]);
        }
    }
}
