use crate::HeaderMap;
use crate::layer::compression::pin_project_cfg::pin_project_cfg;
use crate::layer::util::compression::CompressionLevel;

use compression_codecs::{
    BrotliEncoder, EncodeV2, GzipEncoder, ZlibEncoder, ZstdEncoder,
    brotli::params::EncoderParams as BrotliEncoderParams,
};
use compression_core::util;
use rama_core::bytes::BytesMut;
use rama_core::{
    bytes::{Buf, Bytes},
    error::BoxError,
};

use pin_project_lite::pin_project;
use rama_http_types::StreamingBody;
use rama_http_types::body::{Frame, SizeHint};
use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};

pin_project! {
    /// Response body of [`StreamCompression`].
    ///
    /// [`StreamCompression`]: super::StreamCompression
    pub struct StreamCompressionBody<B>
    where
        B: StreamingBody,
    {
        #[pin]
        inner: BodyInner<B>,
    }
}

impl<B> Default for StreamCompressionBody<B>
where
    B: StreamingBody + Default,
{
    fn default() -> Self {
        Self {
            inner: BodyInner::Identity {
                inner: B::default(),
            },
        }
    }
}

enum Encoder {
    Gzip(GzipEncoder),
    Deflate(ZlibEncoder),
    Brotli(Box<BrotliEncoder>),
    Zstd(ZstdEncoder),
}

impl EncodeV2 for Encoder {
    fn encode(
        &mut self,
        input: &mut util::PartialBuffer<&[u8]>,
        output: &mut util::WriteBuffer<'_>,
    ) -> io::Result<()> {
        match self {
            Self::Gzip(e) => e.encode(input, output),
            Self::Deflate(e) => e.encode(input, output),
            Self::Brotli(e) => e.encode(input, output),
            Self::Zstd(e) => e.encode(input, output),
        }
    }

    fn flush(&mut self, output: &mut util::WriteBuffer<'_>) -> io::Result<bool> {
        match self {
            Self::Gzip(e) => e.flush(output),
            Self::Deflate(e) => e.flush(output),
            Self::Brotli(e) => e.flush(output),
            Self::Zstd(e) => e.flush(output),
        }
    }

    fn finish(&mut self, output: &mut util::WriteBuffer<'_>) -> io::Result<bool> {
        match self {
            Self::Gzip(e) => e.finish(output),
            Self::Deflate(e) => e.finish(output),
            Self::Brotli(e) => e.finish(output),
            Self::Zstd(e) => e.finish(output),
        }
    }
}

struct CompressData {
    encoder: Encoder,
    output_buffer: BytesMut,
    always_flush: bool,
    state: CompressState,
    pending_trailers: Option<HeaderMap>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CompressState {
    /// Reading data from inner body and compressing.
    Reading,
    /// Finishing compression after inner body is done.
    Finishing,
    /// Emitting buffered trailers.
    Trailers,
    /// Compression is complete.
    Done,
}

pin_project_cfg! {
    #[project = BodyInnerProj]
    enum BodyInner<B>
    where
        B: StreamingBody,
    {
        Compress {
            #[pin]
            inner: B,
            data: CompressData,
        },
        Identity {
            #[pin]
            inner: B,
        },
    }
}

impl CompressData {
    const INTERNAL_BUF_CAPACITY: usize = 8096;

    fn new(encoder: Encoder, always_flush: bool) -> Self {
        Self {
            encoder,
            output_buffer: BytesMut::with_capacity(Self::INTERNAL_BUF_CAPACITY),
            always_flush,
            state: CompressState::Reading,
            pending_trailers: None,
        }
    }

    /// Polls the inner body and compresses data.
    fn poll_compressed<B>(
        &mut self,
        cx: &mut Context<'_>,
        mut inner: Pin<&mut B>,
    ) -> Poll<Option<Result<Frame<Bytes>, io::Error>>>
    where
        B: StreamingBody,
        B::Data: Buf,
        B::Error: Into<BoxError>,
    {
        loop {
            match self.state {
                CompressState::Done => return Poll::Ready(None),

                CompressState::Trailers => {
                    if let Some(trailers) = self.pending_trailers.take() {
                        self.state = CompressState::Done;
                        return Poll::Ready(Some(Ok(Frame::trailers(trailers))));
                    } else {
                        self.state = CompressState::Done;
                        return Poll::Ready(None);
                    }
                }

                CompressState::Finishing => {
                    self.output_buffer.reserve(Self::INTERNAL_BUF_CAPACITY);
                    let mut output = util::WriteBuffer::new_uninitialized(
                        self.output_buffer.spare_capacity_mut(),
                    );

                    match self.encoder.finish(&mut output) {
                        Ok(done) => {
                            let written = output.written_len();
                            // Commit the bytes written to spare capacity
                            unsafe {
                                self.output_buffer
                                    .set_len(self.output_buffer.len() + written);
                            }

                            if written > 0 {
                                let data = self.output_buffer.split().freeze();
                                if done {
                                    self.state = if self.pending_trailers.is_some() {
                                        CompressState::Trailers
                                    } else {
                                        CompressState::Done
                                    };
                                }
                                return Poll::Ready(Some(Ok(Frame::data(data))));
                            } else if done {
                                self.state = if self.pending_trailers.is_some() {
                                    CompressState::Trailers
                                } else {
                                    CompressState::Done
                                };
                            } else {
                                // If not done and nothing written, we must yield to avoid busy-looping
                                // though finish() usually finishes or writes.
                                return Poll::Pending;
                            }
                        }
                        Err(e) => return Poll::Ready(Some(Err(io::Error::other(e)))),
                    }
                }

                CompressState::Reading => {
                    match inner.as_mut().poll_frame(cx) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(None) => {
                            self.state = CompressState::Finishing;
                        }
                        Poll::Ready(Some(Err(e))) => {
                            return Poll::Ready(Some(Err(io::Error::other(e.into()))));
                        }
                        Poll::Ready(Some(Ok(frame))) => {
                            match frame.into_data() {
                                Ok(mut data) => {
                                    let input_bytes = data.copy_to_bytes(data.remaining());
                                    match self.compress_chunk(&input_bytes) {
                                        Ok(Some(frame)) => return Poll::Ready(Some(Ok(frame))),
                                        // Encoder buffered the data but didn't emit a block yet.
                                        // We MUST continue to poll the inner body for more data.
                                        Ok(None) => (),
                                        Err(e) => return Poll::Ready(Some(Err(e))),
                                    }
                                }
                                Err(frame) => {
                                    if let Ok(trailers) = frame.into_trailers() {
                                        self.pending_trailers = Some(trailers);
                                        self.state = CompressState::Finishing;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    /// Compresses a chunk of input data.
    fn compress_chunk(&mut self, input: &[u8]) -> io::Result<Option<Frame<Bytes>>> {
        let mut input_buf = util::PartialBuffer::new(input);

        loop {
            self.output_buffer.reserve(Self::INTERNAL_BUF_CAPACITY);
            let mut output =
                util::WriteBuffer::new_uninitialized(self.output_buffer.spare_capacity_mut());

            self.encoder.encode(&mut input_buf, &mut output)?;

            let written = output.written_len();
            unsafe {
                self.output_buffer
                    .set_len(self.output_buffer.len() + written);
            }

            if input_buf.written_len() >= input.len() || written == 0 {
                break;
            }
        }

        if self.always_flush {
            self.output_buffer.reserve(Self::INTERNAL_BUF_CAPACITY);
            let mut output =
                util::WriteBuffer::new_uninitialized(self.output_buffer.spare_capacity_mut());
            let _ = self.encoder.flush(&mut output)?;
            let written = output.written_len();
            unsafe {
                self.output_buffer
                    .set_len(self.output_buffer.len() + written);
            }
        }

        if self.output_buffer.is_empty() {
            Ok(None)
        } else {
            Ok(Some(Frame::data(self.output_buffer.split().freeze())))
        }
    }
}

impl<B> StreamCompressionBody<B>
where
    B: StreamingBody,
{
    #[inline(always)]
    pub(super) fn gzip(inner: B, level: CompressionLevel, always_flush: bool) -> Self {
        Self::compressed(
            inner,
            Encoder::Gzip(GzipEncoder::new(level.into_compression_core().into())),
            always_flush,
        )
    }

    #[inline(always)]
    pub(super) fn deflate(inner: B, level: CompressionLevel, always_flush: bool) -> Self {
        Self::compressed(
            inner,
            Encoder::Deflate(ZlibEncoder::new(level.into_compression_core().into())),
            always_flush,
        )
    }

    #[inline(always)]
    pub(super) fn brotli(inner: B, level: CompressionLevel, always_flush: bool) -> Self {
        let params = BrotliEncoderParams::default().quality(level.into_compression_core());
        Self::compressed(
            inner,
            Encoder::Brotli(Box::new(BrotliEncoder::new(params))),
            always_flush,
        )
    }

    #[inline(always)]
    pub(super) fn zstd(inner: B, level: CompressionLevel, always_flush: bool) -> Self {
        // See https://issues.chromium.org/issues/41493659:
        //  "For memory usage reasons, Chromium limits the window size to 8MB"
        // See https://datatracker.ietf.org/doc/html/rfc8878#name-window-descriptor
        //  "For improved interoperability, it's recommended for decoders to support values
        //  of Window_Size up to 8 MB and for encoders not to generate frames requiring a
        //  Window_Size larger than 8 MB."
        // Level 17 in zstd (as of v1.5.6) is the first level with a window size of 8 MB (2^23):
        // https://github.com/facebook/zstd/blob/v1.5.6/lib/compress/clevels.h#L25-L51
        // Set the parameter for all levels >= 17. This will either have no effect (but reduce
        // the risk of future changes in zstd) or limit the window log to 8MB.
        let needs_window_limit = match level {
            CompressionLevel::Best => true, // level 20
            CompressionLevel::Precise(level) => level >= 17,
            CompressionLevel::Default | CompressionLevel::Fastest => false,
        };

        let level = match level {
            CompressionLevel::Fastest => 1,
            CompressionLevel::Best => 21,
            CompressionLevel::Default => 0,
            CompressionLevel::Precise(level) => level as i32,
        };

        // The parameter is not set for levels below 17 as it will increase the window size
        // for those levels.
        let encoder = if needs_window_limit {
            let params = [compression_codecs::zstd::params::CParameter::window_log(23)];
            ZstdEncoder::new_with_params(level, &params)
        } else {
            ZstdEncoder::new(level)
        };

        Self::compressed(inner, Encoder::Zstd(encoder), always_flush)
    }

    fn compressed(inner: B, encoder: Encoder, always_flush: bool) -> Self {
        Self {
            inner: BodyInner::Compress {
                inner,
                data: CompressData::new(encoder, always_flush),
            },
        }
    }

    pub(super) fn identity(inner: B) -> Self {
        Self {
            inner: BodyInner::Identity { inner },
        }
    }
}

impl<B> StreamingBody for StreamCompressionBody<B>
where
    B: StreamingBody,
    B::Data: Buf,
    B::Error: Into<BoxError>,
{
    type Data = Bytes;
    type Error = io::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        match self.project().inner.project() {
            BodyInnerProj::Identity { inner } => {
                // Pass through frames, converting data to Bytes
                match inner.poll_frame(cx) {
                    Poll::Pending => Poll::Pending,
                    Poll::Ready(None) => Poll::Ready(None),
                    Poll::Ready(Some(Ok(frame))) => {
                        let frame = frame.map_data(|mut data| data.copy_to_bytes(data.remaining()));
                        Poll::Ready(Some(Ok(frame)))
                    }
                    Poll::Ready(Some(Err(e))) => Poll::Ready(Some(Err(io::Error::other(e.into())))),
                }
            }
            BodyInnerProj::Compress { inner, data } => data.poll_compressed(cx, inner),
        }
    }

    fn is_end_stream(&self) -> bool {
        match &self.inner {
            BodyInner::Identity { inner } => inner.is_end_stream(),
            BodyInner::Compress { data, .. } => data.state == CompressState::Done,
        }
    }

    fn size_hint(&self) -> SizeHint {
        match &self.inner {
            BodyInner::Identity { inner } => inner.size_hint(),
            // Compressed size is unknown
            BodyInner::Compress { .. } => SizeHint::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    /// A test body that yields predefined frames.
    struct TestBody {
        frames: VecDeque<Frame<Bytes>>,
    }

    impl TestBody {
        fn new(frames: Vec<Frame<Bytes>>) -> Self {
            Self {
                frames: frames.into(),
            }
        }
    }

    impl StreamingBody for TestBody {
        type Data = Bytes;
        type Error = std::convert::Infallible;

        fn poll_frame(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
            match self.frames.pop_front() {
                Some(frame) => Poll::Ready(Some(Ok(frame))),
                None => Poll::Ready(None),
            }
        }
    }

    fn poll_body<B: StreamingBody + Unpin>(
        body: &mut B,
    ) -> Option<Result<Frame<B::Data>, B::Error>> {
        let waker = std::task::Waker::noop();
        let mut cx = Context::from_waker(waker);
        match Pin::new(body).poll_frame(&mut cx) {
            Poll::Ready(result) => result,
            Poll::Pending => None,
        }
    }

    #[test]
    fn test_identity_data() {
        let inner = TestBody::new(vec![Frame::data(Bytes::from("hello world"))]);
        let mut body = StreamCompressionBody::identity(inner);

        let frame = poll_body(&mut body).unwrap().unwrap();
        assert!(frame.is_data());
        assert_eq!(frame.into_data().unwrap(), Bytes::from("hello world"));

        assert!(poll_body(&mut body).is_none());
    }

    #[test]
    fn test_passthrough_trailers() {
        let mut trailers = HeaderMap::new();
        trailers.insert("x-checksum", "abc123".parse().unwrap());

        let inner = TestBody::new(vec![
            Frame::data(Bytes::from("data")),
            Frame::trailers(trailers.clone()),
        ]);
        let mut body = StreamCompressionBody::identity(inner);

        // First frame is data
        let frame = poll_body(&mut body).unwrap().unwrap();
        assert!(frame.is_data());

        // Second frame is trailers
        let frame = poll_body(&mut body).unwrap().unwrap();
        assert!(frame.is_trailers());
        let received_trailers = frame.into_trailers().unwrap();
        assert_eq!(received_trailers.get("x-checksum").unwrap(), "abc123");

        assert!(poll_body(&mut body).is_none());
    }

    #[test]
    fn test_compressed_produces_output() {
        let mk_inner = || TestBody::new(vec![Frame::data(Bytes::from("hello world"))]);
        for mut body in [
            StreamCompressionBody::gzip(mk_inner(), Default::default(), false),
            StreamCompressionBody::deflate(mk_inner(), Default::default(), false),
            StreamCompressionBody::brotli(mk_inner(), Default::default(), false),
            StreamCompressionBody::zstd(mk_inner(), Default::default(), false),
        ] {
            // Should get compressed data
            let frame = poll_body(&mut body).unwrap().unwrap();
            assert!(frame.is_data());
            let data = frame.into_data().unwrap();
            // Compressed output should exist (gzip header starts with 0x1f 0x8b)
            assert!(!data.is_empty());

            // Should get more data from finishing
            while let Some(Ok(frame)) = poll_body(&mut body) {
                assert!(frame.is_data());
            }
        }
    }

    #[test]
    fn test_compressed_with_trailers() {
        let mk_inner = || {
            let mut trailers = HeaderMap::new();
            trailers.insert("x-checksum", "abc123".parse().unwrap());

            TestBody::new(vec![
                Frame::data(Bytes::from("hello world")),
                Frame::trailers(trailers),
            ])
        };

        for mut body in [
            StreamCompressionBody::gzip(mk_inner(), Default::default(), false),
            StreamCompressionBody::deflate(mk_inner(), Default::default(), false),
            StreamCompressionBody::brotli(mk_inner(), Default::default(), false),
            StreamCompressionBody::zstd(mk_inner(), Default::default(), false),
        ] {
            // Collect all frames
            let mut data_frames = 0;
            let mut trailer_frame = None;
            while let Some(Ok(frame)) = poll_body(&mut body) {
                if frame.is_data() {
                    data_frames += 1;
                } else if frame.is_trailers() {
                    trailer_frame = Some(frame);
                }
            }

            // Should have received at least one data frame
            assert!(data_frames >= 1);

            // Should have received trailers
            let trailers = trailer_frame
                .expect("Expected trailers frame")
                .into_trailers()
                .unwrap();
            assert_eq!(trailers.get("x-checksum").unwrap(), "abc123");
        }
    }
}
