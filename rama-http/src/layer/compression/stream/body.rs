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
use rama_utils::octets::kib;
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

/// Spare room reserved in the output buffer for each codec call.
const INTERNAL_BUF_CAPACITY: usize = kib(8);

/// Input compressed per poll, which bounds how long a poll takes.
const INPUT_LEN_PER_POLL: usize = kib(64);

/// Buffered output from which a data frame is emitted before more is compressed.
const OUTPUT_FRAME_LEN: usize = kib(64);

struct CompressData<D> {
    encoder: Encoder,
    output_buffer: BytesMut,
    always_flush: bool,
    state: CompressState,
    pending_trailers: Option<HeaderMap>,
    /// Rest of the data frame being compressed.
    input: Option<D>,
    /// The encoder is being flushed before more input is read.
    flushing: bool,
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
            data: CompressData<B::Data>,
        },
        Identity {
            #[pin]
            inner: B,
        },
        Empty {
            _inner: B,
        },
    }
}

impl<D> CompressData<D> {
    fn new(encoder: Encoder, always_flush: bool) -> Self {
        Self {
            encoder,
            output_buffer: BytesMut::with_capacity(INTERNAL_BUF_CAPACITY),
            always_flush,
            state: CompressState::Reading,
            pending_trailers: None,
            input: None,
            flushing: false,
        }
    }
}

impl<D: Buf> CompressData<D> {
    /// Polls the inner body and compresses data.
    fn poll_compressed<B>(
        &mut self,
        cx: &mut Context<'_>,
        mut inner: Pin<&mut B>,
    ) -> Poll<Option<Result<Frame<Bytes>, io::Error>>>
    where
        B: StreamingBody<Data = D>,
        B::Error: Into<BoxError>,
    {
        let mut budget = INPUT_LEN_PER_POLL;
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

                CompressState::Finishing => match self.drain(true) {
                    Ok(done) => {
                        if done {
                            self.state = if self.pending_trailers.is_some() {
                                CompressState::Trailers
                            } else {
                                CompressState::Done
                            };
                        }
                        if let Some(frame) = self.take_output() {
                            return Poll::Ready(Some(Ok(frame)));
                        }
                    }
                    Err(error) => return Poll::Ready(Some(Err(error))),
                },

                CompressState::Reading if self.flushing => match self.drain(false) {
                    Ok(done) => {
                        if done {
                            self.flushing = false;
                        }
                        if let Some(frame) = self.take_output() {
                            return Poll::Ready(Some(Ok(frame)));
                        }
                    }
                    Err(error) => return Poll::Ready(Some(Err(error))),
                },

                CompressState::Reading if self.input.is_some() => {
                    if budget == 0 {
                        // The encoder took a poll's worth of input without output: let the
                        // caller run other work before the rest is compressed.
                        cx.waker().wake_by_ref();
                        return Poll::Pending;
                    }
                    if let Err(error) = self.compress_input(&mut budget) {
                        return Poll::Ready(Some(Err(error)));
                    }
                    // A flush joins the output it follows in one frame.
                    if !self.flushing
                        && let Some(frame) = self.take_output()
                    {
                        return Poll::Ready(Some(Ok(frame)));
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
                                // Skip empty DATA locally to avoid flate's no-progress BufError
                                // while preserving EOF and trailers, and consider an upstream
                                // fix in the future if needed.
                                Ok(data) => {
                                    if data.has_remaining() {
                                        self.input = Some(data);
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

    /// Compresses up to `budget` bytes of the data frame held in `input`.
    fn compress_input(&mut self, budget: &mut usize) -> io::Result<()> {
        let Some(data) = self.input.as_mut() else {
            return Ok(());
        };
        let chunk = data.chunk();
        // An empty chunk with bytes remaining breaks the `Buf` contract: end the frame over spinning.
        let ended = chunk.is_empty();
        let len = chunk.len().min(*budget);
        let consumed = encode_input(&mut self.encoder, &chunk[..len], &mut self.output_buffer)?;
        data.advance(consumed);
        *budget -= consumed;

        if ended || !data.has_remaining() {
            self.input = None;
            self.flushing = self.always_flush;
        }
        Ok(())
    }
}

impl<D> CompressData<D> {
    /// Drains the encoder into the output buffer, a frame's worth at most.
    ///
    /// Returns whether the encoder holds nothing back any more.
    fn drain(&mut self, finish: bool) -> io::Result<bool> {
        loop {
            let (done, _) = drain_step(&mut self.encoder, &mut self.output_buffer, finish)?;
            if done || self.output_buffer.len() >= OUTPUT_FRAME_LEN {
                return Ok(done);
            }
        }
    }

    fn take_output(&mut self) -> Option<Frame<Bytes>> {
        (!self.output_buffer.is_empty()).then(|| Frame::data(self.output_buffer.split().freeze()))
    }
}

/// Run `encode` with a `WriteBuffer` over the spare capacity of
/// `output_buffer`, returning its result and the number of bytes written.
///
/// # Safety-usable invariant
///
/// On `Ok((_, written))`, `written <= output_buffer.capacity() -
/// output_buffer.len()` and the `written` bytes right after
/// `output_buffer.len()` are initialized.
fn encode_into_spare<R>(
    output_buffer: &mut BytesMut,
    encode: impl FnOnce(&mut util::WriteBuffer<'_>) -> io::Result<R>,
) -> io::Result<(R, usize)> {
    let buffered = output_buffer.len();
    let spare = output_buffer.spare_capacity_mut();
    // A codec call fills a frame up to its mark, whatever capacity the buffer grew to.
    let room = OUTPUT_FRAME_LEN
        .saturating_sub(buffered)
        .max(INTERNAL_BUF_CAPACITY)
        .min(spare.len());
    let spare = &mut spare[..room];
    let start = spare.as_mut_ptr().cast::<u8>();
    let spare_len = spare.len();
    let mut output = util::WriteBuffer::new_uninitialized(spare);
    let result = encode(&mut output)?;
    // A codec may replace `output` with a buffer over other memory; only
    // bytes written into the original spare capacity may be exposed.
    if output.as_mut_ptr() != start || output.capacity() != spare_len {
        return Err(io::Error::other(
            "compression encoder replaced its output buffer",
        ));
    }
    let written = output.written_len();
    if written > spare_len {
        return Err(io::Error::other(
            "compression encoder reported more output than its buffer holds",
        ));
    }
    // `output` still wraps exactly the original spare capacity (checked
    // above): another `WriteBuffer` over that memory would need a `&mut` to it,
    // which only `output` held, or unsafe code bound by `WriteBuffer`'s unsafe
    // contracts. `WriteBuffer::written` is a safe fn returning its first
    // `written_len()` bytes as `&[u8]`, so its soundness (a compression-core
    // dependency lemma) means those bytes are initialized.
    Ok((result, written))
}

/// Extend `output_buffer` over `written` bytes written into its spare capacity.
///
/// # Safety
///
/// The caller must ensure `written <= output_buffer.capacity() -
/// output_buffer.len()` and that the `written` bytes right after
/// `output_buffer.len()` in its allocation are initialized.
unsafe fn set_len_written(output_buffer: &mut BytesMut, written: usize) {
    // SAFETY: `BytesMut::set_len` requires `new_len <= capacity` and the bytes
    // up to `new_len` initialized. The first `len` bytes are initialized by
    // `BytesMut`'s own invariant, and the precondition gives the rest and the
    // capacity bound.
    unsafe { output_buffer.set_len(output_buffer.len() + written) };
}

/// A synchronous codec has no waker: an unfinished drain must emit bytes.
fn drain_step(
    encoder: &mut impl EncodeV2,
    output_buffer: &mut BytesMut,
    finish: bool,
) -> io::Result<(bool, usize)> {
    output_buffer.reserve(INTERNAL_BUF_CAPACITY);
    let (done, written) = encode_into_spare(output_buffer, |output| {
        if finish {
            encoder.finish(output)
        } else {
            encoder.flush(output)
        }
    })?;
    // SAFETY: `set_len_written` needs `written` to fit the spare capacity and
    // those bytes initialized, which the safety-usable invariant of
    // `encode_into_spare` gives; `output_buffer` is unchanged since.
    unsafe { set_len_written(output_buffer, written) };
    if !done && written == 0 {
        return Err(io::Error::other(
            "compression encoder made no drain progress",
        ));
    }
    Ok((done, written))
}

/// Feed `input` to the encoder until all of it is consumed or a frame's worth of
/// output is buffered, returning the length consumed.
///
/// A codec that buffers input without emitting output still consumes all of it.
fn encode_input(
    encoder: &mut impl EncodeV2,
    input: &[u8],
    output_buffer: &mut BytesMut,
) -> io::Result<usize> {
    let mut input_buf = util::PartialBuffer::new(input);
    while !input_buf.unwritten().is_empty() && output_buffer.len() < OUTPUT_FRAME_LEN {
        output_buffer.reserve(INTERNAL_BUF_CAPACITY);
        let consumed_before = input_buf.written_len();
        let ((), written) = encode_into_spare(output_buffer, |output| {
            encoder.encode(&mut input_buf, output)
        })?;
        // SAFETY: as in `drain_step`: the safety-usable invariant of
        // `encode_into_spare` gives the precondition of `set_len_written`.
        unsafe { set_len_written(output_buffer, written) };
        if input_buf.written_len() == consumed_before && written == 0 {
            return Err(io::Error::other("compression encoder made no progress"));
        }
    }
    Ok(input_buf.written_len())
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

    pub(super) fn empty(inner: B) -> Self {
        Self {
            inner: BodyInner::Empty { _inner: inner },
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
            BodyInnerProj::Empty { .. } => Poll::Ready(None),
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
            BodyInner::Empty { .. } => true,
            BodyInner::Compress { data, .. } => data.state == CompressState::Done,
        }
    }

    fn size_hint(&self) -> SizeHint {
        match &self.inner {
            BodyInner::Identity { inner } => inner.size_hint(),
            BodyInner::Empty { .. } => SizeHint::with_exact(0),
            // Compressed size is unknown
            BodyInner::Compress { .. } => SizeHint::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rama_core::bytes::buf::Chain;
    use std::assert_matches;
    use std::cell::RefCell;
    use std::collections::VecDeque;
    use std::io::{Read, Write};
    use std::rc::Rc;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::{Wake, Waker};

    /// An encoder that swaps in a buffer over its own memory and reports one
    /// written byte there.
    struct SwappingEncoder;

    impl SwappingEncoder {
        fn swap(output: &mut util::WriteBuffer<'_>) {
            let leaked: &'static mut [u8] = Box::leak(vec![b'x'; 8].into_boxed_slice());
            *output = util::WriteBuffer::new_initialized(leaked);
            output.advance(1);
        }
    }

    impl EncodeV2 for SwappingEncoder {
        fn encode(
            &mut self,
            input: &mut util::PartialBuffer<&[u8]>,
            output: &mut util::WriteBuffer<'_>,
        ) -> io::Result<()> {
            input.advance(input.unwritten().len());
            Self::swap(output);
            Ok(())
        }

        fn flush(&mut self, output: &mut util::WriteBuffer<'_>) -> io::Result<bool> {
            Self::swap(output);
            Ok(true)
        }

        fn finish(&mut self, output: &mut util::WriteBuffer<'_>) -> io::Result<bool> {
            Self::swap(output);
            Ok(true)
        }
    }

    #[test]
    fn encoder_replacing_its_output_buffer_is_rejected() {
        let mut output = BytesMut::new();
        encode_input(&mut SwappingEncoder, b"data", &mut output).unwrap_err();
        assert!(output.is_empty());

        drain_step(&mut SwappingEncoder, &mut output, false).unwrap_err();
        drain_step(&mut SwappingEncoder, &mut output, true).unwrap_err();
        assert!(output.is_empty());
    }

    /// A test body that yields predefined frames.
    struct TestBody<D = Bytes> {
        frames: VecDeque<Frame<D>>,
    }

    impl<D> TestBody<D> {
        fn new(frames: Vec<Frame<D>>) -> Self {
            Self {
                frames: frames.into(),
            }
        }
    }

    impl<D: Buf + Unpin> StreamingBody for TestBody<D> {
        type Data = D;
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
    fn empty_data_frames() {
        // Exercise initialization, interleaved empties, EOF, and trailer delivery,
        // both with normal buffering and the per-chunk flushing used for SSE.
        for chunks in [
            vec!["a", "", "b"],
            vec!["", "", ""],
            vec!["a", ""],
            vec!["", "a"],
        ] {
            for with_trailers in [false, true] {
                for always_flush in [false, true] {
                    for encoding in ["gzip", "deflate", "br", "zstd"] {
                        let mut trailers = HeaderMap::new();
                        trailers.insert("x-checksum", "abc123".parse().unwrap());
                        let mut frames: Vec<_> = chunks
                            .iter()
                            .map(|chunk| Frame::data(Bytes::from_static(chunk.as_bytes())))
                            .collect();
                        if with_trailers {
                            frames.push(Frame::trailers(trailers.clone()));
                        }
                        let inner = TestBody::new(frames);
                        let mut body = match encoding {
                            "gzip" => {
                                StreamCompressionBody::gzip(inner, Default::default(), always_flush)
                            }
                            "deflate" => StreamCompressionBody::deflate(
                                inner,
                                Default::default(),
                                always_flush,
                            ),
                            "br" => StreamCompressionBody::brotli(
                                inner,
                                Default::default(),
                                always_flush,
                            ),
                            "zstd" => {
                                StreamCompressionBody::zstd(inner, Default::default(), always_flush)
                            }
                            _ => panic!("unexpected test encoding: {encoding}"),
                        };
                        let mut compressed = Vec::new();
                        let mut received_trailers = None;
                        loop {
                            // Pending is not EOF: these ready-only fixtures must finish.
                            let Poll::Ready(frame) = Pin::new(&mut body)
                                .poll_frame(&mut Context::from_waker(std::task::Waker::noop()))
                            else {
                                panic!("unexpected Pending: {encoding}, {chunks:?}");
                            };
                            let Some(frame) = frame else { break };
                            let frame = frame.unwrap_or_else(|err| {
                                panic!("{encoding}, {chunks:?}, flush={always_flush}: {err}")
                            });
                            match frame.into_data() {
                                Ok(data) => {
                                    assert!(received_trailers.is_none(), "data after trailers");
                                    compressed.extend_from_slice(&data);
                                }
                                Err(frame) => {
                                    assert!(received_trailers.is_none(), "duplicate trailers");
                                    received_trailers = Some(frame.into_trailers().unwrap());
                                }
                            }
                            if body.is_end_stream() {
                                // A transport may stop polling immediately on this hint.
                                assert_eq!(received_trailers.is_some(), with_trailers);
                                assert_matches!(
                                    Pin::new(&mut body).poll_frame(&mut Context::from_waker(
                                        std::task::Waker::noop(),
                                    )),
                                    Poll::Ready(None),
                                    "{encoding}: frames remain after the EOS hint",
                                );
                                break;
                            }
                        }
                        assert!(body.is_end_stream());
                        assert_eq!(received_trailers, with_trailers.then_some(trailers));
                        let mut decoder: Box<dyn Read> = match encoding {
                            "gzip" => Box::new(flate2::read::GzDecoder::new(&compressed[..])),
                            "deflate" => Box::new(flate2::read::ZlibDecoder::new(&compressed[..])),
                            "br" => Box::new(brotli::Decompressor::new(&compressed[..], 4096)),
                            "zstd" => {
                                Box::new(zstd::stream::read::Decoder::new(&compressed[..]).unwrap())
                            }
                            _ => panic!("unexpected test encoding: {encoding}"),
                        };
                        let mut decoded = Vec::new();
                        decoder.read_to_end(&mut decoded).unwrap();
                        assert_eq!(decoded, chunks.concat().as_bytes(), "{encoding}");
                    }
                }
            }
        }
    }

    struct ProgressProbe {
        stalled: bool,
        consumed: usize,
    }

    impl EncodeV2 for ProgressProbe {
        fn encode(
            &mut self,
            input: &mut util::PartialBuffer<&[u8]>,
            _output: &mut util::WriteBuffer<'_>,
        ) -> io::Result<()> {
            if !self.stalled && !input.unwritten().is_empty() {
                input.advance(1);
                self.consumed += 1;
            }
            Ok(())
        }
        fn flush(&mut self, _output: &mut util::WriteBuffer<'_>) -> io::Result<bool> {
            self.consumed += 1;
            // Bound a reverted flush loop so the regression fails instead of hanging.
            if self.consumed > 1 {
                return Err(io::Error::other("probe repeated without progress"));
            }
            Ok(!self.stalled)
        }
        fn finish(&mut self, output: &mut util::WriteBuffer<'_>) -> io::Result<bool> {
            self.flush(output)
        }
    }

    #[test]
    fn encoder_drain_stalls_error_before_retry_or_pending() {
        for finish in [false, true] {
            let mut encoder = ProgressProbe {
                stalled: true,
                consumed: 0,
            };
            let mut output = BytesMut::new();
            let error = drain_step(&mut encoder, &mut output, finish).unwrap_err();
            assert_eq!(
                error.to_string(),
                "compression encoder made no drain progress"
            );
            assert_eq!(encoder.consumed, 1);
            assert!(output.is_empty());

            let mut encoder = ProgressProbe {
                stalled: false,
                consumed: 0,
            };
            assert_eq!(
                drain_step(&mut encoder, &mut output, finish).unwrap(),
                (true, 0)
            );
        }
    }

    #[test]
    fn encoder_stall_is_an_error_not_truncated_success() {
        let mut encoder = ProgressProbe {
            stalled: true,
            consumed: 0,
        };
        let error =
            encode_input(&mut encoder, b"keep every byte", &mut BytesMut::new()).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Other);
        assert_eq!(encoder.consumed, 0);
    }

    #[test]
    fn encoder_consumes_buffered_input_without_output() {
        let mut encoder = ProgressProbe {
            stalled: false,
            consumed: 0,
        };
        let input = b"keep every byte";
        let consumed = encode_input(&mut encoder, input, &mut BytesMut::new()).unwrap();
        assert_eq!(consumed, input.len());
        assert_eq!(encoder.consumed, input.len());
    }

    #[test]
    fn large_streaming_frames_round_trip() {
        // Incompressible input makes a flush exceed the codec's output buffer.
        // Use generated bytes, independent of any captured site's content.
        let mut state = 0x1234_5678_u32;
        let input: Vec<u8> = (0..262_144)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 17;
                state ^= state << 5;
                state as u8
            })
            .collect();
        for width in [4096, 8096, 8192, 65_536, input.len()] {
            for always_flush in [false, true] {
                for encoding in ["br", "gzip", "deflate", "zstd"] {
                    let mut trailers = HeaderMap::new();
                    trailers.insert("x-checksum", "complete".parse().unwrap());
                    let mut frames: Vec<_> = input
                        .chunks(width)
                        .map(|chunk| Frame::data(Bytes::copy_from_slice(chunk)))
                        .collect();
                    frames.push(Frame::trailers(trailers.clone()));
                    let inner = TestBody::new(frames);
                    let mut body = match encoding {
                        "br" => {
                            StreamCompressionBody::brotli(inner, Default::default(), always_flush)
                        }
                        "gzip" => {
                            StreamCompressionBody::gzip(inner, Default::default(), always_flush)
                        }
                        "deflate" => {
                            StreamCompressionBody::deflate(inner, Default::default(), always_flush)
                        }
                        "zstd" => {
                            StreamCompressionBody::zstd(inner, Default::default(), always_flush)
                        }
                        _ => panic!("unexpected test encoding: {encoding}"),
                    };
                    let mut compressed = Vec::new();
                    let mut received_trailers = None;
                    let wakes = Arc::new(WakeCount::default());
                    let waker = Waker::from(wakes.clone());
                    loop {
                        let woken = wakes.0.load(Ordering::Relaxed);
                        let Poll::Ready(frame) =
                            Pin::new(&mut body).poll_frame(&mut Context::from_waker(&waker))
                        else {
                            // These ready-only fixtures are pending only when the body yields.
                            assert!(
                                wakes.0.load(Ordering::Relaxed) > woken,
                                "Pending without wake-up: {encoding}, {width}, {always_flush}",
                            );
                            continue;
                        };
                        let Some(frame) = frame else { break };
                        let frame = frame.unwrap_or_else(|error| {
                            panic!("{encoding}, {width}, {always_flush}: {error}")
                        });
                        match frame.into_data() {
                            Ok(data) => {
                                assert!(received_trailers.is_none());
                                compressed.extend_from_slice(&data);
                            }
                            Err(frame) => {
                                assert!(received_trailers.is_none());
                                received_trailers = Some(frame.into_trailers().unwrap());
                            }
                        }
                    }
                    assert!(body.is_end_stream());
                    assert_eq!(received_trailers, Some(trailers));
                    let mut decoder: Box<dyn Read> = match encoding {
                        "br" => Box::new(brotli::Decompressor::new(&compressed[..], 4096)),
                        "gzip" => Box::new(flate2::read::GzDecoder::new(&compressed[..])),
                        "deflate" => Box::new(flate2::read::ZlibDecoder::new(&compressed[..])),
                        "zstd" => {
                            Box::new(zstd::stream::read::Decoder::new(&compressed[..]).unwrap())
                        }
                        _ => panic!("unexpected test encoding: {encoding}"),
                    };
                    let mut decoded = Vec::new();
                    decoder.read_to_end(&mut decoded).unwrap();
                    assert_eq!(decoded, input, "{encoding}, {width}, {always_flush}");
                }
            }
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

    const ENCODINGS: [&str; 4] = ["gzip", "deflate", "br", "zstd"];

    #[derive(Default)]
    struct WakeCount(AtomicUsize);

    impl Wake for WakeCount {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }

    #[derive(Debug)]
    enum Polled {
        Data(Bytes),
        Trailers(HeaderMap),
        /// Pending after waking its own task.
        Yielded,
        /// Pending without a wake-up.
        Idle,
        Failed(io::Error),
        End,
    }

    fn poll_once<B>(body: &mut StreamCompressionBody<B>) -> Polled
    where
        B: StreamingBody<Data: Buf, Error: Into<BoxError>>,
        StreamCompressionBody<B>: Unpin,
    {
        let wakes = Arc::new(WakeCount::default());
        let waker = Waker::from(wakes.clone());
        match Pin::new(body).poll_frame(&mut Context::from_waker(&waker)) {
            Poll::Pending if wakes.0.load(Ordering::Relaxed) > 0 => Polled::Yielded,
            Poll::Pending => Polled::Idle,
            Poll::Ready(None) => Polled::End,
            Poll::Ready(Some(Err(error))) => Polled::Failed(error),
            Poll::Ready(Some(Ok(frame))) => match frame.into_data() {
                Ok(data) => Polled::Data(data),
                Err(frame) => Polled::Trailers(frame.into_trailers().unwrap()),
            },
        }
    }

    #[derive(Default)]
    struct Drained {
        data: Vec<u8>,
        largest_frame: usize,
        trailers: Option<HeaderMap>,
        yields: usize,
        error: Option<io::Error>,
    }

    /// Polls `body` to its end or first error; the inner body must never be idle.
    fn drain<B>(body: &mut StreamCompressionBody<B>) -> Drained
    where
        B: StreamingBody<Data: Buf, Error: Into<BoxError>>,
        StreamCompressionBody<B>: Unpin,
    {
        let mut drained = Drained::default();
        loop {
            match poll_once(body) {
                Polled::Data(data) => {
                    assert!(!data.is_empty(), "empty data frame");
                    assert!(drained.trailers.is_none(), "data after trailers");
                    drained.largest_frame = drained.largest_frame.max(data.len());
                    drained.data.extend_from_slice(&data);
                }
                Polled::Trailers(trailers) => {
                    assert!(drained.trailers.is_none(), "duplicate trailers");
                    drained.trailers = Some(trailers);
                }
                Polled::Yielded => drained.yields += 1,
                Polled::Idle => panic!("Pending without wake-up"),
                Polled::Failed(error) => {
                    drained.error = Some(error);
                    return drained;
                }
                Polled::End => return drained,
            }
        }
    }

    fn compress_body<B: StreamingBody>(
        encoding: &str,
        inner: B,
        always_flush: bool,
    ) -> StreamCompressionBody<B> {
        match encoding {
            "gzip" => StreamCompressionBody::gzip(inner, Default::default(), always_flush),
            "deflate" => StreamCompressionBody::deflate(inner, Default::default(), always_flush),
            "br" => StreamCompressionBody::brotli(inner, Default::default(), always_flush),
            "zstd" => StreamCompressionBody::zstd(inner, Default::default(), always_flush),
            _ => panic!("unexpected test encoding: {encoding}"),
        }
    }

    fn decode(encoding: &str, compressed: &[u8]) -> Vec<u8> {
        let mut decoder: Box<dyn Read + '_> = match encoding {
            "gzip" => Box::new(flate2::read::GzDecoder::new(compressed)),
            "deflate" => Box::new(flate2::read::ZlibDecoder::new(compressed)),
            "br" => Box::new(brotli::Decompressor::new(compressed, 4096)),
            "zstd" => Box::new(zstd::stream::read::Decoder::new(compressed).unwrap()),
            _ => panic!("unexpected test encoding: {encoding}"),
        };
        let mut decoded = Vec::new();
        decoder.read_to_end(&mut decoded).unwrap();
        decoded
    }

    /// Bytes no codec can shrink.
    fn noise(len: usize) -> Vec<u8> {
        let mut state = 0x1234_5678_u32;
        (0..len)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 17;
                state ^= state << 5;
                state as u8
            })
            .collect()
    }

    #[derive(Default)]
    struct Feed {
        frames: VecDeque<Result<Frame<Bytes>, &'static str>>,
        closed: bool,
    }

    /// Body fed by the test: pending, without a wake-up, while it has nothing and is open.
    struct FedBody(Rc<RefCell<Feed>>);

    impl StreamingBody for FedBody {
        type Data = Bytes;
        type Error = &'static str;

        fn poll_frame(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
            let mut feed = self.0.borrow_mut();
            match feed.frames.pop_front() {
                Some(frame) => Poll::Ready(Some(frame)),
                None if feed.closed => Poll::Ready(None),
                None => Poll::Pending,
            }
        }
    }

    struct SharedSink(Rc<RefCell<Vec<u8>>>);

    impl Write for SharedSink {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0.borrow_mut().extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    /// Decoder that writes what it can decode so far into `decoded`.
    fn stream_decoder(encoding: &str, decoded: Rc<RefCell<Vec<u8>>>) -> Box<dyn Write> {
        let sink = SharedSink(decoded);
        match encoding {
            "gzip" => Box::new(flate2::write::GzDecoder::new(sink)),
            "deflate" => Box::new(flate2::write::ZlibDecoder::new(sink)),
            "br" => Box::new(brotli::DecompressorWriter::new(sink, 4096)),
            "zstd" => Box::new(zstd::stream::write::Decoder::new(sink).unwrap()),
            _ => panic!("unexpected test encoding: {encoding}"),
        }
    }

    #[test]
    fn large_frame_is_emitted_in_bounded_frames() {
        let input = noise(kib(512));
        for always_flush in [false, true] {
            for encoding in ENCODINGS {
                let inner = TestBody::new(vec![Frame::data(Bytes::from(input.clone()))]);
                let mut body = compress_body(encoding, inner, always_flush);
                let drained = drain(&mut body);
                assert!(drained.error.is_none(), "{encoding}, {always_flush}");
                // The last input call and one flush call may each overshoot the mark.
                assert!(
                    drained.largest_frame <= OUTPUT_FRAME_LEN + 2 * INTERNAL_BUF_CAPACITY,
                    "{encoding}, {always_flush}: frame of {}",
                    drained.largest_frame,
                );
                assert_eq!(decode(encoding, &drained.data), input, "{encoding}");
            }
        }
    }

    #[test]
    fn input_without_output_yields_between_slices() {
        // Repetitive input is taken in by every codec long before it emits a block.
        let input = vec![b'a'; kib(512)];
        for always_flush in [false, true] {
            for encoding in ENCODINGS {
                let mut trailers = HeaderMap::new();
                trailers.insert("x-checksum", "complete".parse().unwrap());
                let inner = TestBody::new(vec![
                    Frame::data(Bytes::from(input.clone())),
                    Frame::trailers(trailers.clone()),
                ]);
                let mut body = compress_body(encoding, inner, always_flush);
                let drained = drain(&mut body);
                assert!(drained.error.is_none(), "{encoding}, {always_flush}");
                assert!(drained.yields > 0, "{encoding}, {always_flush}: no yield");
                assert_eq!(drained.trailers, Some(trailers), "{encoding}");
                assert_eq!(decode(encoding, &drained.data), input, "{encoding}");
            }
        }
    }

    #[test]
    fn data_spanning_several_chunks_round_trips() {
        let input = noise(kib(96));
        let (head, tail) = input.split_at(kib(70));
        for always_flush in [false, true] {
            for encoding in ENCODINGS {
                let data: Chain<Bytes, Bytes> =
                    Bytes::copy_from_slice(head).chain(Bytes::copy_from_slice(tail));
                let inner = TestBody::new(vec![Frame::data(data)]);
                let mut body = compress_body(encoding, inner, always_flush);
                let drained = drain(&mut body);
                assert!(drained.error.is_none(), "{encoding}, {always_flush}");
                assert_eq!(decode(encoding, &drained.data), input, "{encoding}");
            }
        }
    }

    #[test]
    fn inner_error_follows_the_data_before_it() {
        for encoding in ENCODINGS {
            let feed = Rc::new(RefCell::new(Feed::default()));
            feed.borrow_mut().frames.extend([
                Ok(Frame::data(Bytes::from_static(b"delivered"))),
                Err("inner body failed"),
            ]);
            let mut body = compress_body(encoding, FedBody(feed), true);
            let drained = drain(&mut body);
            let error = drained.error.expect("inner error");
            assert_eq!(error.to_string(), "inner body failed", "{encoding}");

            let decoded = Rc::new(RefCell::new(Vec::new()));
            let mut decoder = stream_decoder(encoding, decoded.clone());
            decoder.write_all(&drained.data).unwrap();
            decoder.flush().unwrap();
            assert_eq!(*decoded.borrow(), b"delivered", "{encoding}");
        }
    }
}
