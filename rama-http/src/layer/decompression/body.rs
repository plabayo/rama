#![allow(unused_imports)]

use crate::HeaderMap;
use crate::body::{Body, Frame, SizeHint, StreamingBody, util::LengthLimitError};
use crate::layer::util::compression::{
    AsyncReadBody, BodyIntoStream, CompressionLevel, DecorateAsyncRead, WrapBody,
    impl_decorate_async_read,
};
use compression_codecs::zstd::params::DParameter;
use rama_core::error::BoxError;

use async_compression::tokio::bufread::BrotliDecoder;
use async_compression::tokio::bufread::GzipDecoder;
use async_compression::tokio::bufread::ZlibDecoder;
use async_compression::tokio::bufread::ZstdDecoder;
use pin_project_lite::pin_project;
use rama_core::bytes::{Buf, Bytes};
use rama_core::futures::ready;
use rama_core::stream::io::StreamReader;
use std::task::Context;
use std::{io, marker::PhantomData, pin::Pin, task::Poll};
use tokio::io::{AsyncBufRead, AsyncRead, ReadBuf};

pin_project! {
    /// Response body of [`RequestDecompression`] and [`Decompression`].
    ///
    /// [`RequestDecompression`]: super::RequestDecompression
    /// [`Decompression`]: super::Decompression
    pub struct DecompressionBody<B>
    where
        B: StreamingBody
    {
        #[pin]
        pub(crate) inner: BodyInner<B>,
        decoded_budget: Option<usize>,
    }
}

impl<B> Default for DecompressionBody<B>
where
    B: StreamingBody + Default,
{
    fn default() -> Self {
        Self {
            inner: BodyInner::Identity {
                inner: B::default(),
            },
            decoded_budget: None,
        }
    }
}

impl<B> DecompressionBody<B>
where
    B: StreamingBody,
{
    pub(crate) fn new(inner: BodyInner<B>) -> Self {
        Self {
            inner,
            decoded_budget: None,
        }
    }

    /// Fail with a [`LengthLimitError`] once decoded data exceeds `limit` bytes.
    pub(crate) fn with_decoded_limit(mut self, limit: Option<usize>) -> Self {
        self.decoded_budget = limit;
        self
    }
}

type GzipBody<B> = WrapBody<GzipDecoder<B>>;
type DeflateBody<B> = WrapBody<ZlibDecoder<B>>;
type BrotliBody<B> = WrapBody<BrotliWindowGuard<B>>;
type ZstdBody<B> = WrapBody<ZstdDecoder<B>>;

pin_project! {
    #[project = BodyInnerProj]
    pub(crate) enum BodyInner<B>
    where
        B: StreamingBody,
    {
        Gzip {
            #[pin]
            inner: GzipBody<B>,
        },
        Deflate {
            #[pin]
            inner: DeflateBody<B>,
        },
        Brotli {
            #[pin]
            inner: BrotliBody<B>,
        },
        Zstd {
            #[pin]
            inner: ZstdBody<B>,
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

impl<B: StreamingBody> BodyInner<B> {
    pub(crate) fn gzip(inner: WrapBody<GzipDecoder<B>>) -> Self {
        Self::Gzip { inner }
    }

    pub(crate) fn deflate(inner: WrapBody<ZlibDecoder<B>>) -> Self {
        Self::Deflate { inner }
    }

    pub(crate) fn brotli(inner: BrotliBody<B>) -> Self {
        Self::Brotli { inner }
    }

    pub(crate) fn zstd(inner: WrapBody<ZstdDecoder<B>>) -> Self {
        Self::Zstd { inner }
    }

    pub(crate) fn identity(inner: B) -> Self {
        Self::Identity { inner }
    }
}

impl<B> StreamingBody for DecompressionBody<B>
where
    B: StreamingBody<Error: Into<BoxError>>,
{
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.project();
        let decoded = match this.inner.project() {
            BodyInnerProj::Empty { .. } => return Poll::Ready(None),
            BodyInnerProj::Identity { inner } => {
                return match ready!(inner.poll_frame(cx)) {
                    Some(Ok(frame)) => Poll::Ready(Some(Ok(
                        frame.map_data(|mut buf| buf.copy_to_bytes(buf.remaining()))
                    ))),
                    Some(Err(err)) => Poll::Ready(Some(Err(err.into()))),
                    None => Poll::Ready(None),
                };
            }
            BodyInnerProj::Gzip { inner } => ready!(inner.poll_frame(cx)),
            BodyInnerProj::Deflate { inner } => ready!(inner.poll_frame(cx)),
            BodyInnerProj::Brotli { inner } => ready!(inner.poll_frame(cx)),
            BodyInnerProj::Zstd { inner } => ready!(inner.poll_frame(cx)),
        };
        if let (Some(budget), Some(Ok(frame))) = (this.decoded_budget.as_mut(), &decoded)
            && let Some(data) = frame.data_ref()
        {
            if data.len() > *budget {
                *budget = 0;
                return Poll::Ready(Some(Err(LengthLimitError::new().into())));
            }
            *budget -= data.len();
        }
        Poll::Ready(decoded)
    }

    fn is_end_stream(&self) -> bool {
        match &self.inner {
            BodyInner::Identity { inner } => inner.is_end_stream(),
            BodyInner::Empty { .. } => true,
            _ => false,
        }
    }

    fn size_hint(&self) -> SizeHint {
        match self.inner {
            BodyInner::Identity { ref inner } => inner.size_hint(),
            BodyInner::Empty { .. } => SizeHint::with_exact(0),
            BodyInner::Brotli { .. }
            | BodyInner::Gzip { .. }
            | BodyInner::Deflate { .. }
            | BodyInner::Zstd { .. } => SizeHint::default(),
        }
    }
}

impl_decorate_async_read!(GzipDecoder: |input, _quality| {
    GzipDecoder::new(input)
});

impl_decorate_async_read!(ZlibDecoder: |input, _quality| {
    ZlibDecoder::new(input)
});

/// RFC 9659 §3: a "zstd" content coding never needs a window above 8 MiB.
const ZSTD_MAX_WINDOW_LOG: u32 = 23;

impl_decorate_async_read!(ZstdDecoder: |input, _quality| {
    let mut decoder =
        ZstdDecoder::with_params(input, &[DParameter::window_log_max(ZSTD_MAX_WINDOW_LOG)]);
    decoder.multiple_members(true);
    decoder
});

pin_project! {
    /// Brotli decoder input that rejects a stream header asking for a large window
    /// (RFC 7932 §9.1 marks that WBITS pattern invalid): a few bytes could demand up to 1 GiB.
    pub(crate) struct BrotliWindowGuard<R> {
        #[pin]
        inner: R,
        checked: bool,
    }
}

/// Low 7 bits of a stream header using the invalid `0010001` WBITS code.
const BROTLI_LARGE_WINDOW_HEADER: u8 = 0b001_0001;

impl<R: AsyncRead> AsyncRead for BrotliWindowGuard<R> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.project().inner.poll_read(cx, buf)
    }
}

impl<R: AsyncBufRead> AsyncBufRead for BrotliWindowGuard<R> {
    fn poll_fill_buf(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<&[u8]>> {
        let this = self.project();
        let buf = ready!(this.inner.poll_fill_buf(cx))?;
        if !*this.checked
            && let Some(&first) = buf.first()
        {
            *this.checked = true;
            if first & 0x7f == BROTLI_LARGE_WINDOW_HEADER {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "brotli stream requests a large window",
                )));
            }
        }
        Poll::Ready(Ok(buf))
    }

    fn consume(self: Pin<&mut Self>, amt: usize) {
        self.project().inner.consume(amt);
    }
}

impl<B> DecorateAsyncRead for BrotliWindowGuard<B>
where
    B: StreamingBody,
{
    type Input = AsyncReadBody<B>;
    type Output = BrotliDecoder<BrotliWindowGuard<Self::Input>>;

    fn apply(input: Self::Input, _quality: CompressionLevel) -> Self::Output {
        BrotliDecoder::new(BrotliWindowGuard {
            inner: input,
            checked: false,
        })
    }

    fn get_pin_mut(pinned: Pin<&mut Self::Output>) -> Pin<&mut Self::Input> {
        pinned.get_pin_mut().project().inner
    }
}
