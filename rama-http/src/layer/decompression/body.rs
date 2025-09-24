#![allow(unused_imports)]

use crate::HeaderMap;
use crate::body::{Body, Frame, SizeHint, StreamingBody};
use crate::layer::util::compression::{
    AsyncReadBody, BodyIntoStream, CompressionLevel, DecorateAsyncRead, WrapBody,
};
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
        }
    }
}

impl<B> DecompressionBody<B>
where
    B: StreamingBody,
{
    pub(crate) fn new(inner: BodyInner<B>) -> Self {
        Self { inner }
    }
}

type GzipBody<B> = WrapBody<GzipDecoder<B>>;
type DeflateBody<B> = WrapBody<ZlibDecoder<B>>;
type BrotliBody<B> = WrapBody<BrotliDecoder<B>>;
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
    }
}

impl<B: StreamingBody> BodyInner<B> {
    pub(crate) fn gzip(inner: WrapBody<GzipDecoder<B>>) -> Self {
        Self::Gzip { inner }
    }

    pub(crate) fn deflate(inner: WrapBody<ZlibDecoder<B>>) -> Self {
        Self::Deflate { inner }
    }

    pub(crate) fn brotli(inner: WrapBody<BrotliDecoder<B>>) -> Self {
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
        match self.project().inner.project() {
            BodyInnerProj::Gzip { inner } => inner.poll_frame(cx),
            BodyInnerProj::Deflate { inner } => inner.poll_frame(cx),
            BodyInnerProj::Brotli { inner } => inner.poll_frame(cx),
            BodyInnerProj::Zstd { inner } => inner.poll_frame(cx),
            BodyInnerProj::Identity { inner } => match ready!(inner.poll_frame(cx)) {
                Some(Ok(frame)) => {
                    let frame = frame.map_data(|mut buf| buf.copy_to_bytes(buf.remaining()));
                    Poll::Ready(Some(Ok(frame)))
                }
                Some(Err(err)) => Poll::Ready(Some(Err(err.into()))),
                None => Poll::Ready(None),
            },
        }
    }

    fn size_hint(&self) -> SizeHint {
        match self.inner {
            BodyInner::Identity { ref inner } => inner.size_hint(),
            _ => SizeHint::default(),
        }
    }
}

impl<B> DecorateAsyncRead for GzipDecoder<B>
where
    B: StreamingBody,
{
    type Input = AsyncReadBody<B>;
    type Output = GzipDecoder<Self::Input>;

    fn apply(input: Self::Input, _quality: CompressionLevel) -> Self::Output {
        let mut decoder = GzipDecoder::new(input);
        decoder.multiple_members(true);
        decoder
    }

    fn get_pin_mut(pinned: Pin<&mut Self::Output>) -> Pin<&mut Self::Input> {
        pinned.get_pin_mut()
    }
}

impl<B> DecorateAsyncRead for ZlibDecoder<B>
where
    B: StreamingBody,
{
    type Input = AsyncReadBody<B>;
    type Output = ZlibDecoder<Self::Input>;

    fn apply(input: Self::Input, _quality: CompressionLevel) -> Self::Output {
        ZlibDecoder::new(input)
    }

    fn get_pin_mut(pinned: Pin<&mut Self::Output>) -> Pin<&mut Self::Input> {
        pinned.get_pin_mut()
    }
}

impl<B> DecorateAsyncRead for BrotliDecoder<B>
where
    B: StreamingBody,
{
    type Input = AsyncReadBody<B>;
    type Output = BrotliDecoder<Self::Input>;

    fn apply(input: Self::Input, _quality: CompressionLevel) -> Self::Output {
        BrotliDecoder::new(input)
    }

    fn get_pin_mut(pinned: Pin<&mut Self::Output>) -> Pin<&mut Self::Input> {
        pinned.get_pin_mut()
    }
}

impl<B> DecorateAsyncRead for ZstdDecoder<B>
where
    B: StreamingBody,
{
    type Input = AsyncReadBody<B>;
    type Output = ZstdDecoder<Self::Input>;

    fn apply(input: Self::Input, _quality: CompressionLevel) -> Self::Output {
        let mut decoder = ZstdDecoder::new(input);
        decoder.multiple_members(true);
        decoder
    }

    fn get_pin_mut(pinned: Pin<&mut Self::Output>) -> Pin<&mut Self::Input> {
        pinned.get_pin_mut()
    }
}
