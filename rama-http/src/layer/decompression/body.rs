#![allow(unused_imports)]

use crate::HeaderMap;
use crate::body::{Body, Frame, SizeHint, StreamingBody};
use crate::layer::util::compression::{
    AsyncReadBody, BodyIntoStream, CompressionLevel, DecorateAsyncRead, WrapBody,
    compressed_body_poll_frame, impl_decorate_async_read,
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
        compressed_body_poll_frame!(self, cx)
    }

    fn size_hint(&self) -> SizeHint {
        match self.inner {
            BodyInner::Identity { ref inner } => inner.size_hint(),
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

impl_decorate_async_read!(BrotliDecoder: |input, _quality| {
    BrotliDecoder::new(input)
});

impl_decorate_async_read!(ZstdDecoder: |input, _quality| {
    let mut decoder = ZstdDecoder::new(input);
    decoder.multiple_members(true);
    decoder
});
