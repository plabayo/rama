#![allow(unused_imports)]

use crate::error::BoxError;
use crate::http::dep::http_body::{Body, Frame};
use crate::http::layer::util::compression::{
    AsyncReadBody, BodyIntoStream, CompressionLevel, DecorateAsyncRead, WrapBody,
};
use crate::http::HeaderMap;

use async_compression::tokio::bufread::{BrotliEncoder, GzipEncoder, ZlibEncoder, ZstdEncoder};

use bytes::{Buf, Bytes};
use futures_lite::ready;
use pin_project_lite::pin_project;
use std::{
    io,
    marker::PhantomData,
    pin::Pin,
    task::{Context, Poll},
};
use tokio_util::io::StreamReader;

use super::pin_project_cfg::pin_project_cfg;

pin_project! {
    /// Response body of [`Compression`].
    ///
    /// [`Compression`]: super::Compression
    pub struct CompressionBody<B>
    where
        B: Body,
    {
        #[pin]
        pub(crate) inner: BodyInner<B>,
    }
}

impl<B> Default for CompressionBody<B>
where
    B: Body + Default,
{
    fn default() -> Self {
        Self {
            inner: BodyInner::Identity {
                inner: B::default(),
            },
        }
    }
}

impl<B> CompressionBody<B>
where
    B: Body,
{
    pub(crate) fn new(inner: BodyInner<B>) -> Self {
        Self { inner }
    }
}

type GzipBody<B> = WrapBody<GzipEncoder<B>>;

type DeflateBody<B> = WrapBody<ZlibEncoder<B>>;

type BrotliBody<B> = WrapBody<BrotliEncoder<B>>;

type ZstdBody<B> = WrapBody<ZstdEncoder<B>>;

pin_project_cfg! {
    #[project = BodyInnerProj]
    pub(crate) enum BodyInner<B>
    where
        B: Body,
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

impl<B: Body> BodyInner<B> {
    pub(crate) fn gzip(inner: WrapBody<GzipEncoder<B>>) -> Self {
        Self::Gzip { inner }
    }

    pub(crate) fn deflate(inner: WrapBody<ZlibEncoder<B>>) -> Self {
        Self::Deflate { inner }
    }

    pub(crate) fn brotli(inner: WrapBody<BrotliEncoder<B>>) -> Self {
        Self::Brotli { inner }
    }

    pub(crate) fn zstd(inner: WrapBody<ZstdEncoder<B>>) -> Self {
        Self::Zstd { inner }
    }

    pub(crate) fn identity(inner: B) -> Self {
        Self::Identity { inner }
    }
}

impl<B> Body for CompressionBody<B>
where
    B: Body,
    B::Error: Into<BoxError>,
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
}

impl<B> DecorateAsyncRead for GzipEncoder<B>
where
    B: Body,
{
    type Input = AsyncReadBody<B>;
    type Output = GzipEncoder<Self::Input>;

    fn apply(input: Self::Input, quality: CompressionLevel) -> Self::Output {
        GzipEncoder::with_quality(input, quality.into_async_compression())
    }

    fn get_pin_mut(pinned: Pin<&mut Self::Output>) -> Pin<&mut Self::Input> {
        pinned.get_pin_mut()
    }
}

impl<B> DecorateAsyncRead for ZlibEncoder<B>
where
    B: Body,
{
    type Input = AsyncReadBody<B>;
    type Output = ZlibEncoder<Self::Input>;

    fn apply(input: Self::Input, quality: CompressionLevel) -> Self::Output {
        ZlibEncoder::with_quality(input, quality.into_async_compression())
    }

    fn get_pin_mut(pinned: Pin<&mut Self::Output>) -> Pin<&mut Self::Input> {
        pinned.get_pin_mut()
    }
}

impl<B> DecorateAsyncRead for BrotliEncoder<B>
where
    B: Body,
{
    type Input = AsyncReadBody<B>;
    type Output = BrotliEncoder<Self::Input>;

    fn apply(input: Self::Input, quality: CompressionLevel) -> Self::Output {
        // The brotli crate used under the hood here has a default compression level of 11,
        // which is the max for brotli. This causes extremely slow compression times, so we
        // manually set a default of 4 here.
        //
        // This is the same default used by NGINX for on-the-fly brotli compression.
        let level = match quality {
            CompressionLevel::Default => async_compression::Level::Precise(4),
            other => other.into_async_compression(),
        };
        BrotliEncoder::with_quality(input, level)
    }

    fn get_pin_mut(pinned: Pin<&mut Self::Output>) -> Pin<&mut Self::Input> {
        pinned.get_pin_mut()
    }
}

impl<B> DecorateAsyncRead for ZstdEncoder<B>
where
    B: Body,
{
    type Input = AsyncReadBody<B>;
    type Output = ZstdEncoder<Self::Input>;

    fn apply(input: Self::Input, quality: CompressionLevel) -> Self::Output {
        ZstdEncoder::with_quality(input, quality.into_async_compression())
    }

    fn get_pin_mut(pinned: Pin<&mut Self::Output>) -> Pin<&mut Self::Input> {
        pinned.get_pin_mut()
    }
}
