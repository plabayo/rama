#![allow(unused_imports)]

use std::{
    io,
    marker::PhantomData,
    pin::Pin,
    task::{Context, Poll},
};

use async_compression::tokio::bufread::{BrotliEncoder, GzipEncoder, ZlibEncoder, ZstdEncoder};
use pin_project_lite::pin_project;
use rama_core::{
    bytes::{Buf, Bytes},
    error::BoxError,
    futures::ready,
    stream::io::StreamReader,
};
use rama_http_types::{StreamingBody, body::Frame};

use super::pin_project_cfg::pin_project_cfg;
use crate::{
    HeaderMap,
    layer::util::compression::{
        AsyncReadBody, BodyIntoStream, CompressionLevel, DecorateAsyncRead, WrapBody,
        brotli_encoder_params, compressed_body_poll_frame, impl_decorate_async_read,
        zstd_encoder_params,
    },
};

pin_project! {
    /// Response body of [`Compression`].
    ///
    /// [`Compression`]: super::Compression
    pub struct CompressionBody<B>
    where
        B: StreamingBody,
    {
        #[pin]
        pub(crate) inner: BodyInner<B>,
    }
}

impl<B> Default for CompressionBody<B>
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

impl<B> CompressionBody<B>
where
    B: StreamingBody,
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

impl<B> StreamingBody for CompressionBody<B>
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

    fn size_hint(&self) -> rama_http_types::body::SizeHint {
        if let BodyInner::Identity { inner } = &self.inner {
            inner.size_hint()
        } else if matches!(self.inner, BodyInner::Empty { .. }) {
            rama_http_types::body::SizeHint::with_exact(0)
        } else {
            rama_http_types::body::SizeHint::new()
        }
    }

    fn is_end_stream(&self) -> bool {
        if let BodyInner::Identity { inner } = &self.inner {
            inner.is_end_stream()
        } else {
            matches!(self.inner, BodyInner::Empty { .. })
        }
    }
}

impl_decorate_async_read!(GzipEncoder: |input, quality| {
    GzipEncoder::with_quality(input, quality.into_async_compression())
});

impl_decorate_async_read!(ZlibEncoder: |input, quality| {
    ZlibEncoder::with_quality(input, quality.into_async_compression())
});

impl_decorate_async_read!(BrotliEncoder: |input, quality, body_len| {
    BrotliEncoder::with_params(input, brotli_encoder_params(quality, body_len))
});

impl_decorate_async_read!(ZstdEncoder: |input, quality| {
    let (level, window) = zstd_encoder_params(quality);
    ZstdEncoder::with_quality_and_params(
        input,
        async_compression::Level::Precise(level),
        window.as_slice(),
    )
});
