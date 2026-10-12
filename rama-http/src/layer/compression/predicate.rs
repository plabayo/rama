//! Predicates for influencing compression of responses.

use std::{
    pin::Pin,
    task::{Context, Poll},
};

use pin_project_lite::pin_project;
use rama_core::extensions::{Extension, Extensions, ExtensionsRef};
use rama_http_types::{
    HeaderMap, Response, StatusCode, StreamingBody, Version,
    body::{Frame, SizeHint},
    header::{self, content_type::extract_essence},
};
use rama_utils::str::{
    arcstr::{ArcStr, arcstr},
    starts_with_ignore_ascii_case,
};

use crate::headers::encoding::Encoding;
use crate::layer::decompression::DecompressedFrom;

pin_project! {
    /// A body reported as of unknown size: the empty body of a HEAD response says nothing about
    /// the size of the GET one it describes.
    struct UnknownSize<B> {
        #[pin]
        inner: B,
    }
}

impl<B: StreamingBody> StreamingBody for UnknownSize<B> {
    type Data = B::Data;
    type Error = B::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        self.project().inner.poll_frame(cx)
    }

    fn size_hint(&self) -> SizeHint {
        SizeHint::default()
    }
}

/// Run `predicate` as it would decide for the GET a HEAD response describes (RFC 9110 §9.3.2):
/// size predicates then see its declared length, or an unknown one, never its empty body.
pub(crate) fn should_compress_as_get<P, B>(
    predicate: &P,
    response: Response<B>,
    is_head: bool,
) -> (bool, Response<B>)
where
    P: Predicate,
    B: StreamingBody,
{
    if !is_head {
        let mut response = response;
        let decision = predicate.should_compress(&mut response);
        return (decision, response);
    }
    let (parts, inner) = response.into_parts();
    let mut probe = Response::from_parts(parts, UnknownSize { inner });
    let decision = predicate.should_compress(&mut probe);
    let (parts, UnknownSize { inner }) = probe.into_parts();
    (decision, Response::from_parts(parts, inner))
}

/// Predicate used to determine if a response should be compressed or not.
pub trait Predicate: Clone {
    /// Should this response be compressed or not?
    ///
    /// The response is mutable so predicates can attach extensions used later
    /// during response-time compression negotiation.
    fn should_compress<B>(&self, response: &mut rama_http_types::Response<B>) -> bool
    where
        B: StreamingBody;

    /// Combine two predicates into one.
    ///
    /// The resulting predicate enables compression if both inner predicates do.
    fn and<Other>(self, other: Other) -> And<Self, Other>
    where
        Self: Sized,
        Other: Predicate,
    {
        And {
            lhs: self,
            rhs: other,
        }
    }
}

impl<F> Predicate for F
where
    F: Fn(StatusCode, Version, &HeaderMap, &Extensions) -> bool + Clone,
{
    fn should_compress<B>(&self, response: &mut rama_http_types::Response<B>) -> bool
    where
        B: StreamingBody,
    {
        let status = response.status();
        let version = response.version();
        let headers = response.headers().clone();
        let extensions = response.extensions();
        self(status, version, &headers, extensions)
    }
}

/// Predicate to _always_ compress.
#[derive(Debug, Clone, Default, Copy)]
#[non_exhaustive]
pub struct Always;

impl Always {
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl Predicate for Always {
    fn should_compress<B>(&self, _response: &mut rama_http_types::Response<B>) -> bool
    where
        B: StreamingBody,
    {
        true
    }
}

impl<T> Predicate for Option<T>
where
    T: Predicate,
{
    fn should_compress<B>(&self, response: &mut rama_http_types::Response<B>) -> bool
    where
        B: StreamingBody,
    {
        self.as_ref()
            .map(|inner| inner.should_compress(response))
            .unwrap_or(true)
    }
}

/// Two predicates combined into one.
///
/// Created with [`Predicate::and`]
#[derive(Debug, Clone, Default, Copy)]
pub struct And<Lhs, Rhs> {
    lhs: Lhs,
    rhs: Rhs,
}

impl<Lhs, Rhs> Predicate for And<Lhs, Rhs>
where
    Lhs: Predicate,
    Rhs: Predicate,
{
    fn should_compress<B>(&self, response: &mut rama_http_types::Response<B>) -> bool
    where
        B: StreamingBody,
    {
        self.lhs.should_compress(response) && self.rhs.should_compress(response)
    }
}

/// The default predicate used by [`Compression`] and [`CompressionLayer`].
///
/// This will compress responses unless:
///
/// - They're gRPC, which has its own protocol specific compression scheme.
/// - It's an image as determined by the `content-type` starting with `image/`.
/// - They're Server-Sent Events (SSE) as determined by the `content-type` being `text/event-stream`.
/// - The response is less than 32 bytes.
///
/// # Configuring the defaults
///
/// `DefaultPredicate` doesn't support any configuration. Instead you can build your own predicate
/// by combining types in this module:
///
/// ```rust
/// use rama_utils::str::arcstr::arcstr;
/// use rama_http::layer::compression::predicate::{SizeAbove, NotForContentType, Predicate};
///
/// // slightly large min size than the default 32
/// let predicate = SizeAbove::new(256)
///     // still don't compress gRPC
///     .and(NotForContentType::GRPC)
///     // still don't compress images
///     .and(NotForContentType::IMAGES)
///     // also don't compress JSON
///     .and(NotForContentType::new(arcstr!("application/json")));
/// ```
///
/// [`Compression`]: super::Compression
/// [`CompressionLayer`]: super::CompressionLayer
#[derive(Debug, Clone)]
pub struct DefaultPredicate(
    And<And<And<SizeAbove, NotForContentType>, NotForContentType>, NotForContentType>,
);

impl DefaultPredicate {
    /// Create a new `DefaultPredicate`.
    #[must_use]
    pub fn new() -> Self {
        let inner = SizeAbove::new(SizeAbove::DEFAULT_MIN_SIZE)
            .and(NotForContentType::GRPC)
            .and(NotForContentType::IMAGES)
            .and(NotForContentType::SSE);
        Self(inner)
    }
}

impl Default for DefaultPredicate {
    fn default() -> Self {
        Self::new()
    }
}

impl Predicate for DefaultPredicate {
    fn should_compress<B>(&self, response: &mut rama_http_types::Response<B>) -> bool
    where
        B: StreamingBody,
    {
        self.0.should_compress(response)
    }
}

#[derive(Debug, Clone)]
pub struct DefaultStreamPredicate(And<SizeAbove, NotForContentType>);

impl DefaultStreamPredicate {
    /// Create a new `DefaultStreamPredicate`.
    #[must_use]
    pub fn new() -> Self {
        let inner = SizeAbove::new(SizeAbove::DEFAULT_MIN_SIZE).and(NotForContentType::IMAGES);
        Self(inner)
    }
}

impl Default for DefaultStreamPredicate {
    fn default() -> Self {
        Self::new()
    }
}

impl Predicate for DefaultStreamPredicate {
    fn should_compress<B>(&self, response: &mut rama_http_types::Response<B>) -> bool
    where
        B: StreamingBody,
    {
        self.0.should_compress(response)
    }
}

/// Preferred response encoding requested by a compression predicate.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Extension)]
#[extension(tags(http))]
pub enum PreferredEncoding {
    #[default]
    Gzip,
    Deflate,
    Brotli,
    Zstd,
}

impl PreferredEncoding {
    #[must_use]
    pub const fn as_encoding(self) -> Encoding {
        match self {
            Self::Gzip => Encoding::Gzip,
            Self::Deflate => Encoding::Deflate,
            Self::Brotli => Encoding::Brotli,
            Self::Zstd => Encoding::Zstd,
        }
    }
}

/// [`Predicate`] that enables compression only for responses previously
/// decompressed by Rama's [`crate::layer::decompression::DecompressionLayer`],
/// while preferring the original upstream encoding for recompression.
#[derive(Debug, Clone, Copy, Default)]
#[non_exhaustive]
pub struct MirrorDecompressed;

impl MirrorDecompressed {
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl Predicate for MirrorDecompressed {
    fn should_compress<B>(&self, response: &mut rama_http_types::Response<B>) -> bool
    where
        B: StreamingBody,
    {
        let preferred = match response.extensions().get_ref::<DecompressedFrom>() {
            Some(DecompressedFrom::Gzip) => PreferredEncoding::Gzip,
            Some(DecompressedFrom::Deflate) => PreferredEncoding::Deflate,
            Some(DecompressedFrom::Brotli) => PreferredEncoding::Brotli,
            Some(DecompressedFrom::Zstd) => PreferredEncoding::Zstd,
            None => return false,
        };

        response.extensions().insert(preferred);
        true
    }
}

/// [`Predicate`] that will only allow compression of responses above a certain size.
#[derive(Clone, Copy, Debug)]
pub struct SizeAbove(u64);

impl SizeAbove {
    pub(crate) const DEFAULT_MIN_SIZE: u64 = 32;

    /// Create a new `SizeAbove` predicate that will only compress responses larger than
    /// `min_size_bytes`.
    ///
    /// The response will be compressed if the exact size cannot be determined through either the
    /// `content-length` header or [`StreamingBody::size_hint`].
    #[must_use]
    pub const fn new(min_size_bytes: u64) -> Self {
        Self(min_size_bytes)
    }
}

impl Default for SizeAbove {
    fn default() -> Self {
        Self(Self::DEFAULT_MIN_SIZE)
    }
}

impl Predicate for SizeAbove {
    fn should_compress<B>(&self, response: &mut rama_http_types::Response<B>) -> bool
    where
        B: StreamingBody,
    {
        let content_size = response.body().size_hint().exact().or_else(|| {
            response
                .headers()
                .get(header::CONTENT_LENGTH)
                .and_then(|h| h.to_str().ok())
                .and_then(|val| val.parse().ok())
        });

        match content_size {
            Some(size) => size >= self.0,
            _ => true,
        }
    }
}

/// Predicate that won't allow responses with a specific `content-type` to be compressed.
#[derive(Clone, Debug)]
pub struct NotForContentType {
    content_type: ArcStr,
    exception: Option<ArcStr>,
}

impl NotForContentType {
    /// Predicate that won't compress gRPC responses.
    pub const GRPC: Self = Self {
        content_type: arcstr!("application/grpc"),
        exception: Some(arcstr!("application/grpc-web")),
    };

    /// Predicate that won't compress images.
    pub const IMAGES: Self = Self {
        content_type: arcstr!("image/"),
        exception: Some(arcstr!("image/svg+xml")),
    };

    /// Predicate that won't compress Server-Sent Events (SSE) responses.
    pub const SSE: Self = Self::new(arcstr!("text/event-stream"));

    /// Create a new `NotForContentType`.
    #[must_use]
    pub const fn new(content_type: ArcStr) -> Self {
        Self {
            content_type,
            exception: None,
        }
    }
}

impl Predicate for NotForContentType {
    fn should_compress<B>(&self, response: &mut rama_http_types::Response<B>) -> bool
    where
        B: StreamingBody,
    {
        let essence = extract_essence(response.headers().get_all(header::CONTENT_TYPE));
        let essence = essence.as_deref().unwrap_or_default();
        if let Some(except) = &self.exception
            && starts_with_ignore_ascii_case(essence, except.as_str())
        {
            return true;
        }

        !starts_with_ignore_ascii_case(essence, self.content_type.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Body, Response};

    /// The type is the one a browser extracts from several lines: the last valid one.
    #[test]
    fn not_for_content_type_reads_every_line() {
        for (lines, compress) in [
            (&["image/png"][..], false),
            (&["Image/PNG"], false),
            (&["image/svg+xml"], true),
            (&["text/html", "image/png"], false),
            (&["image/png", "text/html"], true),
            (&["image/png", "cannot-parse"], false),
        ] {
            let mut response = Response::new(Body::empty());
            for line in lines {
                response.headers_mut().append(
                    header::CONTENT_TYPE,
                    rama_http_types::HeaderValue::from_static(line),
                );
            }
            assert_eq!(
                NotForContentType::IMAGES.should_compress(&mut response),
                compress,
                "{lines:?}"
            );
        }
    }
}
