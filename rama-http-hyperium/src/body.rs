//! Body bridges between rama's forked [`Body`](rama_http_types::http_body::Body)
//! and the external [`http_body::Body`] used by the `http`/`tower`/`hyper`
//! ecosystem.
//!
//! Bodies are wrapped, not copied: only trailer frames are converted (their
//! [`HeaderMap`](rama_http_types::HeaderMap) ↔ `http::HeaderMap`); data frames
//! pass through untouched.

use std::fmt;
use std::pin::Pin;
use std::task::{Context, Poll};

use pin_project_lite::pin_project;
use rama_http_types::http_body as rama_body;

use crate::{TryIntoHyperiumHttp as _, TryIntoRamaHttp as _};

fn size_hint_to_hyperium(hint: &rama_body::SizeHint) -> http_body::SizeHint {
    let mut out = http_body::SizeHint::new();
    out.set_lower(hint.lower());
    if let Some(upper) = hint.upper() {
        out.set_upper(upper);
    }
    out
}

fn size_hint_to_rama(hint: &http_body::SizeHint) -> rama_body::SizeHint {
    let mut out = rama_body::SizeHint::new();
    out.set_lower(hint.lower());
    if let Some(upper) = hint.upper() {
        out.set_upper(upper);
    }
    out
}

pin_project! {
    /// Wraps a rama [`Body`](rama_body::Body) so it implements the external
    /// [`http_body::Body`], for handing rama bodies to the `http`/`tower`
    /// ecosystem.
    pub struct HyperiumBody<B> {
        #[pin]
        inner: B,
    }
}

impl<B> HyperiumBody<B> {
    /// Wrap a rama body.
    pub const fn new(inner: B) -> Self {
        Self { inner }
    }

    /// Unwrap back into the rama body.
    pub fn into_inner(self) -> B {
        self.inner
    }
}

impl<B: rama_body::Body> http_body::Body for HyperiumBody<B> {
    type Data = B::Data;
    type Error = HyperiumBodyError<B::Error>;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<http_body::Frame<Self::Data>, Self::Error>>> {
        match self.project().inner.poll_frame(cx) {
            Poll::Ready(Some(Ok(frame))) => match frame.into_data() {
                Ok(data) => Poll::Ready(Some(Ok(http_body::Frame::data(data)))),
                Err(frame) => match frame.into_trailers() {
                    Ok(trailers) => Poll::Ready(Some(
                        trailers
                            .try_into_hyperium_http()
                            .map(http_body::Frame::trailers)
                            .map_err(HyperiumBodyError::Trailers),
                    )),
                    // rama frames are data or trailers; defensive for any future kind.
                    Err(_) => Poll::Ready(None),
                },
            },
            Poll::Ready(Some(Err(err))) => Poll::Ready(Some(Err(HyperiumBodyError::Body(err)))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> http_body::SizeHint {
        size_hint_to_hyperium(&self.inner.size_hint())
    }
}

pin_project! {
    /// Wraps an external [`http_body::Body`] so it implements rama's
    /// [`Body`](rama_body::Body), for consuming ecosystem bodies inside rama.
    pub struct RamaBody<B> {
        #[pin]
        inner: B,
    }
}

impl<B> RamaBody<B> {
    /// Wrap an external `http_body` body.
    pub const fn new(inner: B) -> Self {
        Self { inner }
    }

    /// Unwrap back into the external body.
    pub fn into_inner(self) -> B {
        self.inner
    }
}

impl<B: http_body::Body> rama_body::Body for RamaBody<B> {
    type Data = B::Data;
    type Error = RamaBodyError<B::Error>;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<rama_body::Frame<Self::Data>, Self::Error>>> {
        match self.project().inner.poll_frame(cx) {
            Poll::Ready(Some(Ok(frame))) => match frame.into_data() {
                Ok(data) => Poll::Ready(Some(Ok(rama_body::Frame::data(data)))),
                Err(frame) => match frame.into_trailers() {
                    Ok(trailers) => Poll::Ready(Some(
                        trailers
                            .try_into_rama_http()
                            .map(rama_body::Frame::trailers)
                            .map_err(RamaBodyError::Trailers),
                    )),
                    // http frames are data or trailers; defensive for any future kind.
                    Err(_) => Poll::Ready(None),
                },
            },
            Poll::Ready(Some(Err(err))) => Poll::Ready(Some(Err(RamaBodyError::Body(err)))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> rama_body::SizeHint {
        size_hint_to_rama(&self.inner.size_hint())
    }
}

/// Error produced by a [`HyperiumBody`]: either the wrapped rama body failed,
/// or its trailers couldn't be converted to the hyperium `HeaderMap`.
#[derive(Debug)]
pub enum HyperiumBodyError<E> {
    /// The wrapped rama body errored.
    Body(E),
    /// Trailer conversion to the hyperium `HeaderMap` failed.
    Trailers(http::Error),
}

impl<E: fmt::Display> fmt::Display for HyperiumBodyError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Body(err) => write!(f, "rama body error: {err}"),
            Self::Trailers(err) => write!(f, "trailer conversion to hyperium failed: {err}"),
        }
    }
}

impl<E: std::error::Error + 'static> std::error::Error for HyperiumBodyError<E> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Body(err) => Some(err),
            Self::Trailers(err) => Some(err),
        }
    }
}

/// Error produced by a [`RamaBody`]: either the wrapped external body failed, or
/// its trailers couldn't be converted to the rama `HeaderMap`.
#[derive(Debug)]
pub enum RamaBodyError<E> {
    /// The wrapped external body errored.
    Body(E),
    /// Trailer conversion to the rama `HeaderMap` failed.
    Trailers(rama_http_types::Error),
}

impl<E: fmt::Display> fmt::Display for RamaBodyError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Body(err) => write!(f, "http body error: {err}"),
            Self::Trailers(err) => write!(f, "trailer conversion to rama failed: {err}"),
        }
    }
}

impl<E: std::error::Error + 'static> std::error::Error for RamaBodyError<E> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Body(err) => Some(err),
            Self::Trailers(err) => Some(err),
        }
    }
}
