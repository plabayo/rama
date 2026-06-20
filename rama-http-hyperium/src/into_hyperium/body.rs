//! Wrap a rama [`Body`](rama_body::Body) so it implements the external
//! [`http_body::Body`], for handing rama bodies to the `http`/`tower` ecosystem.

use std::fmt;
use std::pin::Pin;
use std::task::{Context, Poll};

use pin_project_lite::pin_project;
use rama_http_types::http_body as rama_body;

use super::TryIntoHyperiumHttp as _;

fn size_hint_to_hyperium(hint: &rama_body::SizeHint) -> http_body::SizeHint {
    let mut out = http_body::SizeHint::new();
    out.set_lower(hint.lower());
    if let Some(upper) = hint.upper() {
        out.set_upper(upper);
    }
    out
}

pin_project! {
    /// Wraps a rama [`Body`](rama_body::Body) so it implements the external
    /// [`http_body::Body`].
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

/// Error produced by a [`HyperiumBody`]: either the wrapped rama body failed, or
/// its trailers couldn't be converted to the hyperium `HeaderMap`.
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
