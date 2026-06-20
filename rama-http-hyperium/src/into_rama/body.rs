//! Wrap an external [`http_body::Body`] so it implements rama's
//! [`Body`](rama_body::Body), for consuming ecosystem bodies inside rama.

use std::fmt;
use std::pin::Pin;
use std::task::{Context, Poll};

use pin_project_lite::pin_project;
use rama_http_types::http_body as rama_body;

use super::TryIntoRamaHttp as _;

fn size_hint_to_rama(hint: &http_body::SizeHint) -> rama_body::SizeHint {
    let mut out = rama_body::SizeHint::new();
    out.set_lower(hint.lower());
    if let Some(upper) = hint.upper() {
        out.set_upper(upper);
    }
    out
}

pin_project! {
    /// Wraps an external [`http_body::Body`] so it implements rama's
    /// [`Body`](rama_body::Body).
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
