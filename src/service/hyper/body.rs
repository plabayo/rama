use std::{
    pin::Pin,
    task::{Context, Poll},
};

use http_body::{Body as HttpBody, Frame, SizeHint};
use hyper::body::Incoming;

pin_project_lite::pin_project! {
    /// A wrapper around `hyper::body::Incoming` that implements `http_body::Body`.
    ///
    /// This type is used to bridge the `hyper` and `tower-async` ecosystems.
    /// Reason is that a lot of middlewares in `tower-async-http` that
    /// operate on `http_body::Body` which also have to implement `Default`.
    #[derive(Debug, Default)]
    pub struct Body {
        #[pin]
        inner: Option<Incoming>,
    }
}

impl From<Incoming> for Body {
    fn from(inner: Incoming) -> Self {
        Self { inner: Some(inner) }
    }
}

impl Body {
    /// Return a reference to the inner [`hyper::body::Incoming`] value.
    ///
    /// This is normally not needed,
    /// but in case you do ever need it, it's here.
    pub fn as_ref(&self) -> Option<&Incoming> {
        self.inner.as_ref()
    }

    /// Return a mutable reference to the inner [`hyper::body::Incoming`] value.
    ///
    /// This is normally not needed,
    /// but in case you do ever need it, it's here.
    pub fn as_mut(&mut self) -> Option<&mut Incoming> {
        self.inner.as_mut()
    }

    /// Turn this [`Body`] into the inner [`hyper::body::Incoming`] value.
    ///
    /// This is normally not needed,
    /// but in case you do ever need it, it's here.
    pub fn into_inner(self) -> Option<Incoming> {
        self.inner
    }
}

impl HttpBody for Body {
    type Data = <Incoming as HttpBody>::Data;
    type Error = <Incoming as HttpBody>::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        self.project()
            .inner
            .as_pin_mut()
            .map(|incoming| incoming.poll_frame(cx))
            .unwrap_or_else(|| Poll::Ready(None))
    }

    fn is_end_stream(&self) -> bool {
        self.inner
            .as_ref()
            .map(|incoming| incoming.is_end_stream())
            .unwrap_or(true)
    }

    fn size_hint(&self) -> SizeHint {
        self.inner
            .as_ref()
            .map(|incoming| incoming.size_hint())
            .unwrap_or_default()
    }
}
