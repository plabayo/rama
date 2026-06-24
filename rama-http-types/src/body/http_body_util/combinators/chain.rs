use std::pin::Pin;
use std::task::{Context, Poll};

use pin_project_lite::pin_project;
use rama_core::error::BoxError;

use crate::body::http_body::{Body, Frame, SizeHint};

pin_project! {
    /// A [`Body`] that yields every frame of `first`, then every frame of `second`.
    ///
    /// This is what makes a bounded collect reversible: the bytes already read
    /// can be re-prepended in front of the unread remainder so the original
    /// body can be forwarded untouched (see [`CollectError::into_full_body`]).
    ///
    /// [`CollectError::into_full_body`]: crate::body::util::CollectError::into_full_body
    pub struct Chain<A, B> {
        first_done: bool,
        #[pin]
        first: A,
        #[pin]
        second: B,
    }
}

impl<A, B> Chain<A, B> {
    /// Create a new [`Chain`] yielding all of `first` before all of `second`.
    pub fn new(first: A, second: B) -> Self {
        Self {
            first_done: false,
            first,
            second,
        }
    }
}

impl<A, B> Body for Chain<A, B>
where
    A: Body,
    B: Body<Data = A::Data>,
    A::Error: Into<BoxError>,
    B::Error: Into<BoxError>,
{
    type Data = A::Data;
    type Error = BoxError;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let mut this = self.project();

        if !*this.first_done {
            match this.first.as_mut().poll_frame(cx) {
                Poll::Ready(Some(Ok(frame))) => return Poll::Ready(Some(Ok(frame))),
                Poll::Ready(Some(Err(err))) => return Poll::Ready(Some(Err(err.into()))),
                Poll::Ready(None) => *this.first_done = true,
                Poll::Pending => return Poll::Pending,
            }
        }

        match this.second.poll_frame(cx) {
            Poll::Ready(Some(Ok(frame))) => Poll::Ready(Some(Ok(frame))),
            Poll::Ready(Some(Err(err))) => Poll::Ready(Some(Err(err.into()))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }

    fn is_end_stream(&self) -> bool {
        self.first_done && self.second.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        let second = self.second.size_hint();
        if self.first_done {
            return second;
        }

        let first = self.first.size_hint();
        let mut hint = SizeHint::new();
        hint.set_lower(first.lower().saturating_add(second.lower()));
        if let (Some(a), Some(b)) = (first.upper(), second.upper()) {
            hint.set_upper(a.saturating_add(b));
        }
        hint
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::body::http_body_util::{BodyExt, Empty, Full};
    use bytes::Bytes;

    #[tokio::test]
    async fn chains_two_full_bodies() {
        let body = Chain::new(
            Full::new(Bytes::from("hello ")),
            Full::new(Bytes::from("world")),
        );
        let out = body.collect().await.unwrap().to_bytes();
        assert_eq!(&out[..], b"hello world");
    }

    #[tokio::test]
    async fn empty_first_yields_only_second() {
        let body = Chain::new(Empty::<Bytes>::new(), Full::new(Bytes::from("tail")));
        let out = body.collect().await.unwrap().to_bytes();
        assert_eq!(&out[..], b"tail");
    }

    #[tokio::test]
    async fn empty_second_yields_only_first() {
        let body = Chain::new(Full::new(Bytes::from("head")), Empty::<Bytes>::new());
        let out = body.collect().await.unwrap().to_bytes();
        assert_eq!(&out[..], b"head");
    }
}
