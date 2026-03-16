use pin_project_lite::pin_project;
use std::{
    pin::Pin,
    task::{self, Poll},
};

use super::Stream;

pin_project! {
    /// Stream which aborts in case the cancel [`Future`] is fulfilled...
    #[derive(Debug)]
    #[must_use = "streams do nothing unless polled"]
    pub struct GracefulStream<S, F> {
        #[pin]
        cancel: F,

        #[pin]
        stream: S,

        done: bool,
    }
}

impl<S, F> GracefulStream<S, F> {
    pub fn new(cancel: F, stream: S) -> Self {
        Self {
            cancel,
            stream,
            done: false,
        }
    }

    /// Acquires a reference to the underlying stream that this combinator is
    /// pulling from.
    pub fn get_ref(&self) -> &S {
        &self.stream
    }

    /// Acquires a mutable reference to the underlying stream that this combinator
    /// is pulling from.
    ///
    /// Note that care must be taken to avoid tampering with the state of the stream
    /// which may otherwise confuse this combinator.
    pub fn get_mut(&mut self) -> &mut S {
        &mut self.stream
    }

    /// Consumes this combinator, returning the underlying stream.
    ///
    /// Note that this may discard intermediate state of this combinator, so care
    /// should be taken to avoid losing resources when this is called.
    pub fn into_inner(self) -> S {
        self.stream
    }
}

impl<S: Stream, F: Future> Stream for GracefulStream<S, F> {
    type Item = S::Item;

    fn poll_next(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<Option<Self::Item>> {
        let mut me = self.project();

        if *me.done {
            tracing::trace!("stream called after cancel triggered");
            return Poll::Ready(None);
        }

        if me.cancel.as_mut().poll(cx).is_ready() {
            tracing::trace!("stream cancelled; return Ready(None)");
            *me.done = true;
            return Poll::Ready(None);
        }

        me.stream.poll_next(cx)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.stream.size_hint()
    }
}
