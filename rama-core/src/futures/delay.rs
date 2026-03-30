use pin_project_lite::pin_project;
use std::{
    pin::Pin,
    task::{self, Poll, ready},
    time::Duration,
};
use tokio::time::Sleep;

use super::Stream;

pin_project! {
    /// Stream which has a delay prior to starting...
    #[derive(Debug)]
    #[must_use = "streams do nothing unless polled"]
    pub struct DelayStream<S> {
        #[pin]
        delay: Option<Sleep>,
        has_delayed: bool,

        // The stream to throttle
        #[pin]
        stream: S,
    }
}

impl<S> DelayStream<S> {
    pub fn new(dur: Duration, stream: S) -> Self {
        let has_delayed = dur.is_zero();
        Self {
            delay: (!has_delayed).then(|| tokio::time::sleep(dur)),
            has_delayed,
            stream,
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

impl<T: Stream> Stream for DelayStream<T> {
    type Item = T::Item;

    fn poll_next(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<Option<Self::Item>> {
        let me = self.project();

        if !*me.has_delayed
            && let Some(delay) = me.delay.as_pin_mut()
        {
            ready!(delay.poll(cx));
            *me.has_delayed = true;
        }

        me.stream.poll_next(cx)
    }

    #[inline(always)]
    fn size_hint(&self) -> (usize, Option<usize>) {
        self.stream.size_hint()
    }
}
