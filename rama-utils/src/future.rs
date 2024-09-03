//! future utils
//!
//! usually because missing or out of scope from futures-lite

use pin_project_lite::pin_project;
use std::{
    fmt,
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};

pin_project! {
    /// Future for the [`fuse`](super::FutureExt::fuse) method.
    #[must_use = "futures do nothing unless polled"]
    pub struct Fuse<Fut: Future> {
        #[pin]
        future: Option<Fut>,
    }
}

impl<Fut: Future + fmt::Debug> fmt::Debug for Fuse<Fut> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Fuse")
            .field("future", &self.future)
            .finish()
    }
}

impl<Fut: Future> Fuse<Fut> {
    /// Create a new [`Fuse`].
    pub fn new(future: Fut) -> Self {
        Self {
            future: Some(future),
        }
    }
}

impl<Fut: Future> Future for Fuse<Fut> {
    type Output = Fut::Output;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Fut::Output> {
        match self.as_mut().project().future.as_pin_mut() {
            Some(fut) => fut.poll(cx).map(|output| {
                self.project().future.set(None);
                output
            }),
            None => Poll::Pending,
        }
    }
}
