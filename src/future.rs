use pin_project_lite::pin_project;
use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};

pin_project! {
    /// Future for the [`fuse`](super::FutureExt::fuse) method.
    #[derive(Debug)]
    #[must_use = "futures do nothing unless polled"]
    pub(crate) struct Fuse<Fut: Future> {
        #[pin]
        future: Option<Fut>,
    }
}

impl<Fut: Future> Fuse<Fut> {
    pub(crate) fn new(future: Fut) -> Self {
        Self {
            future: Some(future),
        }
    }
}

impl<Fut: Future> Future for Fuse<Fut> {
    type Output = Fut::Output;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Fut::Output> {
        // safety: we use this &mut only for matching, not for movement
        let v = match self.as_mut().project().future.as_pin_mut() {
            Some(fut) => {
                // safety: this re-pinned future will never move before being dropped
                match fut.poll(cx) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(v) => v,
                }
            }
            None => return Poll::Pending,
        };

        self.as_mut().project().future.as_pin_mut().take();
        Poll::Ready(v)
    }
}
