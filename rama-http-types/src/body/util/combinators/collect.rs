use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};

use crate::body::StreamingBody;
use pin_project_lite::pin_project;

pin_project! {
    /// Future that resolves into a [`Collected`].
    ///
    /// [`Collected`]: crate::Collected
    pub struct Collect<T>
    where
        T: StreamingBody,
        T: ?Sized,
    {
        pub(crate) collected: Option<crate::body::util::Collected<T::Data>>,
        #[pin]
        pub(crate) body: T,
    }
}

impl<T: StreamingBody + ?Sized> Future for Collect<T> {
    type Output = Result<crate::body::util::Collected<T::Data>, T::Error>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> std::task::Poll<Self::Output> {
        let mut me = self.project();

        loop {
            let frame = futures_util::ready!(me.body.as_mut().poll_frame(cx));

            let frame = if let Some(frame) = frame {
                frame?
            } else {
                return Poll::Ready(Ok(me.collected.take().expect("polled after complete")));
            };

            me.collected.as_mut().unwrap().push_frame(frame);
        }
    }
}
