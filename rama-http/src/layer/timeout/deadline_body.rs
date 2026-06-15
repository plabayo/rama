use super::TimeoutError;
use crate::body::{Frame, SizeHint, StreamingBody};
use pin_project_lite::pin_project;
use rama_core::error::{BoxError, ErrorContext as _};
use std::{
    pin::Pin,
    task::{Context, Poll, ready},
    time::Duration,
};
use tokio::time::{Sleep, sleep};

pin_project! {
    /// Wrapper around a [`Body`][`http_body::Body`] that enforces a hard deadline on the entire body transfer.
    ///
    /// Unlike [`TimeoutBody`][super::TimeoutBody], which resets its deadline each time a frame is
    /// received, `DeadlineBody` starts a single timer at construction and returns a
    /// [`TimeoutError`] if the body is not fully consumed before the deadline.
    ///
    /// The deadline is **wall-clock time from construction**, not cumulative poll time. The
    /// timer continues to count even if the consumer is not actively polling the body. If you
    /// poll some frames, pause to do other work, and then resume, the elapsed pause time counts
    /// toward the deadline.
    ///
    /// # When to use this
    ///
    /// This is primarily useful as middleware on public-facing endpoints where you want to bound
    /// the total wall-clock time a single request can hold resources (task slots, memory for
    /// buffering, etc.), regardless of how frequently data trickles in. A slow client sending
    /// one byte per second will never trip [`TimeoutBody`][super::TimeoutBody]'s idle timeout,
    /// but will correctly trip `DeadlineBody`.
    ///
    /// If you only need to detect stalled connections where no data flows for a period, use
    /// [`TimeoutBody`][super::TimeoutBody] instead. The two can be stacked if you want both
    /// an idle timeout and a hard deadline.
    pub struct DeadlineBody<B> {
        #[pin]
        sleep: Sleep,
        #[pin]
        body: B,
    }
}

impl<B> DeadlineBody<B> {
    /// Creates a new [`DeadlineBody`].
    ///
    /// The timeout starts immediately. If the body is not fully consumed within `timeout`,
    /// subsequent `poll_frame` calls will return a [`TimeoutError`].
    pub fn new(timeout: Duration, body: B) -> Self {
        Self {
            sleep: sleep(timeout),
            body,
        }
    }
}

impl<B> StreamingBody for DeadlineBody<B>
where
    B: StreamingBody,
    B::Error: Into<BoxError>,
{
    type Data = B::Data;
    type Error = BoxError;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.project();

        // Error if the absolute deadline has expired.
        if this.sleep.poll(cx) == Poll::Ready(()) {
            return Poll::Ready(Some(Err(Box::new(TimeoutError(())))));
        }

        // Check for body data.
        let frame = ready!(this.body.poll_frame(cx));

        Poll::Ready(frame.transpose().into_box_error().transpose())
    }

    fn is_end_stream(&self) -> bool {
        self.body.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.body.size_hint()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::body::util::BodyExt;
    use pin_project_lite::pin_project;
    use rama_core::bytes::Bytes;
    use std::{error::Error, fmt::Display};

    #[derive(Debug)]
    struct MockError;

    impl Error for MockError {}

    impl Display for MockError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "mock error")
        }
    }

    pin_project! {
        /// A body that yields a single frame after a delay.
        struct MockBody {
            #[pin]
            sleep: Sleep,
        }
    }

    impl StreamingBody for MockBody {
        type Data = Bytes;
        type Error = MockError;

        fn poll_frame(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
            let this = self.project();
            this.sleep
                .poll(cx)
                .map(|()| Some(Ok(Frame::data(vec![].into()))))
        }
    }

    pin_project! {
        /// A body that yields multiple frames with a delay between each.
        struct MultiFrameBody {
            frames_remaining: usize,
            frame_interval: Duration,
            #[pin]
            sleep: Option<Sleep>,
        }
    }

    impl StreamingBody for MultiFrameBody {
        type Data = Bytes;
        type Error = MockError;

        fn poll_frame(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
            let mut this = self.project();

            if *this.frames_remaining == 0 {
                return Poll::Ready(None);
            }

            // Start the sleep if not active.
            let sleep_pinned = if let Some(s) = this.sleep.as_mut().as_pin_mut() {
                s
            } else {
                this.sleep.set(Some(sleep(*this.frame_interval)));
                this.sleep
                    .as_mut()
                    .as_pin_mut()
                    .expect("Some value to be set in previous statement")
            };

            ready!(sleep_pinned.poll(cx));
            this.sleep.set(None);
            *this.frames_remaining -= 1;

            Poll::Ready(Some(Ok(Frame::data(Bytes::from("chunk")))))
        }
    }

    #[tokio::test(start_paused = true)]
    async fn body_completes_within_timeout() {
        let mock_body = MockBody {
            sleep: sleep(Duration::from_millis(50)),
        };
        let timeout_body = DeadlineBody::new(Duration::from_millis(200), mock_body);

        timeout_body
            .boxed()
            .frame()
            .await
            .expect("no frame")
            .expect("frame should arrive before the deadline");
    }

    #[tokio::test(start_paused = true)]
    async fn body_exceeds_timeout() {
        let mock_body = MockBody {
            sleep: sleep(Duration::from_millis(200)),
        };
        let timeout_body = DeadlineBody::new(Duration::from_millis(50), mock_body);

        let result = timeout_body.boxed().frame().await.unwrap();
        assert!(result.is_err());
        assert!(result.unwrap_err().downcast_ref::<TimeoutError>().is_some());
    }

    #[tokio::test(start_paused = true)]
    async fn deadline_fires_despite_steady_frames() {
        // Each frame arrives every 30ms (well within an idle timeout of 100ms),
        // but total transfer takes 5 * 30ms = 150ms, exceeding the 100ms deadline.
        let body = MultiFrameBody {
            frames_remaining: 5,
            frame_interval: Duration::from_millis(30),
            sleep: None,
        };
        let timeout_body = DeadlineBody::new(Duration::from_millis(100), body);

        let mut boxed = timeout_body.boxed();
        let mut got_error = false;

        loop {
            match boxed.frame().await {
                Some(Ok(_)) => {}
                Some(Err(_)) => {
                    got_error = true;
                    break;
                }
                None => break,
            }
        }

        assert!(
            got_error,
            "expected timeout error before all frames arrived"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn all_frames_arrive_within_deadline() {
        // Each frame arrives every 20ms, total = 3 * 20ms = 60ms, within 200ms deadline.
        let body = MultiFrameBody {
            frames_remaining: 3,
            frame_interval: Duration::from_millis(20),
            sleep: None,
        };
        let timeout_body = DeadlineBody::new(Duration::from_millis(200), body);

        let mut boxed = timeout_body.boxed();
        let mut frame_count = 0;

        loop {
            match boxed.frame().await {
                Some(Ok(_)) => frame_count += 1,
                Some(Err(e)) => panic!("unexpected error: {e}"),
                None => break,
            }
        }

        assert_eq!(frame_count, 3);
    }

    /// A body that immediately yields a single inner error.
    struct ErrBody;

    impl StreamingBody for ErrBody {
        type Data = Bytes;
        type Error = MockError;

        fn poll_frame(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
            Poll::Ready(Some(Err(MockError)))
        }
    }

    #[tokio::test(start_paused = true)]
    async fn inner_error_propagates_and_is_not_masked() {
        // A genuine inner-body error before the deadline must surface as that error,
        // not be swallowed or mistaken for a TimeoutError.
        let body = DeadlineBody::new(Duration::from_millis(200), ErrBody);
        let err = body.boxed().frame().await.unwrap().unwrap_err();
        assert!(
            err.downcast_ref::<MockError>().is_some(),
            "inner error should be preserved"
        );
        assert!(
            err.downcast_ref::<TimeoutError>().is_none(),
            "inner error must not be reported as a deadline timeout"
        );
    }
}
