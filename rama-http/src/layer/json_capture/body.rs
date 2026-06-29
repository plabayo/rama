//! Streaming request or response [`Body`](crate::Body)
//! that captures selected JSON values while forwarding frames.

use std::pin::Pin;
use std::task::{Context, Poll};

use pin_project_lite::pin_project;
use rama_core::bytes::{Buf, Bytes};
use rama_core::error::BoxError;
use rama_core::futures::ready;
use rama_json::capture::{CaptureHandler, JsonCapturer};
use rama_json::path::JsonPath;
use rama_json::tokenizer::DEFAULT_MAX_BUFFERED_BYTES;

use crate::body::{Frame, SizeHint, StreamingBody};

/// Completion hook, handed the finalized handler once capture ends.
/// `Send + Sync` so the body keeps satisfying [`Body::new`](crate::Body::new).
type OnEnd<H> = Box<dyn FnOnce(H) + Send + Sync>;

pin_project! {
    /// A body that feeds the inner body's bytes through a
    /// [`JsonCapturer`], forwarding the body unchanged as [`Bytes`].
    ///
    /// Build it directly with [`new`](Self::new). Attach
    /// [`on_end`](Self::on_end) to recover the handler and any state it
    /// accumulated once the body finishes cleanly.
    pub struct JsonCaptureBody<B, H> {
        #[pin]
        inner: B,
        // `None` => passthrough; `Some` => actively capturing.
        capturer: Option<JsonCapturer<H>>,
        // Fired once after `end()` on clean termination; `None` => no hook.
        on_end: Option<OnEnd<H>>,
        done: bool,
    }
}

impl<B, H> JsonCaptureBody<B, H>
where
    H: CaptureHandler,
{
    /// Wraps `inner`, capturing values matching `selectors` with `handler`
    /// (the `selector` index used internally is the index into `selectors`).
    pub fn new(inner: B, selectors: &[JsonPath], max_capture_bytes: usize, handler: H) -> Self {
        Self::with_max_buffered_bytes(
            inner,
            selectors,
            max_capture_bytes,
            DEFAULT_MAX_BUFFERED_BYTES,
            handler,
        )
    }

    /// Wraps `inner` with a custom tokenizer buffered-input limit.
    pub fn with_max_buffered_bytes(
        inner: B,
        selectors: &[JsonPath],
        max_capture_bytes: usize,
        max_buffered_bytes: usize,
        handler: H,
    ) -> Self {
        Self {
            inner,
            capturer: Some(JsonCapturer::with_max_buffered_bytes(
                selectors,
                max_capture_bytes,
                max_buffered_bytes,
                handler,
            )),
            on_end: None,
            done: false,
        }
    }
}

impl<B, H> JsonCaptureBody<B, H> {
    /// Wraps `inner` without capturing - frames pass through unchanged (their
    /// data type normalized to [`Bytes`]).
    pub fn passthrough(inner: B) -> Self {
        Self {
            inner,
            capturer: None,
            on_end: None,
            done: false,
        }
    }

    /// Installs a completion hook, handed the finalized handler by value
    /// after capture ends - for reading state it accumulated.
    ///
    /// Fires once after [`JsonCapturer::end`] on clean termination (inner EOF
    /// or trailers); not on the error path, nor in
    /// [`passthrough`](Self::passthrough) mode (no handler). A later call
    /// replaces an earlier hook.
    #[must_use]
    pub fn on_end<F>(mut self, on_end: F) -> Self
    where
        F: FnOnce(H) + Send + Sync + 'static,
    {
        self.on_end = Some(Box::new(on_end));
        self
    }
}

/// Hands the spent capturer's handler to the hook, if one is installed.
fn fire_on_end<H: CaptureHandler>(
    capturer: &mut Option<JsonCapturer<H>>,
    on_end: &mut Option<OnEnd<H>>,
) {
    if let (Some(capturer), Some(on_end)) = (capturer.take(), on_end.take()) {
        on_end(capturer.into_handler());
    }
}

impl<B, H> StreamingBody for JsonCaptureBody<B, H>
where
    B: StreamingBody<Error: Into<BoxError>>,
    H: CaptureHandler,
{
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let mut this = self.project();

        if *this.done {
            return Poll::Ready(None);
        }

        let Some(capturer) = this.capturer.as_mut() else {
            return match ready!(this.inner.as_mut().poll_frame(cx)) {
                Some(Ok(frame)) => Poll::Ready(Some(Ok(normalize_frame(frame)))),
                Some(Err(err)) => Poll::Ready(Some(Err(err.into()))),
                None => {
                    *this.done = true;
                    Poll::Ready(None)
                }
            };
        };

        match ready!(this.inner.as_mut().poll_frame(cx)) {
            Some(Ok(frame)) => match frame.into_data() {
                Ok(mut data) => {
                    let bytes = data.copy_to_bytes(data.remaining());
                    if let Err(err) = capturer.write(&bytes) {
                        return Poll::Ready(Some(Err(err.into())));
                    }
                    Poll::Ready(Some(Ok(Frame::data(bytes))))
                }
                Err(frame) => match frame.into_trailers() {
                    Ok(trailers) => {
                        if let Err(err) = capturer.end() {
                            return Poll::Ready(Some(Err(err.into())));
                        }
                        fire_on_end(this.capturer, this.on_end);
                        *this.done = true;
                        Poll::Ready(Some(Ok(Frame::trailers(trailers))))
                    }
                    Err(_) => Poll::Ready(Some(Ok(Frame::data(Bytes::new())))),
                },
            },
            Some(Err(err)) => Poll::Ready(Some(Err(err.into()))),
            None => {
                *this.done = true;
                if let Err(err) = capturer.end() {
                    return Poll::Ready(Some(Err(err.into())));
                }
                fire_on_end(this.capturer, this.on_end);
                Poll::Ready(None)
            }
        }
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

/// Normalizes a frame's data type to [`Bytes`], preserving trailers.
fn normalize_frame<D: Buf>(frame: Frame<D>) -> Frame<Bytes> {
    match frame.into_data() {
        Ok(mut data) => Frame::data(data.copy_to_bytes(data.remaining())),
        Err(frame) => match frame.into_trailers() {
            Ok(trailers) => Frame::trailers(trailers),
            Err(_) => Frame::data(Bytes::new()),
        },
    }
}
