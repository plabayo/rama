//! Shared plumbing for the streaming rewrite and capture bodies.

use std::pin::Pin;
use std::task::{Context, Poll};

use rama_core::bytes::{Buf, Bytes};
use rama_core::error::BoxError;
use rama_core::futures::ready;

use crate::body::{Frame, StreamingBody};

/// Completion hook, handed the finalized handler once the body ends.
/// `Send + Sync` so the body keeps satisfying [`Body::new`](crate::Body::new).
pub(crate) type OnEnd<H> = Box<dyn FnOnce(H) + Send + Sync>;

pub(crate) trait IntoHandler<H> {
    fn finish_handler(self) -> H;
}

/// Hands the spent processor's handler to the hook, if one is installed.
pub(crate) fn fire_on_end<P, H>(processor: &mut Option<P>, on_end: &mut Option<OnEnd<H>>)
where
    P: IntoHandler<H>,
{
    if let (Some(processor), Some(on_end)) = (processor.take(), on_end.take()) {
        on_end(processor.finish_handler());
    }
}

/// Normalizes a frame's data type to [`Bytes`], preserving trailers.
pub(crate) fn normalize_frame<D: Buf>(frame: Frame<D>) -> Frame<Bytes> {
    match frame.into_data() {
        Ok(mut data) => Frame::data(data.copy_to_bytes(data.remaining())),
        Err(frame) => match frame.into_trailers() {
            Ok(trailers) => Frame::trailers(trailers),
            // `Frame` is data-or-trailers, so this is unreachable; emit an
            // empty data frame rather than panic.
            Err(_) => Frame::data(Bytes::new()),
        },
    }
}

/// Passthrough: forward frames, normalizing the data type to `Bytes`.
pub(crate) fn poll_passthrough_frame<B>(
    inner: Pin<&mut B>,
    cx: &mut Context<'_>,
    done: &mut bool,
) -> Poll<Option<Result<Frame<Bytes>, BoxError>>>
where
    B: StreamingBody<Error: Into<BoxError>>,
{
    match ready!(inner.poll_frame(cx)) {
        Some(Ok(frame)) => Poll::Ready(Some(Ok(normalize_frame(frame)))),
        Some(Err(err)) => Poll::Ready(Some(Err(err.into()))),
        None => {
            *done = true;
            Poll::Ready(None)
        }
    }
}
