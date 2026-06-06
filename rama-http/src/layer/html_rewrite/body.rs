//! Streaming response [`Body`](crate::Body)
//! that rewrites HTML on the fly.

use std::pin::Pin;
use std::task::{Context, Poll};

use pin_project_lite::pin_project;
use rama_core::bytes::{Buf, Bytes};
use rama_core::error::BoxError;
use rama_core::futures::ready;

use crate::body::{Frame, SizeHint, StreamingBody};
use crate::protocols::html::rewrite::{ElementContentHandler, HtmlRewriter};
use crate::protocols::html::selector::Selector;

pin_project! {
    /// A response body that feeds the inner body's bytes through an
    /// [`HtmlRewriter`], emitting rewritten chunks as they become available.
    ///
    /// Build it directly with [`new`](Self::new) (rewriting) or
    /// [`passthrough`](Self::passthrough) (forward unchanged), or let
    /// [`HtmlRewriteLayer`](super::HtmlRewriteLayer) construct one per
    /// response.
    pub struct HtmlRewriteBody<B, H> {
        #[pin]
        inner: B,
        // `None` => passthrough; `Some` => actively rewriting.
        rewriter: Option<HtmlRewriter<H>>,
        // Set once the inner body has ended and the rewriter is flushed.
        done: bool,
    }
}

impl<B, H> HtmlRewriteBody<B, H>
where
    H: ElementContentHandler,
{
    /// Wraps `inner`, rewriting elements matching `selectors` with `handler`
    /// (the `selector` index passed to the handler is the index into
    /// `selectors`).
    pub fn new(inner: B, selectors: &[Selector], handler: H) -> Self {
        Self {
            inner,
            rewriter: Some(HtmlRewriter::new(selectors, handler)),
            done: false,
        }
    }
}

impl<B, H> HtmlRewriteBody<B, H> {
    /// Wraps `inner` without rewriting — frames pass through unchanged (their
    /// data type normalized to [`Bytes`]).
    ///
    /// Lets a layer keep one body type for responses it must not rewrite
    /// (e.g. a non-HTML content type).
    pub fn passthrough(inner: B) -> Self {
        Self {
            inner,
            rewriter: None,
            done: false,
        }
    }
}

impl<B, H> StreamingBody for HtmlRewriteBody<B, H>
where
    B: StreamingBody<Error: Into<BoxError>>,
    H: ElementContentHandler,
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

        let Some(rewriter) = this.rewriter.as_mut() else {
            // Passthrough: forward frames, normalizing the data type to `Bytes`.
            return match ready!(this.inner.as_mut().poll_frame(cx)) {
                Some(Ok(frame)) => Poll::Ready(Some(Ok(normalize_frame(frame)))),
                Some(Err(err)) => Poll::Ready(Some(Err(err.into()))),
                None => {
                    *this.done = true;
                    Poll::Ready(None)
                }
            };
        };

        loop {
            match ready!(this.inner.as_mut().poll_frame(cx)) {
                Some(Ok(frame)) => match frame.into_data() {
                    Ok(mut data) => {
                        let chunk = data.copy_to_bytes(data.remaining());
                        if let Err(err) = rewriter.write(&chunk) {
                            return Poll::Ready(Some(Err(err)));
                        }
                        let out = rewriter.take_output();
                        if !out.is_empty() {
                            return Poll::Ready(Some(Ok(Frame::data(Bytes::from(out)))));
                        }
                        // The rewriter buffered an incomplete construct (e.g. a
                        // partial tag); keep polling for more input.
                    }
                    // A non-data frame (trailers) — forward it verbatim.
                    Err(frame) => {
                        if let Ok(trailers) = frame.into_trailers() {
                            return Poll::Ready(Some(Ok(Frame::trailers(trailers))));
                        }
                    }
                },
                Some(Err(err)) => return Poll::Ready(Some(Err(err.into()))),
                None => {
                    *this.done = true;
                    if let Err(err) = rewriter.end() {
                        return Poll::Ready(Some(Err(err)));
                    }
                    let out = rewriter.take_output();
                    return if out.is_empty() {
                        Poll::Ready(None)
                    } else {
                        Poll::Ready(Some(Ok(Frame::data(Bytes::from(out)))))
                    };
                }
            }
        }
    }

    fn size_hint(&self) -> SizeHint {
        if self.rewriter.is_some() {
            // Rewriting changes the body length unpredictably.
            SizeHint::default()
        } else {
            self.inner.size_hint()
        }
    }
}

/// Normalizes a frame's data type to [`Bytes`], preserving trailers.
fn normalize_frame<D: Buf>(frame: Frame<D>) -> Frame<Bytes> {
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
