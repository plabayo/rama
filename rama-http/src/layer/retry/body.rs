use super::{
    SourceBody,
    storage::ReplaySource,
    tee::{Forward, PendingReplay},
};
use crate::{
    Body, HeaderMap, StreamingBody,
    body::{Frame, SizeHint},
};
use rama_core::{
    bytes::Bytes,
    error::{BoxError, BoxErrorExt as _},
};
use std::{
    future::poll_fn,
    pin::Pin,
    task::{Context, Poll},
};

/// A replayable request body, or an original stream sent without retries.
///
/// Use [`Self::try_clone`] when preparing another attempt. Streaming bodies
/// cannot be cloned; replayable bodies retain both data and trailers.
#[derive(Debug)]
pub struct RetryBody {
    inner: Kind,
}

#[derive(Debug)]
enum Kind {
    Memory(MemoryCursor),
    Forward(Forward),
    Pending(PendingReplay),
    Unavailable,
    Stored(Box<dyn ReplaySource>),
    Streaming {
        body: Option<parking_lot::Mutex<SourceBody>>,
        hint: SizeHint,
    },
}

impl RetryBody {
    pub(crate) fn new(bytes: Bytes) -> Self {
        Self {
            inner: Kind::Memory(MemoryCursor::new(bytes, None)),
        }
    }

    pub(crate) fn empty() -> Self {
        Self::new(Bytes::new())
    }

    pub(super) fn forwarding(body: Forward) -> Self {
        Self {
            inner: Kind::Forward(body),
        }
    }

    pub(super) fn pending(pending: PendingReplay) -> Self {
        Self {
            inner: Kind::Pending(pending),
        }
    }

    pub(super) async fn resolve_pending(&mut self) -> Result<bool, BoxError> {
        poll_fn(|cx| self.poll_resolve(cx)).await
    }

    fn poll_resolve(&mut self, cx: &mut Context<'_>) -> Poll<Result<bool, BoxError>> {
        let pending = match &mut self.inner {
            Kind::Pending(pending) => pending,
            Kind::Unavailable => return Poll::Ready(Ok(false)),
            _ => return Poll::Ready(Ok(true)),
        };
        let resolution = std::task::ready!(pending.poll(cx));
        // A policy may inspect the body and still request another attempt.
        // A failed capture stays unavailable even after the error is observed.
        self.inner = Kind::Unavailable;
        let Some(source) = resolution.map_err(|error| Box::new(error) as BoxError)? else {
            return Poll::Ready(Ok(false));
        };
        self.inner = match (&*source as &dyn std::any::Any).downcast_ref::<MemoryCursor>() {
            Some(memory) => Kind::Memory(memory.clone()),
            None => Kind::Stored(source.clone_cursor()),
        };
        Poll::Ready(Ok(true))
    }

    pub(super) fn streaming(body: Option<SourceBody>, hint: SizeHint) -> Self {
        Self {
            inner: Kind::Streaming {
                body: body.map(parking_lot::Mutex::new),
                hint,
            },
        }
    }

    /// Whether this body is a candidate for replay. A candidate handed to policy
    /// can still become unavailable if capturing its remaining frames fails.
    /// The live reader driving the first streamed attempt is always one-shot.
    #[must_use]
    pub fn is_replayable(&self) -> bool {
        matches!(
            self.inner,
            Kind::Memory(_) | Kind::Stored(_) | Kind::Pending(_)
        )
    }

    /// Clone the remaining data and trailers, or return `None` for a stream.
    #[must_use]
    pub fn try_clone(&self) -> Option<Self> {
        match &self.inner {
            Kind::Memory(cursor) => Some(Self {
                inner: Kind::Memory(cursor.clone()),
            }),
            Kind::Stored(cursor) => Some(Self {
                inner: Kind::Stored(cursor.clone_cursor()),
            }),
            Kind::Pending(pending) => Some(Self::pending(pending.clone())),
            Kind::Unavailable | Kind::Forward(_) | Kind::Streaming { .. } => None,
        }
    }

    /// Extract buffered data when there are no trailers.
    ///
    /// Returns the unchanged body on failure, so streams and trailers are
    /// never silently discarded. `Ok(None)` means the body is exhausted.
    pub fn into_bytes(self) -> Result<Option<Bytes>, Self> {
        match self.inner {
            Kind::Memory(MemoryCursor {
                bytes,
                trailers: None,
            }) => Ok(bytes),
            _ => Err(self),
        }
    }
}

impl Default for RetryBody {
    fn default() -> Self {
        Self::empty()
    }
}

/// A single shared payload and its optional trailing headers.
#[derive(Debug, Clone)]
pub(super) struct MemoryCursor {
    bytes: Option<Bytes>,
    trailers: Option<Box<HeaderMap>>,
}

impl MemoryCursor {
    pub(super) fn new(bytes: Bytes, trailers: Option<HeaderMap>) -> Self {
        Self {
            bytes: (!bytes.is_empty()).then_some(bytes),
            trailers: trailers.map(Box::new),
        }
    }
}

impl StreamingBody for MemoryCursor {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        Poll::Ready(
            self.bytes
                .take()
                .map(Frame::data)
                .or_else(|| {
                    self.trailers
                        .take()
                        .map(|trailers| Frame::trailers(*trailers))
                })
                .map(Ok),
        )
    }

    fn is_end_stream(&self) -> bool {
        self.bytes.is_none() && self.trailers.is_none()
    }

    fn size_hint(&self) -> SizeHint {
        SizeHint::with_exact(self.bytes.as_ref().map_or(0, |bytes| bytes.len() as u64))
    }
}

impl ReplaySource for MemoryCursor {
    fn clone_cursor(&self) -> Box<dyn ReplaySource> {
        Box::new(self.clone())
    }
}
impl StreamingBody for RetryBody {
    type Data = Bytes;
    type Error = rama_core::error::BoxError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
        match &mut self.inner {
            Kind::Unavailable => Poll::Ready(None),
            Kind::Pending(_) => {
                if std::task::ready!(self.poll_resolve(cx))? {
                    self.poll_frame(cx)
                } else {
                    Poll::Ready(Some(Err(BoxError::from_static_str(
                        "request body unavailable for replay",
                    ))))
                }
            }
            Kind::Forward(body) => Pin::new(body).poll_frame(cx),
            Kind::Stored(reader) => Pin::new(reader).poll_frame(cx),
            Kind::Streaming { body, hint } => {
                let Some(source) = body.as_mut() else {
                    return Poll::Ready(None);
                };
                let frame = Pin::new(source.get_mut()).poll_frame(cx);
                match &frame {
                    Poll::Ready(Some(Ok(frame))) => {
                        if let Some(data) = frame.data_ref() {
                            hint.consume(data.len() as u64);
                        }
                    }
                    Poll::Ready(None) => {
                        hint.set_exact(0);
                        *body = None;
                    }
                    _ => (),
                }
                frame
            }
            Kind::Memory(cursor) => Pin::new(cursor).poll_frame(cx),
        }
    }

    fn is_end_stream(&self) -> bool {
        match &self.inner {
            Kind::Memory(cursor) => cursor.is_end_stream(),
            Kind::Forward(body) => body.is_end_stream(),
            Kind::Pending(_) => false,
            Kind::Unavailable => true,
            Kind::Stored(reader) => reader.is_end_stream(),
            Kind::Streaming { body, .. } => body
                .as_ref()
                .is_none_or(|source| source.lock().is_end_stream()),
        }
    }

    fn size_hint(&self) -> SizeHint {
        match &self.inner {
            Kind::Memory(cursor) => cursor.size_hint(),
            Kind::Forward(body) => body.size_hint(),
            Kind::Pending(pending) => pending.hint,
            Kind::Unavailable => SizeHint::with_exact(0),
            Kind::Stored(reader) => reader.size_hint(),
            Kind::Streaming { hint, .. } => *hint,
        }
    }
}

impl From<RetryBody> for Body {
    fn from(body: RetryBody) -> Self {
        match body.inner {
            Kind::Memory(MemoryCursor {
                bytes,
                trailers: None,
            }) => bytes.map_or_else(Self::empty, Into::into),
            _ => Self::new(body),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{BodyExtractExt, body::util::BodyExt as _};

    #[test]
    fn bytes_and_stream_metadata_match_body_state() {
        let body = RetryBody::new(Bytes::from_static(b"hello"));
        assert!(!body.is_end_stream());
        assert_eq!(body.size_hint().exact(), Some(5));
        assert_eq!(
            body.into_bytes().unwrap(),
            Some(Bytes::from_static(b"hello"))
        );

        let empty = RetryBody::empty();
        assert!(empty.is_end_stream());
        assert_eq!(empty.size_hint().exact(), Some(0));
        assert_eq!(empty.into_bytes().unwrap(), None);
    }

    #[tokio::test]
    async fn cloning_a_partly_read_store_keeps_its_byte_offset_and_trailers() {
        let mut trailers = HeaderMap::new();
        trailers.insert("x-end", "yes".parse().unwrap());
        let mut first = RetryBody {
            inner: Kind::Stored(Box::new(MemoryCursor::new(
                Bytes::from_static(b"hello"),
                Some(trailers),
            ))),
        };
        assert_eq!(
            first.frame().await.unwrap().unwrap().into_data().unwrap(),
            "hello"
        );
        let second = first.try_clone().unwrap();
        assert_eq!(second.size_hint().exact(), Some(0));
        for body in [first, second] {
            let mut collected = body.collect().await.unwrap();
            assert_eq!(collected.take_trailers().unwrap()["x-end"], "yes");
            assert!(collected.to_bytes().is_empty());
        }
    }

    #[tokio::test]
    async fn consume_retry_body() {
        let body = RetryBody::new(Bytes::from("hello"));
        let s = body.try_into_string().await.unwrap();
        assert_eq!(s, "hello");
    }
}
