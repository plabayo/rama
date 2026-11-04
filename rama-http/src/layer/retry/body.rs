use crate::{
    Body, HeaderMap, StreamingBody,
    body::{Frame, SizeHint, util::Collected},
};
use rama_core::bytes::Bytes;
use std::{
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
    Replayable {
        bytes: Option<Bytes>,
        trailers: Option<Box<HeaderMap>>,
    },
    Streaming {
        body: Body,
        hint: SizeHint,
    },
}

impl RetryBody {
    pub(crate) fn new(bytes: Bytes) -> Self {
        Self {
            inner: Kind::Replayable {
                bytes: (!bytes.is_empty()).then_some(bytes),
                trailers: None,
            },
        }
    }

    pub(crate) fn empty() -> Self {
        Self::new(Bytes::new())
    }

    pub(crate) fn collected(mut body: Collected<Bytes>) -> Self {
        let trailers = body.take_trailers().map(Box::new);
        let bytes = body.to_bytes();
        Self {
            inner: Kind::Replayable {
                bytes: (!bytes.is_empty()).then_some(bytes),
                trailers,
            },
        }
    }

    pub(crate) fn streaming(body: Body, hint: SizeHint) -> Self {
        Self {
            inner: Kind::Streaming { body, hint },
        }
    }

    /// Whether this body's remaining frames can be replayed.
    #[must_use]
    pub fn is_replayable(&self) -> bool {
        matches!(self.inner, Kind::Replayable { .. })
    }

    /// Clone the remaining data and trailers, or return `None` for a stream.
    #[must_use]
    pub fn try_clone(&self) -> Option<Self> {
        match &self.inner {
            Kind::Replayable { bytes, trailers } => Some(Self {
                inner: Kind::Replayable {
                    bytes: bytes.clone(),
                    trailers: trailers.clone(),
                },
            }),
            Kind::Streaming { .. } => None,
        }
    }

    /// Extract buffered data when there are no trailers.
    ///
    /// Returns the unchanged body on failure, so streams and trailers are
    /// never silently discarded. `Ok(None)` means the body is exhausted.
    pub fn into_bytes(self) -> Result<Option<Bytes>, Self> {
        match self.inner {
            Kind::Replayable {
                bytes,
                trailers: None,
            } => Ok(bytes),
            _ => Err(self),
        }
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
            Kind::Streaming { body, hint } => {
                let frame = Pin::new(body).poll_frame(cx);
                match &frame {
                    Poll::Ready(Some(Ok(frame))) => {
                        if let Some(data) = frame.data_ref() {
                            let len = data.len() as u64;
                            let lower = hint.lower().saturating_sub(len);
                            let upper = hint.upper().map(|upper| upper.saturating_sub(len));
                            hint.set_lower(lower);
                            if let Some(upper) = upper {
                                hint.set_upper(upper);
                            }
                        }
                    }
                    Poll::Ready(None) => hint.set_exact(0),
                    _ => (),
                }
                frame
            }
            Kind::Replayable { bytes, trailers } => Poll::Ready(
                bytes
                    .take()
                    .map(Frame::data)
                    .or_else(|| trailers.take().map(|trailers| Frame::trailers(*trailers)))
                    .map(Ok),
            ),
        }
    }

    fn is_end_stream(&self) -> bool {
        match &self.inner {
            Kind::Replayable { bytes, trailers } => bytes.is_none() && trailers.is_none(),
            Kind::Streaming { body, .. } => body.is_end_stream(),
        }
    }

    fn size_hint(&self) -> SizeHint {
        match &self.inner {
            Kind::Replayable { bytes, .. } => {
                SizeHint::with_exact(bytes.as_ref().map_or(0, |bytes| bytes.len() as u64))
            }
            Kind::Streaming { hint, .. } => *hint,
        }
    }
}

impl From<RetryBody> for Body {
    fn from(body: RetryBody) -> Self {
        match body.inner {
            Kind::Replayable {
                bytes,
                trailers: None,
            } => bytes.map_or_else(Self::empty, Into::into),
            Kind::Replayable { .. } | Kind::Streaming { .. } => Self::new(body),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::BodyExtractExt;

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
    async fn consume_retry_body() {
        let body = RetryBody::new(Bytes::from("hello"));
        let s = body.try_into_string().await.unwrap();
        assert_eq!(s, "hello");
    }
}
