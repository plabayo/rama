use crate::{
    Body, StreamingBody,
    body::{Frame, SizeHint},
};
use rama_core::bytes::Bytes;

#[derive(Debug, Clone)]
/// A body that can be clone and used for requests that have to be rertried.
pub struct RetryBody {
    bytes: Option<Bytes>,
}

impl RetryBody {
    pub(crate) fn new(bytes: Bytes) -> Self {
        Self { bytes: Some(bytes) }
    }

    #[cfg(test)]
    pub(crate) fn empty() -> Self {
        Self { bytes: None }
    }

    /// Turn this body into bytes.
    pub fn into_bytes(self) -> Option<Bytes> {
        self.bytes
    }
}

impl StreamingBody for RetryBody {
    type Data = Bytes;
    type Error = rama_core::error::BoxError;

    fn poll_frame(
        mut self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        std::task::Poll::Ready(self.bytes.take().map(|bytes| Ok(Frame::data(bytes))))
    }

    fn is_end_stream(&self) -> bool {
        self.bytes.is_none()
    }

    fn size_hint(&self) -> SizeHint {
        SizeHint::with_exact(
            self.bytes
                .as_ref()
                .map(|b| b.len() as u64)
                .unwrap_or_default(),
        )
    }
}

impl From<RetryBody> for Body {
    fn from(body: RetryBody) -> Self {
        match body.bytes {
            Some(bytes) => bytes.into(),
            None => Self::empty(),
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
        assert_eq!(body.into_bytes(), Some(Bytes::from_static(b"hello")));

        let empty = RetryBody::empty();
        assert!(empty.is_end_stream());
        assert_eq!(empty.size_hint().exact(), Some(0));
        assert_eq!(empty.into_bytes(), None);
    }

    #[tokio::test]
    async fn consume_retry_body() {
        let body = RetryBody::new(Bytes::from("hello"));
        let s = body.try_into_string().await.unwrap();
        assert_eq!(s, "hello");
    }
}
