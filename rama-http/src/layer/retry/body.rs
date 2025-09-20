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

    #[tokio::test]
    async fn consume_retry_body() {
        let body = RetryBody::new(Bytes::from("hello"));
        let s = body.try_into_string().await.unwrap();
        assert_eq!(s, "hello");
    }
}
