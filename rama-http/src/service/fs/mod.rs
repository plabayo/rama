//! File system related services.

use crate::{
    StreamingBody,
    body::{Frame, SizeHint},
};
use pin_project_lite::pin_project;
use rama_core::bytes::Bytes;
use rama_core::futures::Stream;
use rama_core::stream::io::ReaderStream;
use std::{
    fmt, io,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncReadExt, Take};

mod serve_dir;
mod serve_file;

#[doc(inline)]
pub use self::{
    serve_dir::{
        DefaultServeDirFallback, DirectoryServeMode, ServeDir, ServeDirHiddenKinds,
        ServeDirSymlinkPolicy,
    },
    serve_file::ServeFile,
};

pin_project! {
    // NOTE: This could potentially be upstreamed to `http-body`.
    /// Adapter that turns an [`impl AsyncRead`][tokio::io::AsyncRead] to an [`impl Body`][http_body::Body].
    pub struct AsyncReadBody<T> {
        #[pin]
        reader: ReaderStream<T>,
        remaining: u64,
    }
}

impl<T> fmt::Debug for AsyncReadBody<T>
where
    T: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AsyncReadBody")
            .field("reader", &self.reader)
            .field("remaining", &self.remaining)
            .finish()
    }
}

impl<T> AsyncReadBody<T>
where
    T: AsyncRead,
{
    /// Create a new [`AsyncReadBody`] serving at most `len` bytes of the given reader,
    /// with a specific read buffer capacity
    fn with_capacity_limited(read: T, capacity: usize, len: u64) -> AsyncReadBody<Take<T>> {
        AsyncReadBody {
            reader: ReaderStream::with_capacity(read.take(len), capacity),
            remaining: len,
        }
    }
}

impl<T> StreamingBody for AsyncReadBody<T>
where
    T: AsyncRead,
{
    type Data = Bytes;
    type Error = io::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.project();
        match std::task::ready!(this.reader.poll_next(cx)) {
            Some(Ok(chunk)) => {
                *this.remaining = this.remaining.saturating_sub(chunk.len() as u64);
                Poll::Ready(Some(Ok(Frame::data(chunk))))
            }
            Some(Err(err)) => Poll::Ready(Some(Err(err))),
            None => Poll::Ready(None),
        }
    }

    #[inline]
    fn is_end_stream(&self) -> bool {
        self.remaining == 0
    }

    #[inline]
    fn size_hint(&self) -> SizeHint {
        SizeHint::with_exact(self.remaining)
    }
}

#[cfg(test)]
mod tests {
    use super::AsyncReadBody;
    use crate::{StreamingBody, body::util::BodyExt};

    #[tokio::test]
    async fn body_size_and_end_follow_the_bytes_left_to_read() {
        let data = [7u8; 10];
        // the reader holds more than is served
        let mut body = Box::pin(AsyncReadBody::with_capacity_limited(&data[..], 4, 6));
        let mut left = 6;
        loop {
            assert_eq!(body.size_hint().exact(), Some(left));
            assert_eq!(body.is_end_stream(), left == 0);
            let Some(frame) = body.frame().await else {
                break;
            };
            left -= frame.unwrap().into_data().unwrap().len() as u64;
        }
        assert_eq!(left, 0);
    }
}
