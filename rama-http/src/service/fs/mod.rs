//! File system related services.

use futures_lite::Stream;
use pin_project_lite::pin_project;
use rama_core::bytes::Bytes;
use rama_http_types::dep::http_body::{Body, Frame};
use std::{
    fmt, io,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncReadExt, Take};
use tokio_util::io::ReaderStream;

mod serve_dir;
mod serve_file;

#[doc(inline)]
pub use self::{
    serve_dir::{DefaultServeDirFallback, DirectoryServeMode, ServeDir},
    serve_file::ServeFile,
};

pin_project! {
    // NOTE: This could potentially be upstreamed to `http-body`.
    /// Adapter that turns an [`impl AsyncRead`][tokio::io::AsyncRead] to an [`impl Body`][http_body::Body].
    pub struct AsyncReadBody<T> {
        #[pin]
        reader: ReaderStream<T>,
    }
}

impl<T> fmt::Debug for AsyncReadBody<T>
where
    T: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AsyncReadBody")
            .field("reader", &self.reader)
            .finish()
    }
}

impl<T> AsyncReadBody<T>
where
    T: AsyncRead,
{
    /// Create a new [`AsyncReadBody`] wrapping the given reader,
    /// with a specific read buffer capacity
    fn with_capacity(read: T, capacity: usize) -> Self {
        Self {
            reader: ReaderStream::with_capacity(read, capacity),
        }
    }

    fn with_capacity_limited(
        read: T,
        capacity: usize,
        max_read_bytes: u64,
    ) -> AsyncReadBody<Take<T>> {
        AsyncReadBody {
            reader: ReaderStream::with_capacity(read.take(max_read_bytes), capacity),
        }
    }
}

impl<T> Body for AsyncReadBody<T>
where
    T: AsyncRead,
{
    type Data = Bytes;
    type Error = io::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        match std::task::ready!(self.project().reader.poll_next(cx)) {
            Some(Ok(chunk)) => Poll::Ready(Some(Ok(Frame::data(chunk)))),
            Some(Err(err)) => Poll::Ready(Some(Err(err))),
            None => Poll::Ready(None),
        }
    }
}
