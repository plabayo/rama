//! Streaming body type for FastCGI requests and responses.

use rama_core::bytes::Bytes;
use std::fmt;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, ReadBuf};
use tokio::sync::mpsc;

/// A streaming body for FastCGI requests and responses.
///
/// `FastCgiBody` wraps any [`AsyncRead`] source — in-memory bytes or a live
/// channel-backed stream from the FastCGI framing layer — using the same type.
///
/// # Constructors
///
/// - [`FastCgiBody::empty()`] — an immediately-empty body (no data).
/// - [`FastCgiBody::from_bytes()`] — wraps already-collected bytes.
/// - [`FastCgiBody::from_reader()`] — wraps any `AsyncRead + Send + Unpin`.
///
/// # Conversion
///
/// [`Bytes`], `Vec<u8>`, `String`, and `&'static [u8]` all implement
/// `Into<FastCgiBody>`, so they can be passed directly to
/// [`FastCgiResponse::new()`][crate::server::FastCgiResponse::new].
///
/// # Reading
///
/// `FastCgiBody` implements [`AsyncRead`] so it works with any async I/O
/// consumer. To collect the entire body into memory call [`FastCgiBody::collect()`].
pub struct FastCgiBody(Box<dyn AsyncRead + Send + Unpin + 'static>);

impl FastCgiBody {
    /// Create an empty body (immediate EOF on the first read).
    pub fn empty() -> Self {
        Self(Box::new(std::io::Cursor::new(Bytes::new())))
    }

    /// Wrap pre-collected bytes as a body.
    pub fn from_bytes(b: Bytes) -> Self {
        Self(Box::new(std::io::Cursor::new(b)))
    }

    /// Wrap any [`AsyncRead`] as a body.
    pub fn from_reader(r: impl AsyncRead + Send + Unpin + 'static) -> Self {
        Self(Box::new(r))
    }

    /// Wrap an mpsc channel receiver as a streaming body.
    ///
    /// Used internally by the server to bridge the IO reading task and the
    /// `FastCgiRequest` presented to the inner service.
    pub(crate) fn from_channel(rx: mpsc::Receiver<Result<Bytes, io::Error>>) -> Self {
        Self(Box::new(ChannelBody {
            rx,
            current: None,
        }))
    }

    /// Collect the entire body into a [`Bytes`] buffer.
    ///
    /// For bodies backed by a live stream this drives the stream to EOF.
    pub async fn collect(mut self) -> Result<Bytes, io::Error> {
        use tokio::io::AsyncReadExt;
        let mut buf = Vec::new();
        self.0.read_to_end(&mut buf).await?;
        Ok(Bytes::from(buf))
    }
}

impl fmt::Debug for FastCgiBody {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FastCgiBody").finish_non_exhaustive()
    }
}

impl AsyncRead for FastCgiBody {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.0).poll_read(cx, buf)
    }
}

impl From<Bytes> for FastCgiBody {
    fn from(b: Bytes) -> Self {
        Self::from_bytes(b)
    }
}

impl From<Vec<u8>> for FastCgiBody {
    fn from(v: Vec<u8>) -> Self {
        Self::from_bytes(Bytes::from(v))
    }
}

impl From<&'static [u8]> for FastCgiBody {
    fn from(s: &'static [u8]) -> Self {
        Self::from_bytes(Bytes::from_static(s))
    }
}

impl From<String> for FastCgiBody {
    fn from(s: String) -> Self {
        Self::from_bytes(Bytes::from(s))
    }
}

// ---------------------------------------------------------------------------
// Internal channel-backed body
// ---------------------------------------------------------------------------

struct ChannelBody {
    rx: mpsc::Receiver<Result<Bytes, io::Error>>,
    current: Option<Bytes>,
}

impl AsyncRead for ChannelBody {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        loop {
            // Drain from the current buffered chunk first.
            if let Some(mut chunk) = this.current.take() {
                if !chunk.is_empty() {
                    // split_to(n) consumes first n bytes from `chunk`, returns them.
                    let to_copy = chunk.len().min(buf.remaining());
                    let prefix = chunk.split_to(to_copy);
                    buf.put_slice(&prefix);
                    if !chunk.is_empty() {
                        this.current = Some(chunk);
                    }
                    return Poll::Ready(Ok(()));
                }
                // Empty chunk: discard and try next.
            }

            // Wait for the next chunk from the background reader task.
            match this.rx.poll_recv(cx) {
                Poll::Ready(Some(Ok(bytes))) => {
                    if bytes.is_empty() {
                        // Explicit EOF marker sent by the reading task.
                        return Poll::Ready(Ok(()));
                    }
                    this.current = Some(bytes);
                    // Loop back to drain.
                }
                Poll::Ready(Some(Err(e))) => return Poll::Ready(Err(e)),
                // Channel closed without an explicit EOF: treat as EOF.
                Poll::Ready(None) => return Poll::Ready(Ok(())),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}
