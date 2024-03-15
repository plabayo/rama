use hyper::upgrade::Upgraded as hyperUpgraded;
use hyper_util::rt::TokioIo;
use pin_project_lite::pin_project;
use std::{
    fmt, io,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

pin_project! {
    /// An opaque object to represent an upgraded connection,
    /// that is to be operated on as an abstract bytes stream.
    pub struct Upgraded {
        #[pin]
        // TODO: once we embed Hyper we can heavily simplify this by directly connecting to Tokio I/O
        hu: TokioIo<hyperUpgraded>,
    }
}

impl Upgraded {
    pub(crate) fn new(upgraded: hyperUpgraded) -> Self {
        Self {
            hu: TokioIo::new(upgraded),
        }
    }
}

impl fmt::Debug for Upgraded {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Upgraded")
    }
}

impl AsyncRead for Upgraded {
    #[inline]
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<Result<(), io::Error>> {
        self.project().hu.poll_read(cx, buf)
    }
}

impl AsyncWrite for Upgraded {
    #[inline]
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        self.project().hu.poll_write(cx, buf)
    }

    #[inline]
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), io::Error>> {
        self.project().hu.poll_flush(cx)
    }

    #[inline]
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), io::Error>> {
        self.project().hu.poll_shutdown(cx)
    }

    #[inline]
    fn is_write_vectored(&self) -> bool {
        self.hu.is_write_vectored()
    }

    #[inline]
    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<Result<usize, io::Error>> {
        self.project().hu.poll_write_vectored(cx, bufs)
    }
}
