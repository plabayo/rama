use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};

use crate::{
    context::Extensions,
    extensions::{ExtensionsMut, ExtensionsRef},
};
use pin_project_lite::pin_project;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

pin_project! {
    #[derive(Debug)]
    pub struct GenericRequest<T> {
        #[pin]
        pub request: T,
        pub extensions: Extensions,
    }
}

impl<T> GenericRequest<T> {
    pub fn new(request: T) -> Self {
        Self {
            request,
            extensions: Extensions::new(),
        }
    }
}

impl<T> ExtensionsRef for GenericRequest<T> {
    fn extensions(&self) -> &Extensions {
        &self.extensions
    }
}

impl<T> ExtensionsMut for GenericRequest<T> {
    fn extensions_mut(&mut self) -> &mut Extensions {
        &mut self.extensions
    }
}

impl<T: AsyncRead> AsyncRead for GenericRequest<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.project().request.poll_read(cx, buf)
    }
}

impl<T: AsyncWrite> AsyncWrite for GenericRequest<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.project().request.poll_write(cx, buf)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        self.project().request.poll_write_vectored(cx, bufs)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.project().request.poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.project().request.poll_shutdown(cx)
    }

    fn is_write_vectored(&self) -> bool {
        self.request.is_write_vectored()
    }
}
